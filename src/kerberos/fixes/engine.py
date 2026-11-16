"""Applying the plan (tech.md §6 S8, §10.1, §11).

One change at a time, nodes one after another. The journal is written
before every state change, so an interrupted process leaves an honest record.
A change that needs confirmation (SSH access) is confirmed over a new
connection within 60 s, else rolled back (the agent's own timer rolls it back
anyway). After applying, the finding is checked again; if it still fails,
the change is rolled back. Interruption stops before the next change.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Optional

from kerberos.checks import spec
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.model import Change
from kerberos.fixes.plan import PlanItem
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, Target, TransportError

CONFIRM_WINDOW = 60
LOCAL_ADDRESS = "127.0.0.1"  # the 3x-ui server reaching itself (§7.6)
CONFIRM_RETRY = 5
ROLLBACKABLE = ("applied", "confirmed", "pending_confirm")


class Engine:
    def __init__(
        self,
        app: Any,
        session: Any,
        items: list[PlanItem],
        on_event: Optional[Callable[[str, PlanItem, str, str], None]] = None,
    ) -> None:
        self.app = app
        self.env = app.env
        self.session = session
        self.run = session.data["run"]
        self.store = RunStore(self.env.state, self.env.clock)
        self.queue = [i for i in items if i.selected and i.blocked is None]
        self.index = 0
        self.cancelled = False
        self.failed = 0
        self.on_event = on_event or (lambda *args: None)
        self.ask_diff: Callable[[str], bool] = lambda _diff: True
        # 3x-ui (§7.6): a new SSH port of this very server is tried from outside by
        # the person: KERBEROS on the same server cannot see the hoster's firewall.
        self.ask_outside: Callable[[int, str], bool] = lambda _port, _command: False
        self._panel_fixes = None

    @property
    def panel_fixes(self) -> Any:
        if self._panel_fixes is None:
            from kerberos.fixes.panel_fixes import PanelFixes

            self._panel_fixes = PanelFixes(self)
        return self._panel_fixes

    # -- driving -------------------------------------------------------------
    @property
    def done(self) -> bool:
        return self.cancelled or self.index >= len(self.queue)

    @property
    def current(self) -> Optional[PlanItem]:
        return None if self.done else self.queue[self.index]

    def step(self) -> None:
        """Apply the next change completely: it is never left half done."""
        if self.done:
            return
        item = self.queue[self.index]
        self.index += 1
        self.apply(item)

    def cancel(self) -> None:
        self.cancelled = True

    # -- helpers -------------------------------------------------------------
    def save(self) -> None:
        self.store.save(self.run)

    def target(self, node_uuid: str) -> Target:
        node = self.session.snapshot.node(node_uuid)
        record = self.env.state.node(node_uuid)
        if record is not None:
            return record.target(node.address)
        return Target(node.uuid, node.name, node.address, 22)

    def event(self, step: str, item: PlanItem, state: str, note: str = "") -> None:
        self.on_event(step, item, state, note)

    def admin_public_key(self) -> str:
        """The administrator key on the panel server, created on first use (§8.5)."""
        state = self.env.state
        public = state.public_key(admin=True)
        if public:
            return public
        host = self.env.host
        result = host.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                           f"admin@{host.hostname()}", "-f", str(state.admin_key)])  # fmt: skip
        public = state.public_key(admin=True)
        if not result.ok or not public:
            raise NodeAgentError("command_failed", "ssh-keygen")
        return public

    def finish(self, change: Change, state: str, error: Optional[str] = None) -> None:
        change["state"] = state  # type: ignore[typeddict-item]
        change["error"] = error
        change["finishedAt"] = iso(self.env.clock)
        self.save()

    # -- one change ------------------------------------------------------------
    def apply(self, item: PlanItem) -> None:
        from kerberos.fixes.panel_fixes import PANEL_ITEMS

        if item.fix_id in PANEL_ITEMS:
            try:
                self.panel_fixes.run(item)
            except Exception:  # noqa: BLE001 - a failed panel step is counted, not fatal
                self.failed += 1
            return
        if item.fix_id == "self_steal":
            from kerberos.fixes.self_steal import SelfSteal

            self.event("backup", item, "running")
            self.event("backup", item, "ok")
            SelfSteal(self, item).run()
            return
        target = self.target(item.node_uuid or "")
        change: Change = {
            "changeId": str(uuid.uuid4()),
            "fixId": item.fix_id,
            "target": item.target,
            "state": "planned",
            "params": {k: v for k, v in item.params.items() if k != "create"},
            "before": None,
            "details": {},
            "error": None,
            "startedAt": iso(self.env.clock),
            "finishedAt": None,
        }
        self.run["changes"].append(change)
        self.save()
        self.event("backup", item, "running")
        change["state"] = "applying"
        self.save()
        params = dict(change["params"])
        try:
            if item.fix_id == "access.admin_keys" and item.params.get("create"):
                params["keys"] = [self.admin_public_key()]
                change["params"] = {"keys": params["keys"]}
            answer = self.env.transport.agent(
                target, f"apply {item.fix_id} {change['changeId']}", params
            )
        except NodeAgentError as exc:
            self.failed += 1
            self.event("apply", item, "failed", exc.code)
            self.finish(change, "failed", exc.code)
            return
        except TransportError as exc:
            # The change may have happened before the connection broke: undo it.
            self.failed += 1
            self.rollback(target, change["changeId"])
            self.event("apply", item, "failed", exc.kind)
            self.finish(change, "failed", exc.kind)
            return
        self.event("backup", item, "ok")
        self.event("apply", item, "ok")
        change["details"] = dict(answer.get("details") or {})
        state = "applied" if answer.get("state") == "noop" else answer.get("state")
        change["state"] = state
        self.save()
        if state == "pending_confirm":
            previous = None
            confirm_target = target
            if item.fix_id == "hostkeys.regenerate":
                previous = self.pin_new_host_key(target, change)
            if item.fix_id == "ssh.port":
                confirm_target = self.new_port_target(target, change)
            self.event("confirm", item, "running")
            if (item.fix_id == "ssh.port" and target.address == LOCAL_ADDRESS
                    and not self.outside_login(item, confirm_target.port)):  # fmt: skip
                confirmed = False
            else:
                confirmed = self.confirm(confirm_target, change["changeId"])
            if not confirmed:
                # The old port still listens until confirm: roll back through it.
                rolled = self.rollback(target, change["changeId"], fresh=True)
                if previous:
                    self.env.state.pin(target.address, target.port, "ssh-ed25519", previous)
                error = "port_closed" if item.fix_id == "ssh.port" else "confirm_failed"
                self.failed += 1
                self.event("confirm", item, "rolled_back" if rolled else "failed", error)
                self.finish(change, "rolled_back" if rolled else "failed", error)
                return
            change["state"] = "confirmed"
            self.save()
            if item.fix_id == "ssh.port":
                self.move_to_port(item.node_uuid or "", confirm_target.port)
                target = confirm_target
            self.event("confirm", item, "ok")
        else:
            self.event("confirm", item, "skipped")
        self.event("check", item, "running")
        if not self.recheck(item, target):
            rolled = self.rollback(target, change["changeId"])
            self.failed += 1
            self.event("check", item, "rolled_back" if rolled else "failed", "recheck")
            self.finish(change, "rolled_back" if rolled else "failed", "recheck_failed")
            return
        self.event("check", item, "ok")
        self.finish(change, change["state"])

    def outside_login(self, item: PlanItem, port: int) -> bool:
        node = self.session.snapshot.node(item.node_uuid or "")
        address = node.address if node else ""
        return bool(self.ask_outside(port, f"ssh -p {port} root@{address}"))

    def pin_new_host_key(self, target: Target, change: Change) -> Optional[str]:
        """§10.3: read the new key from the agent, check it with ssh-keyscan, pin it."""
        state = self.env.state
        previous = state.pinned(target.address, target.port)
        new = {k["fingerprint"] for k in change["details"].get("hostKeys", [])
               if k.get("type") == "ED25519"}  # fmt: skip
        scanned = self.env.transport.keyscan(target.address, target.port)
        if scanned is not None and scanned.fingerprint in new:
            state.pin(target.address, target.port, scanned.type, scanned.blob)
            change["details"]["previousKey"] = previous
            self.save()
        return previous

    def new_port_target(self, target: Target, change: Change) -> Target:
        """§10.3: the same host key answers on the new port; KERBEROS goes there."""
        port = int(change["details"].get("newPort") or change["params"]["port"])
        blob = self.env.state.pinned(target.address, target.port)
        if blob:
            self.env.state.pin(target.address, port, "ssh-ed25519", blob)
        return Target(target.uuid, target.name, target.address, port)

    def move_to_port(self, node_uuid: str, port: int) -> None:
        record = self.env.state.node(node_uuid)
        if record is not None:
            record.ssh_port = port
            self.env.state.save_node(record)

    def confirm(self, target: Target, change_id: str) -> bool:
        clock = self.env.clock
        deadline = clock.monotonic() + CONFIRM_WINDOW
        while True:
            try:
                self.env.transport.agent(target, f"confirm {change_id}", fresh=True)
                return True
            except NodeAgentError:
                return False
            except TransportError:
                if clock.monotonic() + CONFIRM_RETRY > deadline:
                    return False
                clock.sleep(CONFIRM_RETRY)

    def rollback(self, target: Target, change_id: str, fresh: bool = False) -> bool:
        try:
            self.env.transport.agent(target, f"rollback {change_id}", fresh=fresh)
            return True
        except (NodeAgentError, TransportError):
            return False

    def recheck(self, item: PlanItem, target: Target) -> bool:
        data = self.session.data["input"]
        node = data.node_data(item.node_uuid or "")
        try:
            node.facts = schema.facts(self.env.transport.agent(target, "facts"))
        except (NodeAgentError, TransportError, schema.BadAnswer):
            return False
        if item.fix_id == "access.admin_keys":
            return bool(node.facts["ssh"].get("adminKeys"))
        if item.fix_id == "cdn.edge_only" and not self.recheck_edges(data, node):
            return False
        for check_id in item.checks:
            for finding in spec(check_id).rule(data):
                if finding["target"] == item.target and not finding["ok"]:
                    return False
        if item.fix_id == "ssh.key_only" and node.ipv4 and self.env.prober is not None:
            methods = self.env.prober.auth_methods(node.ipv4, target.port)
            if methods is not None and set(methods) - {"publickey"}:
                return False
        if item.fix_id == "node_api.panel_only" and self.session.panel is not None:
            try:
                nodes = {n.uuid: n for n in self.session.panel.nodes()}
            except Exception:  # noqa: BLE001 - the panel check is advisory here
                return True
            current = nodes.get(item.node_uuid or "")
            if current is not None and not current.is_connected:
                return False
        return True

    def recheck_edges(self, data: Any, node: Any) -> bool:
        """§10.6: a direct request gets what a missing page gets; through the edge it works."""
        from kerberos.checks import is_ip
        from kerberos.checks.collect import first_v4
        from kerberos.checks.rules import cdn_xhttp_hosts, tls_listen_ports, xhttp_path

        prober = self.env.prober
        if prober is None or not node.ipv4:
            return False
        missing_path = "/" + uuid.uuid4().hex[:12]
        ports = tls_listen_ports(node.facts)
        if not ports:
            return False
        for inbound, host in cdn_xhttp_hosts(data, node):
            name = host.sni or host.address
            path = xhttp_path(inbound, host)
            for port in ports:
                missing = prober.http(node.ipv4, port, name, missing_path)
                for probe in (path, "/cdn-check"):
                    answer = prober.http(node.ipv4, port, name, probe)
                    data.pages[(node.ipv4, port, name, probe)] = answer
                    if (answer.status, answer.body) != (missing.status, missing.body):
                        return False
            addresses = [host.address] if is_ip(host.address) else prober.resolve(host.address)
            edge = first_v4(addresses)
            if edge is None:
                return False
            via = prober.http(edge, host.port or 443, name, path)
            if via.status is None or via.status == missing.status:
                return False  # the edge itself is cut off: the list of nets is not complete
        return True

"""Applying the plan (tech.md §6 S8, §10.1, §11).

One change at a time, nodes one after another. The journal is written
before every state change, so an interrupted process leaves an honest record.
A change that needs confirmation (SSH access) is confirmed over a new
connection within 60 s, else rolled back (the agent's own timer rolls it back
anyway). After applying, the finding is checked again; if it still fails,
the change is rolled back. Interruption stops before the next change.

A change whose automatic rollback fails too keeps the state it reached, with
error `rollback_failed`: it is still in place, `kerberos rollback` offers it,
and the run exits with 5 (§5.3).
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Optional

from kerberos.checks import spec
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.model import ROLLBACK_FAILED, Change
from kerberos.fixes.plan import PlanItem
from kerberos.flow import EXIT_INTERRUPTED, EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, Target, TransportError

CONFIRM_WINDOW = 60
LOCAL_ADDRESS = "127.0.0.1"  # the 3x-ui server reaching itself (§7.6)
CONFIRM_RETRY = 5
# §11.2: a change left "applying" was cut short (a killed process, an uncaught error)
# and may be partly in place, so `kerberos rollback` offers it as well.
ROLLBACKABLE = ("applying", "applied", "confirmed", "pending_confirm")
# §10.3 node_api.panel_only: the panel must keep its node for about 30 s after the rule.
NODE_API_POLLS = 6
NODE_API_PAUSE = 5


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
        self.failed = 0  # plan items that failed; what they changed went back
        self.rollback_failed = 0  # changes that failed and could not be rolled back
        self.on_event = on_event or (lambda *args: None)
        self.ask_diff: Callable[[str], bool] = lambda _diff: True
        # An automatic undo meets a panel object edited after KERBEROS wrote it: overwrite?
        # By default no: the change stays as it is and `kerberos rollback` asks later.
        self.ask_undo: Callable[[str], bool] = lambda _diff: False
        # 3x-ui (§7.6): a new SSH port of this very server is tried from outside by
        # the person: KERBEROS on the same server cannot see the hoster's firewall.
        self.ask_outside: Callable[[int, str], bool] = lambda _port, _command: False
        # The same, when a confirmed new port goes back after its recheck: the person
        # tries the old port from outside (§9.3).
        self.ask_old_port: Callable[[int, str], bool] = lambda _port, _command: False
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

    @property
    def exit_code(self) -> int:
        """§5.3: a rollback that failed needs a person first, then interruption, then 4."""
        if self.rollback_failed:
            return EXIT_ROLLBACK_FAILED
        if self.cancelled:
            return EXIT_INTERRUPTED
        if self.failed:
            return EXIT_PARTIAL
        return EXIT_OK

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

    def settle(self, change: Change, failure: str, rollback_error: Optional[str],
               done: str = "rolled_back") -> bool:  # fmt: skip
        """A failed change after its automatic rollback. False: that rollback failed too.

        Then the change keeps the state it reached: it is still in place.
        """
        if rollback_error is None:
            self.finish(change, done, failure)
            return True
        change["error"] = ROLLBACK_FAILED
        change["details"] = {**(change.get("details") or {}), "failure": failure,
                             "rollbackError": rollback_error}  # fmt: skip
        change["finishedAt"] = iso(self.env.clock)
        self.rollback_failed += 1
        self.save()
        return False

    # -- one change ------------------------------------------------------------
    def apply(self, item: PlanItem) -> None:
        from kerberos.fixes.panel_fixes import PANEL_ITEMS

        if item.fix_id in PANEL_ITEMS:
            try:
                self.panel_fixes.run(item)
            except Exception as exc:  # noqa: BLE001 - a panel change is never left half done
                self.panel_fixes.abandon(item, exc)
            return
        if item.fix_id == "self_steal":
            from kerberos.fixes.self_steal import SelfSteal
            from kerberos.fixes.xui_self_steal import SelfStealXui

            self.event("backup", item, "running")
            self.event("backup", item, "ok")
            kind = SelfStealXui if self.session.snapshot.kind == "3x-ui" else SelfSteal
            kind(self, item).run()
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
            # The change may have happened before the connection broke: undo it. An agent
            # without a record of it never started it.
            error = self.rollback(target, change["changeId"], missing_ok=True)
            if self.settle(change, exc.kind, error, done="failed"):
                self.failed += 1
            self.event("apply", item, "failed", exc.kind if error is None else ROLLBACK_FAILED)
            return
        self.event("backup", item, "ok")
        self.event("apply", item, "ok")
        change["details"] = dict(answer.get("details") or {})
        state = "applied" if answer.get("state") == "noop" else answer.get("state")
        change["state"] = state
        self.save()
        original, previous = target, None
        if state == "pending_confirm":
            confirm_target = target
            if item.fix_id == "hostkeys.regenerate":
                previous, served = self.pin_new_host_key(target, change)
                if not served:
                    # sshd does not show any of the new keys (HostKey elsewhere, §10.3):
                    # confirming on the old pin would report keys nobody sees.
                    self.give_up(item, change, target, "confirm", "hostkey_mismatch")
                    return
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
                error = self.rollback(target, change["changeId"], fresh=True)
                if previous:
                    self.env.state.pin(target.address, target.port, "ssh-ed25519", previous)
                reason = "port_closed" if item.fix_id == "ssh.port" else "confirm_failed"
                if self.settle(change, reason, error):
                    self.failed += 1
                self.event("confirm", item, "rolled_back" if error is None else "failed",
                           reason if error is None else ROLLBACK_FAILED)  # fmt: skip
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
            if item.fix_id == "ssh.port" and change["state"] == "confirmed":
                error, back = self.roll_back_port(item, target, change)
            else:
                error = self.rollback(target, change["changeId"])
                back = error is None
            if back:
                self.restore_access(item, change, original, previous)
            if self.settle(change, "recheck_failed", error):
                self.failed += 1
            self.event("check", item, "rolled_back" if error is None else "failed",
                       "recheck_failed" if error is None else ROLLBACK_FAILED)  # fmt: skip
            return
        self.event("check", item, "ok")
        self.finish(change, change["state"])

    def give_up(self, item: PlanItem, change: Change, target: Target, step: str,
                reason: str) -> None:  # fmt: skip
        """Roll an agent change back before it is confirmed; journal why."""
        error = self.rollback(target, change["changeId"])
        if self.settle(change, reason, error):
            self.failed += 1
        self.event(step, item, "rolled_back" if error is None else "failed",
                   reason if error is None else ROLLBACK_FAILED)  # fmt: skip

    def roll_back_port(self, item: PlanItem, target: Target, change: Change) -> tuple:
        """A confirmed SSH port goes back the way it came (§9.3): the old port is proved
        by a new connection, from outside on 3x-ui, before the new one closes.

        (error, back): back when SSH listens on the old port only again.
        """
        from kerberos.nodes.ssh_port import roll_back_port

        node = self.session.snapshot.node(item.node_uuid or "")
        address = node.address if node else target.address

        def ask(port: int) -> bool:
            return bool(self.ask_old_port(port, f"ssh -p {port} root@{address}"))

        return roll_back_port(self.env, target, change, ask)

    def restore_access(self, item: PlanItem, change: Change, original: Target,
                       previous: Optional[str]) -> None:  # fmt: skip
        """A confirmed access change went back: KERBEROS's own records go back with it."""
        if item.fix_id == "ssh.port" and change["state"] == "confirmed":
            self.move_to_port(item.node_uuid or "", original.port)
        if item.fix_id == "hostkeys.regenerate" and previous:
            self.env.state.pin(original.address, original.port, "ssh-ed25519", previous)

    def outside_login(self, item: PlanItem, port: int) -> bool:
        node = self.session.snapshot.node(item.node_uuid or "")
        address = node.address if node else ""
        return bool(self.ask_outside(port, f"ssh -p {port} root@{address}"))

    def pin_new_host_key(self, target: Target, change: Change) -> tuple[Optional[str], bool]:
        """§10.3: read the new key from the agent, check it with ssh-keyscan, pin it.

        (the key pinned before, whether sshd now shows one of the new keys).
        """
        state = self.env.state
        previous = state.pinned(target.address, target.port)
        new = {k["fingerprint"] for k in change["details"].get("hostKeys", [])
               if k.get("type") == "ED25519"}  # fmt: skip
        scanned = self.env.transport.keyscan(target.address, target.port)
        if scanned is None or scanned.fingerprint not in new:
            return previous, False
        state.pin(target.address, target.port, scanned.type, scanned.blob)
        change["details"]["previousKey"] = previous
        self.save()
        return previous, True

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

    def rollback(self, target: Target, change_id: str, fresh: bool = False,
                 missing_ok: bool = False) -> Optional[str]:  # fmt: skip
        """None: the agent rolled the change back; else the code of why it did not.

        `missing_ok`: an agent with no record of the change never applied it.
        """
        try:
            self.env.transport.agent(target, f"rollback {change_id}", fresh=fresh)
            return None
        except NodeAgentError as exc:
            return None if missing_ok and exc.code == "no_backup" else exc.code
        except TransportError as exc:
            return exc.kind

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
        if item.fix_id == "node_api.panel_only":
            return self.panel_keeps_node(item.node_uuid or "")
        return True

    def panel_keeps_node(self, node_uuid: str) -> bool:
        """§10.3: the panel still reaches the node a while after the rule (6 × 5 s).

        The panel notices a lost node only on its next health check, so one look
        right after the rule proves nothing. The demo has nothing to wait for.
        """
        panel = self.session.panel
        if panel is None or not hasattr(panel, "nodes"):
            return True
        pause = 0 if self.env.demo else NODE_API_PAUSE
        for _ in range(NODE_API_POLLS):
            if pause:
                self.env.clock.sleep(pause)
            try:
                nodes = {n.uuid: n for n in panel.nodes()}
            except Exception:  # noqa: BLE001 - the panel check is advisory here
                return True
            current = nodes.get(node_uuid)
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

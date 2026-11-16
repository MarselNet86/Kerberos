"""Self-steal of one node (tech.md §10.4): own domain, copies of hosts, old ones off.

Steps, each a journaled change: the site and certificate on the node; the
letsencrypt volume if the node container lacks it; the profile from the
template; the new inbound in the squads; copies of hosts with the new SNI,
then the old hosts disabled (never before the copies exist); a check from
the panel server. A failure undoes what was done, in reverse order.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from typing import Any, Optional

from kerberos.checks import spec
from kerberos.fixes.hosts import copy_fields, hysteria_host, mismatches
from kerberos.fixes.journal import iso
from kerberos.fixes.model import Change
from kerberos.fixes.panel_changes import digest, save_snapshot, undo
from kerberos.fixes.profile import build_profile, is_hysteria, is_reality, server_names
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, TransportError
from kerberos.panel.errors import PanelError
from kerberos.probe import HttpResult

FINALIZE_AFTER = timedelta(hours=24)
CHECK_ATTEMPTS = 6
CHECK_PAUSE = 5


class StepFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SelfSteal:
    def __init__(self, engine: Any, item: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.item = item
        self.client = self.session.panel
        self.node = self.session.snapshot.node(item.node_uuid)
        self.target = engine.target(item.node_uuid)
        self.domain = item.params["domain"]
        self.done: list[Change] = []
        self.current: Optional[Change] = None  # a panel change caught half way
        # Reality keys come from the system's secure source; the demo is repeatable.
        self.rng = random.Random(item.node_uuid) if self.env.demo else random.SystemRandom()

    # -- journal -------------------------------------------------------------
    def change(self, fix_id: str, target: str, params: Optional[dict] = None) -> Change:
        change: Change = {
            "changeId": str(uuid.uuid4()),
            "fixId": fix_id,
            "target": target,
            "state": "applying",
            "params": {**(params or {}), "node": self.node.uuid},
            "before": None,
            "details": {},
            "error": None,
            "startedAt": iso(self.env.clock),
            "finishedAt": None,
        }
        self.engine.run["changes"].append(change)
        self.current = change
        self.engine.save()
        return change

    def applied(self, change: Change) -> None:
        change["state"] = "applied"
        change["finishedAt"] = iso(self.env.clock)
        self.done.append(change)
        self.current = None
        self.engine.save()

    # -- steps ---------------------------------------------------------------
    def agent(self, fix_id: str, params: dict) -> dict:
        change = self.change(fix_id, self.item.target, params)
        try:
            answer = self.env.transport.agent(
                self.target, f"apply {fix_id} {change['changeId']}", params
            )
        except NodeAgentError as exc:
            self.engine.finish(change, "failed", exc.code)
            raise StepFailed(exc.code) from exc
        except TransportError as exc:
            self.engine.rollback(self.target, change["changeId"])
            self.engine.finish(change, "failed", exc.kind)
            raise StepFailed(exc.kind) from exc
        change["details"] = dict(answer.get("details") or {})
        self.applied(change)
        return change["details"]

    def panel_step(self, change: Change, action) -> Any:
        try:
            return action()
        except PanelError as exc:
            self.engine.finish(change, "failed", exc.code)
            raise StepFailed(exc.code) from exc

    def site(self) -> None:
        self.engine.event("apply", self.item, "running")
        params = {"domain": self.domain, "siteSeed": self.item.params.get("siteSeed", 0)}
        self.agent("self_steal.site", params)

    def mount(self) -> None:
        facts = (self.session.data["input"].node_data(self.node.uuid).facts) or {}
        if not (facts.get("remnanode") or {}).get("letsencryptMounted", True):
            self.agent("node.letsencrypt_mount", {})

    def profile(self) -> tuple:
        profile = self.session.snapshot.node_profile(self.node)
        change = self.change(
            "self_steal.profile", f"profile:{profile.uuid}", {"domain": self.domain}
        )
        current = self.panel_step(
            change, lambda: next(p for p in self.client.profiles() if p.uuid == profile.uuid)
        )
        run_id = self.engine.run["runId"]
        change["before"] = save_snapshot(
            self.engine.store,
            run_id,
            f"profile-{profile.uuid}",
            {"uuid": profile.uuid, "config": current.config},
        )
        new = build_profile(current.config, self.node.name, self.domain, self.rng)
        written_path = save_snapshot(
            self.engine.store, run_id, f"profile-{profile.uuid}-written", new
        )
        change["details"] = {
            "profileUuid": profile.uuid,
            "domain": self.domain,
            "oldNames": [n for n in server_names(current.config) if n != self.domain],
            "written": digest(new),
            "writtenPath": written_path,
        }
        self.engine.save()
        patched = self.panel_step(change, lambda: self.client.patch_profile(profile.uuid, new))
        profile.config, profile.inbounds = patched.config, patched.inbounds
        self.applied(change)
        had_hysteria = any(is_hysteria(i) for i in current.config.get("inbounds") or [])
        return patched, had_hysteria

    def squads(self, patched: Any, had_hysteria: bool) -> None:
        if had_hysteria:
            return
        tags = {i.get("tag"): i for i in patched.config.get("inbounds") or []}
        reality = next((t for t, i in tags.items() if is_reality(i)), None)
        hysteria = next((t for t, i in tags.items() if is_hysteria(i)), None)
        by_tag = {i.tag: i.uuid for i in patched.inbounds}
        if reality not in by_tag or hysteria not in by_tag:
            return
        change = self.change("self_steal.squads", "panel", {"inbound": hysteria})
        squads = self.panel_step(change, self.client.squads)
        touched = {
            s.uuid: list(s.inbound_uuids)
            for s in squads
            if by_tag[reality] in s.inbound_uuids and by_tag[hysteria] not in s.inbound_uuids
        }
        change["before"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"squads-{self.node.uuid}", touched
        )
        change["details"] = {"squads": touched}
        self.engine.save()
        for squad_uuid, inbounds in touched.items():
            self.panel_step(
                change,
                lambda u=squad_uuid, i=inbounds: self.client.patch_squad(u, i + [by_tag[hysteria]]),
            )
        self.applied(change)

    def hosts(self, patched: Any) -> None:
        change = self.change("self_steal.hosts", self.item.target, {"domain": self.domain})
        hosts = self.panel_step(change, self.client.hosts)
        by_tag = {i.tag: i for i in patched.inbounds}
        wanted = {
            i.uuid
            for i in by_tag.values()
            if i.type in ("vless", "hysteria") and i.network != "xhttp"
        }
        sources = [
            h for h in hosts if h.inbound_uuid in wanted and not h.is_disabled and self.belongs(h)
        ]
        change["details"] = {"created": [], "disabled": [], "atEnd": True}
        self.engine.save()
        for source in sources:
            self.create(change, copy_fields(source, self.domain))
        hysteria = next((i for i in patched.inbounds if i.type == "hysteria"), None)
        vless = {i.uuid for i in patched.inbounds if i.type == "vless"}
        reality_sources = [h for h in sources if h.inbound_uuid in vless]
        has_hy2_host = hysteria is not None and any(
            h.inbound_uuid == hysteria.uuid for h in sources
        )
        if hysteria and reality_sources and not has_hy2_host:
            remark = f"{reality_sources[0].remark} Hysteria2".strip()
            self.create(
                change,
                hysteria_host(reality_sources[0], self.domain, patched.uuid, hysteria.uuid, remark),
            )
        # Old hosts go off only now, after every copy exists and was read back.
        old = [h.uuid for h in sources]
        if old:
            self.panel_step(change, lambda: self.client.disable_hosts(old))
            change["details"]["disabled"] = old
        self.applied(change)

    def belongs(self, host: Any) -> bool:
        profile = self.session.snapshot.node_profile(self.node)
        if profile is None or len(profile.node_uuids) <= 1:
            return True
        return host.address == self.node.address

    def create(self, change: Change, fields: dict) -> None:
        created = self.panel_step(change, lambda: self.client.create_host(fields))
        change["details"]["created"].append(created.uuid)
        self.engine.save()
        stored = next(
            (h for h in self.panel_step(change, self.client.hosts) if h.uuid == created.uuid), None
        )
        if stored is None or mismatches(fields, stored):
            self.engine.finish(change, "failed", "host_mismatch")
            raise StepFailed("host_mismatch")

    def check(self) -> None:
        """§10.4 step 5: TLS without SNI shows the domain, the site answers, node online."""
        self.engine.event("check", self.item, "running")
        data = self.session.data["input"]
        node_data = data.node_data(self.node.uuid)
        ip = node_data.ipv4 if node_data else None
        if not ip:
            raise StepFailed("check_failed")
        prober = self.env.prober
        for attempt in range(CHECK_ATTEMPTS):
            tls = prober.tls_names(ip, 443, None)
            page = prober.http(ip, 443, self.domain, "/") if self.domain in tls.names else None
            if tls.ok and self.domain in tls.names and page and page.status == 200:
                data.tls[ip] = tls
                data.pages[(ip, 443, self.domain, "/")] = page or HttpResult(None)
                break
            if attempt + 1 < CHECK_ATTEMPTS:
                self.env.clock.sleep(CHECK_PAUSE)
        else:
            raise StepFailed("check_failed")
        data.dns[self.domain] = prober.resolve(self.domain)
        try:
            online = {n.uuid: n.is_connected for n in self.client.nodes()}
        except PanelError as exc:
            raise StepFailed(exc.code) from exc
        if not online.get(self.node.uuid, False):
            raise StepFailed("node_offline")
        try:
            node_data.facts = schema.facts(self.env.transport.agent(self.target, "facts"))
        except (NodeAgentError, TransportError, schema.BadAnswer):
            pass
        for check_id in self.item.checks:
            if check_id not in ("reality.foreign_sni", "probe.no_sni"):
                continue
            for finding in spec(check_id).rule(data):
                if finding["target"] == self.item.target and not finding["ok"]:
                    raise StepFailed("check_failed")

    # -- the whole -------------------------------------------------------------
    def run(self) -> bool:
        try:
            self.site()
            self.mount()
            patched, had_hysteria = self.profile()
            self.squads(patched, had_hysteria)
            self.hosts(patched)
            self.engine.event("apply", self.item, "ok")
            self.check()
        except StepFailed as exc:
            self.undo_all(exc.code)
            self.engine.event("check", self.item, "rolled_back", exc.code)
            return False
        self.engine.event("check", self.item, "ok")
        profile_change = next(c for c in self.done if c["fixId"] == "self_steal.profile")
        due = self.env.clock.now() + FINALIZE_AFTER
        self.engine.run["pending"].append(
            {
                "changeId": profile_change["changeId"],
                "action": "finalize",
                "due": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "profileUuid": profile_change["details"]["profileUuid"],
                "domain": self.domain,
                "nodeUuid": self.node.uuid,
                "nodeName": self.node.name,
            }
        )
        self.engine.save()
        return True

    def undo_all(self, reason: str) -> None:
        half = self.current
        if half is not None and half["fixId"] in ("self_steal.squads", "self_steal.hosts"):
            # Copies already created (or squads already patched) go back too.
            undone = undo(self.client, half) is None
            half["state"] = "rolled_back" if undone else "failed"
            half["error"] = reason
        for change in reversed(self.done):
            if change["fixId"] in ("self_steal.site", "node.letsencrypt_mount"):
                ok = self.engine.rollback(self.target, change["changeId"])
            else:
                ok = undo(self.client, change) is None
            change["state"] = "rolled_back" if ok else "failed"
            change["error"] = reason
            change["finishedAt"] = iso(self.env.clock)
        self.engine.failed += 1
        self.engine.save()

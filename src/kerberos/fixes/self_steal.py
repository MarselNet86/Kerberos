"""Self-steal of one node (tech.md §10.4): own domain, copies of hosts, old ones off.

Steps, each a journaled change: the site and certificate on the node; the
letsencrypt volume if the node container lacks it; the profile from the
template; the new inbound in the squads; copies of hosts with the new SNI,
then the old hosts disabled (never before the copies exist); a check from
the panel server. A failure undoes what was done, in reverse order: the step
caught half way first. A change that cannot be undone keeps the state it
reached, with error `rollback_failed`.
"""

from __future__ import annotations

import random
import uuid
from datetime import timedelta
from typing import Any, Optional

from kerberos.checks import spec
from kerberos.fixes.hosts import copy_fields, hysteria_host, mismatches
from kerberos.fixes.journal import iso
from kerberos.fixes.model import ROLLBACK_FAILED, Change
from kerberos.fixes.panel_changes import digest, save_snapshot, undo
from kerberos.fixes.profile import (
    build_profile,
    is_hysteria,
    server_names,
    template_tags,
)
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, TransportError
from kerberos.panel.errors import PanelError
from kerberos.probe import HttpResult

FINALIZE_AFTER = timedelta(hours=24)
CHECK_ATTEMPTS = 6
CHECK_PAUSE = 5
AGENT_STEPS = ("self_steal.site", "node.letsencrypt_mount")
# The step-5 check judges these findings, and reality.foreign_sni only for the inbounds
# this self-steal changed: another inbound of the person keeps its own SNI.
CHECKED = ("reality.foreign_sni", "probe.no_sni")


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
        self.changed: set = set()  # tags of the Reality inbounds this self-steal changed
        self.clean = True  # False once a change could not be rolled back
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
            self.current = None  # the agent put its files back itself
            self.engine.finish(change, "failed", exc.code)
            raise StepFailed(exc.code) from exc
        except TransportError as exc:
            self.current = None
            error = self.engine.rollback(self.target, change["changeId"], missing_ok=True)
            if not self.engine.settle(change, exc.kind, error, done="failed"):
                self.clean = False
            raise StepFailed(exc.kind) from exc
        change["details"] = dict(answer.get("details") or {})
        self.applied(change)
        return change["details"]

    @staticmethod
    def panel_call(action) -> Any:
        """A panel request of the current step; `undo_all` puts back what the step wrote."""
        try:
            return action()
        except PanelError as exc:
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
        current = self.panel_call(
            lambda: next(p for p in self.client.profiles() if p.uuid == profile.uuid)
        )
        run_id = self.engine.run["runId"]
        change["before"] = save_snapshot(
            self.engine.store,
            run_id,
            f"profile-{profile.uuid}",
            {"uuid": profile.uuid, "config": current.config},
        )
        new = build_profile(current.config, self.node.name, self.domain, self.rng)
        tags = template_tags(new)
        self.changed = {tags["reality"]} - {None}
        written_path = save_snapshot(
            self.engine.store, run_id, f"profile-{profile.uuid}-written", new
        )
        change["details"] = {
            "profileUuid": profile.uuid,
            "domain": self.domain,
            "oldNames": [n for n in server_names(current.config) if n != self.domain],
            "written": digest(new),
            "writtenPath": written_path,
            "tags": tags,
        }
        self.engine.save()
        patched = self.panel_call(lambda: self.client.patch_profile(profile.uuid, new))
        profile.config, profile.inbounds = patched.config, patched.inbounds
        self.applied(change)
        had_hysteria = any(is_hysteria(i) for i in current.config.get("inbounds") or [])
        return patched, had_hysteria, tags

    def squads(self, patched: Any, had_hysteria: bool, tags: dict) -> None:
        if had_hysteria:
            return
        reality, hysteria = tags["reality"], tags["hysteria"]
        by_tag = {i.tag: i.uuid for i in patched.inbounds}
        if reality not in by_tag or hysteria not in by_tag:
            return
        change = self.change("self_steal.squads", "panel", {"inbound": hysteria})
        squads = self.panel_call(self.client.squads)
        touched = {
            s.uuid: list(s.inbound_uuids)
            for s in squads
            if by_tag[reality] in s.inbound_uuids and by_tag[hysteria] not in s.inbound_uuids
        }
        change["before"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"squads-{self.node.uuid}", touched
        )
        # The uuid KERBEROS adds: a rollback takes only it out of each squad.
        change["details"] = {"squads": touched, "added": by_tag[hysteria]}
        self.engine.save()
        for squad_uuid, inbounds in touched.items():
            self.panel_call(
                lambda u=squad_uuid, i=inbounds: self.client.patch_squad(u, i + [by_tag[hysteria]]),
            )
        self.applied(change)

    def hosts(self, patched: Any, tags: dict) -> None:
        change = self.change("self_steal.hosts", self.item.target, {"domain": self.domain})
        hosts = self.panel_call(self.client.hosts)
        by_tag = {i.tag: i for i in patched.inbounds}
        # §10.4 step 3: hosts of the inbounds the template replaced. Other inbounds of the
        # person (WebSocket, gRPC, a second Reality) keep their hosts and SNI.
        reality = by_tag.get(tags["reality"])
        hysteria = by_tag.get(tags["hysteria"])
        wanted = {i.uuid for i in (reality, hysteria) if i is not None}
        sources = [
            h for h in hosts if h.inbound_uuid in wanted and not h.is_disabled and self.belongs(h)
        ]
        change["details"] = {"created": [], "disabled": [], "atEnd": True}
        self.engine.save()
        template = self.template_uuid()
        for source in sources:
            self.create(change, copy_fields(source, self.domain, template_uuid=template))
        reality_sources = [h for h in sources if reality and h.inbound_uuid == reality.uuid]
        has_hy2_host = hysteria is not None and any(
            h.inbound_uuid == hysteria.uuid for h in sources
        )
        if hysteria and reality_sources and not has_hy2_host:
            remark = f"{reality_sources[0].remark} Hysteria2".strip()
            fields = hysteria_host(
                reality_sources[0], self.domain, patched.uuid, hysteria.uuid, remark
            )
            fields["xrayJsonTemplateUuid"] = template
            self.create(change, fields)
        # Old hosts go off only now, after every copy exists and was read back.
        old = [h.uuid for h in sources]
        if old:
            self.panel_call(lambda: self.client.disable_hosts(old))
            change["details"]["disabled"] = old
        self.applied(change)

    def template_uuid(self) -> Any:
        """§10.9: copies get «KERBEROS» in a pair with a reserve, else «без резерва»."""
        paired = self.item.params.get("reserve") or self.item.params.get("reserveOf")
        try:
            templates = self.engine.panel_fixes.templates()
        except PanelError as exc:
            raise StepFailed(exc.code) from exc
        return templates["reserve" if paired else "single"]

    def belongs(self, host: Any) -> bool:
        profile = self.session.snapshot.node_profile(self.node)
        if profile is None or len(profile.node_uuids) <= 1:
            return True
        return host.address == self.node.address

    def create(self, change: Change, fields: dict) -> None:
        created = self.panel_call(lambda: self.client.create_host(fields))
        change["details"]["created"].append(created.uuid)
        self.engine.save()
        stored = next(
            (h for h in self.panel_call(self.client.hosts) if h.uuid == created.uuid), None
        )
        if stored is None or mismatches(fields, stored):
            raise StepFailed("host_mismatch")

    def check(self) -> None:
        """§10.4 step 5; what it saw is dropped again when the self-steal is undone."""
        self.engine.event("check", self.item, "running")
        data = self.session.data["input"]
        node_data = data.node_data(self.node.uuid)
        saved = (dict(data.tls), dict(data.pages), dict(data.dns), data.snapshot,
                 node_data.facts if node_data else None)  # fmt: skip
        try:
            self.verify(data, node_data)
        except Exception:
            # The findings after «Исправление» must not show a state that is being undone.
            data.tls, data.pages, data.dns, data.snapshot = saved[:4]
            if node_data is not None:
                node_data.facts = saved[4]
            raise

    def verify(self, data: Any, node_data: Any) -> None:
        """TLS without SNI shows the domain, the site answers, the node is online."""
        ip = node_data.ipv4 if node_data else None
        if not ip:
            raise StepFailed("check_failed")
        self.reach_site(data, ip)
        try:
            online = {n.uuid: n.is_connected for n in self.client.nodes()}
        except PanelError as exc:
            raise StepFailed(exc.code) from exc
        if not online.get(self.node.uuid, False):
            raise StepFailed("node_offline")
        self.read_facts(node_data)
        self.judge(data)

    def reach_site(self, data: Any, ip: str) -> None:
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

    def read_facts(self, node_data: Any) -> None:
        try:
            node_data.facts = schema.facts(self.env.transport.agent(self.target, "facts"))
        except (NodeAgentError, TransportError, schema.BadAnswer):
            pass

    def judge(self, data: Any) -> None:
        """The findings this self-steal fixes are fixed: Reality only where it changed."""
        for check_id in self.item.checks:
            if check_id not in CHECKED:
                continue
            for finding in spec(check_id).rule(data):
                if finding["target"] != self.item.target or finding["ok"]:
                    continue
                inbound = finding["evidence"].get("inbound")
                if check_id == "reality.foreign_sni" and inbound not in self.changed:
                    continue
                raise StepFailed("check_failed")

    # -- the whole -------------------------------------------------------------
    def steps(self) -> Change:
        """Every step up to the check; the change that finalization later works on."""
        self.site()
        self.mount()
        patched, had_hysteria, tags = self.profile()
        profile_change = self.done[-1]
        self.squads(patched, had_hysteria, tags)
        self.hosts(patched, tags)
        return profile_change

    def pending(self, change: Change) -> dict:
        due = self.env.clock.now() + FINALIZE_AFTER
        return {
            "changeId": change["changeId"],
            "action": "finalize",
            "due": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "profileUuid": change["details"]["profileUuid"],
            "domain": self.domain,
            "nodeUuid": self.node.uuid,
            "nodeName": self.node.name,
        }

    def run(self) -> bool:
        try:
            change = self.steps()
            self.engine.event("apply", self.item, "ok")
            self.check()
        except StepFailed as exc:
            self.fail(exc.code)
            return False
        except Exception as exc:  # noqa: BLE001 - a self-steal is never left half done
            self.engine.store.log(self.engine.run, f"self_steal: internal error "
                                                   f"{type(exc).__name__}")  # fmt: skip
            self.fail("internal_error")
            return False
        self.engine.event("check", self.item, "ok")
        self.engine.run["pending"].append(self.pending(change))
        self.engine.save()
        return True

    def fail(self, code: str) -> None:
        rolled = self.undo_all(code)
        self.engine.event("check", self.item, "rolled_back" if rolled else "failed",
                          code if rolled else ROLLBACK_FAILED)  # fmt: skip

    def undo_all(self, reason: str) -> bool:
        """Everything done goes back in reverse order; False: something stayed in place."""
        half, self.current = self.current, None
        # The step caught half way (a panel change: agent steps settle themselves) first.
        for change in ([half] if half is not None else []) + list(reversed(self.done)):
            if change["fixId"] in AGENT_STEPS:
                error = self.engine.rollback(self.target, change["changeId"])
            else:
                error = undo(self.client, change, ask=self.engine.ask_undo)
            if not self.engine.settle(change, reason, error):
                self.clean = False
        if self.clean:
            self.engine.failed += 1
        self.engine.save()
        return self.clean

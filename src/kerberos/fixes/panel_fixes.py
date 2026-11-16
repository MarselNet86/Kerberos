"""Fixes in the panel (tech.md §10.5, §10.9): templates, hosts, settings, reserves.

Each is a journaled change with a snapshot of what it touches, so rollback
can put the objects back. Templates of the person are never edited: hosts
move to the KERBEROS templates instead.
"""

from __future__ import annotations

import uuid as uuidlib
from typing import Any, Optional

from kerberos.fixes import subscription
from kerberos.fixes.journal import iso
from kerberos.fixes.model import Change
from kerberos.fixes.panel_changes import diff_text, digest, save_snapshot
from kerberos.panel.errors import PanelError

PANEL_ITEMS = {"sub.template", "sub.ping_type", "host.fingerprint", "reserve"}
PING_TYPE = "proxy-head"


class PanelFixes:
    """Panel changes of one run; the KERBEROS templates are made once and shared."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.client = self.session.panel
        self._templates: Optional[dict] = None

    # -- journal -------------------------------------------------------------
    def change(self, fix_id: str, target: str, params: Optional[dict] = None) -> Change:
        change: Change = {
            "changeId": str(uuidlib.uuid4()),
            "fixId": fix_id,
            "target": target,
            "state": "applying",
            "params": params or {},
            "before": None,
            "details": {},
            "error": None,
            "startedAt": iso(self.env.clock),
            "finishedAt": None,
        }
        self.engine.run["changes"].append(change)
        self.engine.save()
        return change

    def snapshot(self, change: Change, name: str, value: Any) -> None:
        change["before"] = save_snapshot(self.engine.store, self.engine.run["runId"], name, value)
        self.engine.save()

    # -- the two KERBEROS templates (§10.9) ----------------------------------
    def fleet_domains(self) -> list[str]:
        data = self.session.data["input"]
        domains = []
        for item in data.nodes:
            domains += data.own_domains(item)
        for change in self.engine.run["changes"]:
            if change["fixId"] == "self_steal.site" and change["state"] == "applied":
                domains.append(change["params"].get("domain", ""))
        return [d for d in dict.fromkeys(domains) if d]

    def templates(self) -> dict:
        """{"reserve": uuid, "single": uuid}, created or brought up to date once per run."""
        if self._templates is not None:
            return self._templates
        change = self.change("sub.templates", "panel")
        details: dict = {"templates": {}}
        change["details"] = details
        result = {}
        try:
            existing = {t.name: t for t in self.client.templates()}
            for kind, name in (("reserve", subscription.RESERVE_NAME),
                               ("single", subscription.SINGLE_NAME)):  # fmt: skip
                wanted = subscription.build(kind, self.fleet_domains())
                current = existing.get(name)
                if current is None:
                    current = self.client.create_template(name)
                    details["templates"][current.uuid] = {"created": True, "previousPath": None}
                    self.engine.save()
                else:
                    current = self.client.template(current.uuid)
                    if current.json == wanted:
                        result[kind] = current.uuid
                        continue
                    path = save_snapshot(self.engine.store, self.engine.run["runId"],
                                         f"template-{current.uuid}", current.json)  # fmt: skip
                    details["templates"][current.uuid] = {"created": False, "previousPath": path}
                    self.engine.save()
                    if current.json and not self.engine.ask_diff(diff_text(wanted, current.json)):
                        result[kind] = current.uuid  # the person keeps their edits
                        continue
                self.client.patch_template(current.uuid, wanted)
                details["templates"][current.uuid]["written"] = digest(wanted)
                result[kind] = current.uuid
        except PanelError as exc:
            self.engine.finish(change, "failed", exc.code)
            raise
        self.engine.finish(change, "applied")
        self._templates = result
        return result

    # -- one plan item ---------------------------------------------------------
    def run(self, item: Any) -> bool:
        handler = {
            "sub.template": self.sub_template,
            "sub.ping_type": self.ping_type,
            "host.fingerprint": self.fingerprint,
            "reserve": self.reserve,
        }[item.fix_id]
        self.engine.event("backup", item, "running")
        try:
            change = handler(item)
        except PanelError as exc:
            self.engine.failed += 1
            self.engine.event("apply", item, "failed", exc.code)
            return False
        self.engine.event("backup", item, "ok")
        self.engine.event("apply", item, "ok")
        self.engine.event("confirm", item, "skipped")
        if not self.recheck(item, change):
            from kerberos.fixes.panel_changes import undo

            reason = undo(self.client, change)
            self.engine.failed += 1
            self.engine.event("check", item, "rolled_back" if reason is None else "failed",
                              "recheck")  # fmt: skip
            self.engine.finish(change, "rolled_back" if reason is None else "failed",
                               "recheck_failed")  # fmt: skip
            return False
        self.engine.event("check", item, "ok")
        self.engine.finish(change, "applied")
        return True

    def guarded(self, change: Change, action) -> Any:
        try:
            return action()
        except PanelError as exc:
            self.engine.finish(change, "failed", exc.code)
            raise

    def sub_template(self, item: Any) -> Change:
        """§10.5: hosts with the finding move to a KERBEROS template; theirs stay intact."""
        templates = self.templates()
        params = {"hosts": list(item.params["hosts"]), "name": item.params.get("name", "")}
        change = self.change("sub.template", item.target, params)
        hosts = {h.uuid: h for h in self.guarded(change, self.client.hosts)}
        previous = {u: hosts[u].template_uuid for u in item.params["hosts"] if u in hosts}
        self.snapshot(change, f"hosts-{change['changeId'][:8]}", previous)
        change["details"] = {"hosts": previous}
        paired = set(item.params.get("paired", []))
        for host_uuid in previous:
            kind = "reserve" if host_uuid in paired else "single"
            self.guarded(change, lambda u=host_uuid, k=kind: self.client.patch_host(
                u, {"xrayJsonTemplateUuid": templates[k]}))  # fmt: skip
        return change

    def ping_type(self, item: Any) -> Change:
        """§10.5: read, merge, write: PATCH replaces the whole header object."""
        change = self.change("sub.ping_type", "panel")
        settings = self.guarded(change, self.client.sub_settings)
        self.snapshot(change, "subscription-settings", {"uuid": settings.uuid,
                                                        "headers": settings.headers})  # fmt: skip
        change["details"] = {"uuid": settings.uuid, "previous": dict(settings.headers)}
        headers = dict(settings.headers)
        headers["ping-type"] = PING_TYPE
        self.guarded(change, lambda: self.client.patch_sub_settings(settings.uuid, headers))
        return change

    def fingerprint(self, item: Any) -> Change:
        host_uuid = item.params["host"]
        params = {"host": host_uuid, "remark": item.params.get("remark", "")}
        change = self.change("host.fingerprint", item.target, params)
        hosts = {h.uuid: h for h in self.guarded(change, self.client.hosts)}
        change["details"] = {"previous": hosts[host_uuid].fingerprint if host_uuid in hosts else ""}
        self.guarded(change, lambda: self.client.patch_host(host_uuid, {"fingerprint": "firefox"}))
        return change

    def reserve(self, item: Any) -> Change:
        """§10.9: copies of the main and of the reserve share tags; the reserve's are hidden."""
        templates = self.templates()
        main, spare = item.node_uuid, item.params["reserve"]
        change = self.change("reserve", item.target, {"reserve": spare, "node": main})
        hosts = {h.uuid: h for h in self.guarded(change, self.client.hosts)}
        main_name = self.session.snapshot.node(main).name
        tags = subscription.pair_tags(main_name)
        plan = {}
        for node_uuid, hidden in ((main, False), (spare, True)):
            for host_uuid in self.copies_of(node_uuid):
                host = hosts.get(host_uuid)
                if host is None:
                    continue
                kind = "hysteria" if self.is_hysteria(host) else "vless"
                plan[host_uuid] = ({"tags": host.tags, "isHidden": host.is_hidden,
                                    "xrayJsonTemplateUuid": host.template_uuid},
                                   {"tags": [tags[kind]], "isHidden": hidden,
                                    "xrayJsonTemplateUuid": templates["reserve"]})  # fmt: skip
        previous = {u: before for u, (before, _after) in plan.items()}
        self.snapshot(change, f"reserve-{main[:8]}", previous)
        change["details"] = {"hosts": previous, "tags": tags}
        for host_uuid, (_before, after) in plan.items():
            self.guarded(change, lambda u=host_uuid, a=after: self.client.patch_host(u, a))
        return change

    def copies_of(self, node_uuid: str) -> list[str]:
        for change in self.engine.run["changes"]:
            if (
                change["fixId"] == "self_steal.hosts"
                and change["state"] == "applied"
                and (change["params"].get("node") == node_uuid)
            ):
                return list(change["details"].get("created", []))
        return []

    def is_hysteria(self, host: Any) -> bool:
        for profile in self.session.snapshot.profiles:
            for inbound in profile.inbounds:
                if inbound.uuid == host.inbound_uuid:
                    return inbound.type in ("hysteria", "hysteria2")
        return False

    # -- checking again --------------------------------------------------------
    def recheck(self, item: Any, change: Change) -> bool:
        try:
            if item.fix_id == "sub.ping_type":
                headers = self.client.sub_settings().headers
                return any(k.lower() == "ping-type" for k in headers)
            hosts = {h.uuid: h for h in self.client.hosts()}
            if item.fix_id == "host.fingerprint":
                host = hosts.get(item.params["host"])
                return bool(host and host.fingerprint)
            if item.fix_id == "sub.template":
                wanted = set(self.templates().values())
                return all(hosts[u].template_uuid in wanted for u in change["details"]["hosts"]
                           if u in hosts)  # fmt: skip
            if item.fix_id == "reserve":
                for host_uuid in change["details"]["hosts"]:
                    host = hosts.get(host_uuid)
                    if host is None or not set(host.tags) & set(change["details"]["tags"].values()):
                        return False
                return True
        except PanelError:
            return False
        return True

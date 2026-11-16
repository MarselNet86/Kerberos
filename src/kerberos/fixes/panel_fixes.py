"""Fixes in the panel (tech.md §10.5, §10.9): templates, hosts, settings, reserves.

Each is a journaled change with a snapshot of what it touches, so rollback
can put the objects back. Templates of the person are never edited: hosts
move to the KERBEROS templates instead.
"""

from __future__ import annotations

import random
import uuid as uuidlib
from typing import Any, Optional

from kerberos.fixes import subscription, xhttp
from kerberos.fixes.journal import iso
from kerberos.fixes.model import Change
from kerberos.fixes.panel_changes import diff_text, digest, load_snapshot, save_snapshot, undo
from kerberos.panel.errors import PanelError

PANEL_ITEMS = {
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "reserve",
    "xhttp.padding",
    "xhttp.uplink_get",
}
PING_TYPE = "proxy-head"


class PanelFixes:
    """Panel changes of one run; the KERBEROS templates are made once and shared."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.client = self.session.panel
        self._templates: Optional[dict] = None
        self.current: Optional[Change] = None  # the change a failing step belongs to

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
        self.current = change
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
            "xhttp.padding": self.padding,
            "xhttp.uplink_get": self.uplink,
        }[item.fix_id]
        self.engine.event("backup", item, "running")
        self.current = None
        try:
            change = handler(item)
        except PanelError as exc:
            self.engine.failed += 1
            change = self.current
            if change is not None and change["state"] == "applying":
                # Part of it may be written already: put that back (§10.1).
                reason = undo(self.client, change)
                self.engine.finish(change, "rolled_back" if reason is None else "failed",
                                   exc.code)  # fmt: skip
            self.engine.event("apply", item, "failed", exc.code)
            return False
        self.engine.event("backup", item, "ok")
        self.engine.event("apply", item, "ok")
        self.engine.event("confirm", item, "skipped")
        if not self.recheck(item, change):
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
        """A panel call of a change; a failure is undone and finished by `run`."""
        return action()

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

    def padding(self, item: Any) -> Change:
        """§10.6: one set of padding fields in the inbound and in every host of it."""
        node_uuid = item.params["node"]
        params = {"node": node_uuid, "inbounds": list(item.params["inbounds"])}
        change = self.change("xhttp.padding", item.target, params)
        node = self.session.snapshot.node(node_uuid)
        profiles = {p.uuid: p for p in self.client.profiles()}
        profile = profiles.get(node.profile_uuid if node else None)
        if profile is None:
            raise PanelError("bad_response", "the node has no profile")
        rng = random.Random(node_uuid) if self.env.demo else random.SystemRandom()
        config, written = xhttp.add_padding(profile.config, params["inbounds"], rng)
        uuids = {i.uuid: i.tag for i in profile.inbounds if i.tag in written}
        hosts = [h for h in self.client.hosts() if h.inbound_uuid in uuids]
        change["details"] = {"profileUuid": profile.uuid, "inbounds": sorted(written),
                             "hosts": {h.uuid: uuids[h.inbound_uuid] for h in hosts}}  # fmt: skip
        if not written:
            self.engine.save()
            return change
        self.snapshot(change, f"profile-{profile.uuid}-padding",
                      {"uuid": profile.uuid, "config": profile.config})  # fmt: skip
        # The written values live in a 0600 file, like every panel snapshot.
        change["details"]["writtenPath"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"padding-{change['changeId'][:8]}",
            written)  # fmt: skip
        self.engine.save()
        self.client.patch_profile(profile.uuid, config)
        for host in hosts:
            fields = written[uuids[host.inbound_uuid]]
            self.client.patch_host(host.uuid,
                                   {"xhttpExtraParams": xhttp.with_padding(host.xhttp_extra,
                                                                           fields)})  # fmt: skip
        return change

    def uplink(self, item: Any) -> Change:
        """§10.6: only the host's extra: uploads go as GET, which the CDN lets through."""
        host_uuid = item.params["host"]
        params = {"host": host_uuid, "remark": item.params.get("remark", "")}
        change = self.change("xhttp.uplink_get", item.target, params)
        host = next((h for h in self.client.hosts() if h.uuid == host_uuid), None)
        if host is None:
            raise PanelError("bad_response", "the host is gone")
        change["details"] = {"previous": (host.xhttp_extra or {}).get("uplinkHTTPMethod"),
                             "extraWasNone": host.xhttp_extra is None}  # fmt: skip
        self.engine.save()
        self.client.patch_host(host_uuid, {"xhttpExtraParams": xhttp.uplink_get(host.xhttp_extra)})
        return change

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
            if item.fix_id == "xhttp.uplink_get":
                host = hosts.get(item.params["host"])
                return bool(host and (host.xhttp_extra or {}).get("uplinkHTTPMethod") == "GET")
            if item.fix_id == "xhttp.padding":
                return self.padding_matches(change, hosts)
        except PanelError:
            return False
        return True

    def padding_matches(self, change: Change, hosts: dict) -> bool:
        """The server and every client of the inbound carry the same padding fields."""
        details = change["details"]
        if not details["inbounds"]:
            return True
        written = load_snapshot(details.get("writtenPath")) or {}
        profile = next((p for p in self.client.profiles() if p.uuid == details["profileUuid"]),
                       None)  # fmt: skip
        if profile is None:
            return False
        for tag in details["inbounds"]:
            inbound = profile.inbound_config(tag) or {}
            server = xhttp.padding_of(((inbound.get("streamSettings") or {})
                                       .get("xhttpSettings") or {}).get("extra"))  # fmt: skip
            if not server or server != written.get(tag):
                return False
            for host_uuid, host_tag in details["hosts"].items():
                host = hosts.get(host_uuid)
                if host_tag != tag:
                    continue
                if host is None or xhttp.padding_of(host.xhttp_extra) != server:
                    return False
        return True

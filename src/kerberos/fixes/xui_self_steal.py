"""Self-steal on a 3x-ui server (tech.md §7.6, §10.4).

The same site and certificate as on a Remnawave node (agent, step 1). In
3x-ui the clients' links are built from the inbound itself, so instead of
a profile, host copies and old hosts switched off, KERBEROS changes the
Reality inbounds of this server: the destination becomes the local stub
site and the own domain goes first in serverNames; the old names stay for a
day, until `kerberos finalize`. 3x-ui puts a random name of serverNames into
a fresh link, so for that day part of the clients may still get an old one.
"""

from __future__ import annotations

import copy
from typing import Any

from kerberos.fixes.panel_changes import digest, save_snapshot
from kerberos.fixes.self_steal import FINALIZE_AFTER, SelfSteal, StepFailed

STUB = "127.0.0.1:8445"


def is_reality(item: dict) -> bool:
    stream = item["streamSettings"]
    return item["protocol"] == "vless" and stream.get("security") == "reality"


def with_domain(stream: dict, domain: str) -> dict:
    """Reality of one inbound pointed at the stub site, the domain first in serverNames."""
    stream = copy.deepcopy(stream)
    reality = stream.setdefault("realitySettings", {})
    # Panels before v2.8 write `dest`, newer ones `target`: keep the inbound's own word.
    key = "dest" if "dest" in reality and "target" not in reality else "target"
    reality[key] = STUB
    names = [n for n in reality.get("serverNames") or [] if isinstance(n, str) and n]
    reality["serverNames"] = [domain] + [n for n in names if n != domain]
    return stream


def without_old_names(stream: dict, domain: str) -> dict:
    """Finalization: only the own domain is left (a no-op when it is not there)."""
    stream = copy.deepcopy(stream)
    reality = stream.get("realitySettings") or {}
    if domain in (reality.get("serverNames") or []):
        reality["serverNames"] = [domain]
    return stream


class SelfStealXui(SelfSteal):
    def reality(self) -> Any:
        change = self.change("xui.reality", self.item.target, {"domain": self.domain})
        inbounds = self.panel_call(self.client.inbounds)
        targets = [i for i in inbounds if i["enable"] and is_reality(i)]
        if not targets:
            self.current = None  # nothing was written
            self.engine.finish(change, "failed", "no_reality")
            raise StepFailed("no_reality")
        self.changed = {i["tag"] for i in targets}
        run_id = self.engine.run["runId"]
        before = {str(i["id"]): i["streamSettings"] for i in targets}
        written = {str(i["id"]): with_domain(i["streamSettings"], self.domain) for i in targets}
        # Both snapshots hold the Reality private key: 0600 files, never run.json.
        name = f"xui-reality-{change['changeId'][:8]}"
        change["before"] = save_snapshot(self.engine.store, run_id, name, before)
        change["details"] = {
            "domain": self.domain,
            "inbounds": sorted(written, key=int),
            "oldNames": {k: written[k]["realitySettings"]["serverNames"][1:] for k in written},
            "written": {k: digest(v) for k, v in written.items()},
            "writtenPath": save_snapshot(self.engine.store, run_id, f"{name}-written", written),
        }
        self.engine.save()
        for ident, stream in written.items():
            self.panel_call(lambda i=int(ident), s=stream: self.client.update_inbound(i, s))
        self.applied(change)
        return change

    def verify(self, data: Any, node_data: Any) -> None:
        """§10.4 step 5 without the panel's node list: 3x-ui has none, the node is here."""
        ip = node_data.ipv4 if node_data else None
        if not ip:
            raise StepFailed("check_failed")
        self.reach_site(data, ip)
        self.read_facts(node_data)
        try:
            data.snapshot = self.client.snapshot(self.session.location, self.node.address,
                                                 self.node.name)  # fmt: skip
        except Exception:  # noqa: BLE001 - the findings below then use what was read before
            pass
        self.judge(data)

    def steps(self) -> Any:
        self.site()
        return self.reality()

    def pending(self, change: Any) -> dict:
        due = self.env.clock.now() + FINALIZE_AFTER
        return {
            "changeId": change["changeId"],
            "action": "finalize",
            "due": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "panel": "3x-ui",
            "inbounds": change["details"]["inbounds"],
            "domain": self.domain,
            "nodeUuid": self.node.uuid,
            "nodeName": self.node.name,
        }

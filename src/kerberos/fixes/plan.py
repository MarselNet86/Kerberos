"""Plan of «Исправление» (tech.md §6 S7, §10.1): pure function of the findings.

One plan item is one fix on one target. Items are ordered as §10.1 wants
(per node, in a fixed order; panel fixes after the nodes). By default all
automatic fixes of high and medium risk are marked, except `ssh.port`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from kerberos.checks import CheckInput, spec
from kerberos.fixes.model import Finding

# §10.1, with access.admin_keys first: the person's own key reaches the node
# before ssh.key_only turns password login off.
NODE_ORDER = (
    "access.admin_keys",
    "mptcp.guard",
    "fail2ban.sshd",
    "node_api.panel_only",
    "ports.drop",
    "hostkeys.regenerate",
    "ssh.key_only",
    "ssh.port",
    "node.letsencrypt_mount",
    "self_steal",
    "watch.install",
)
PANEL_ORDER = ("sub.template", "sub.ping_type", "host.fingerprint", "xhttp.uplink_get")

# Fixes this version of KERBEROS can apply; the rest stay findings in the report.
IMPLEMENTED = {
    "access.admin_keys",
    "mptcp.guard",
    "fail2ban.sshd",
    "node_api.panel_only",
    "ports.drop",
    "hostkeys.regenerate",
    "ssh.key_only",
}
ACCESS_FIXES = {"ssh.key_only", "ssh.port", "hostkeys.regenerate"}
RISK_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class PlanItem:
    fix_id: str
    target: str
    node_uuid: Optional[str]
    params: dict = field(default_factory=dict)
    risk: str = "medium"
    checks: list[str] = field(default_factory=list)
    selected: bool = False
    blocked: Optional[str] = None  # reason: an error code of §9.2 or a text key

    @property
    def key(self) -> tuple:
        return (self.target, self.fix_id)


def order_key(item: PlanItem, node_index: dict) -> tuple:
    if item.node_uuid is not None:
        return (0, node_index.get(item.node_uuid, 999), NODE_ORDER.index(item.fix_id), "")
    return (1, 0, PANEL_ORDER.index(item.fix_id) if item.fix_id in PANEL_ORDER else 99,
            item.target)  # fmt: skip


def node_params(fix_id: str, finding: Finding, facts: dict, panel_ip: str) -> dict:
    if fix_id == "fail2ban.sshd":
        return {"sshPorts": list(facts["ssh"]["ports"]), "panelIp": panel_ip}
    if fix_id == "node_api.panel_only":
        return {"port": facts["nodeApi"]["port"], "panelIp": panel_ip}
    if fix_id == "ports.drop":
        return {"ports": list(finding["evidence"].get("ports", []))}
    return {}


def build_plan(findings: list[Finding], data: CheckInput, admin: Optional[dict],
               panel_ips: dict) -> list[PlanItem]:  # fmt: skip
    """`admin`: the choice of §8.5 ({mode, keys}); `panel_ips`: node uuid -> panel address."""
    items: dict = {}
    for finding in findings:
        fix_id = finding["fixId"]
        if finding["ok"] or fix_id not in IMPLEMENTED or spec(finding["checkId"]).kind != "fix":
            continue
        kind, _, ref = finding["target"].partition(":")
        if kind != "node":
            continue
        node = data.node_data(ref)
        if node is None or node.facts is None or node.access != "ok":
            continue
        key = (finding["target"], fix_id)
        item = items.get(key)
        if item is None:
            params = node_params(fix_id, finding, node.facts, panel_ips.get(ref, ""))
            item = PlanItem(fix_id, finding["target"], ref, params, finding["risk"])
            items[key] = item
        elif RISK_RANK[finding["risk"]] < RISK_RANK[item.risk]:
            item.risk = finding["risk"]
        if finding["checkId"] not in item.checks:
            item.checks.append(finding["checkId"])
        if fix_id == "ports.drop":
            for port in finding["evidence"].get("ports", []):
                if port not in item.params["ports"]:
                    item.params["ports"].append(port)
    for item in list(items.values()):
        node = data.node_data(item.node_uuid or "")
        facts = node.facts if node else {}
        if (
            item.fix_id == "node_api.panel_only"
            and (facts.get("remnanode") or {}).get("network") == "bridge"
        ):
            item.blocked = "bridge_network"
        if item.fix_id == "ssh.key_only" and not (facts.get("ssh") or {}).get("adminKeys"):
            mode = (admin or {}).get("mode", "skip")
            if mode in ("mine", "create"):
                keys = list((admin or {}).get("keys", []))
                extra = PlanItem("access.admin_keys", item.target, item.node_uuid,
                                 {"keys": keys, "create": mode == "create"}, item.risk,
                                 ["ssh.password"])  # fmt: skip
                items[extra.key] = extra
            else:
                item.blocked = "no_admin_key"
    for item in items.values():
        item.selected = (
            item.blocked is None
            and item.risk in ("high", "medium")
            and item.fix_id not in ("ssh.port", "watch.install")
        )
    node_index = {n.node.uuid: i for i, n in enumerate(data.nodes)}
    return sorted(items.values(), key=lambda i: order_key(i, node_index))


def follow_admin_key(items: list[PlanItem]) -> None:
    """The admin key goes with ssh.key_only: one is marked only with the other."""
    by_target = {}
    for item in items:
        by_target.setdefault(item.target, {})[item.fix_id] = item
    for fixes in by_target.values():
        admin, key_only = fixes.get("access.admin_keys"), fixes.get("ssh.key_only")
        if admin and key_only:
            admin.selected = key_only.selected

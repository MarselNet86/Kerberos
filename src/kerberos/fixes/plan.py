"""Plan of «Исправление» (tech.md §6 S7, §10.1): pure function of the findings.

One plan item is one fix on one target. Items are ordered as §10.1 wants
(per node, in a fixed order; panel fixes after the nodes). By default all
automatic fixes of high and medium risk are marked, except `ssh.port`.
"""

from __future__ import annotations

import random
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
    "cdn.edge_only",
    "watch.install",
)
PANEL_ORDER = (
    "reserve",
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "xhttp.padding",
    "xhttp.uplink_get",
)
# Fixes of a node that live in the panel: no agent access is needed for them.
PANEL_NODE_FIXES = {"xhttp.padding"}
# Fixes that wait for input in S7: a domain with matching DNS, a confirmed list of nets.
NEEDS_INPUT = {"self_steal", "cdn.edge_only"}

# Fixes this version of KERBEROS can apply; the rest stay findings in the report.
IMPLEMENTED = {
    "access.admin_keys",
    "mptcp.guard",
    "fail2ban.sshd",
    "node_api.panel_only",
    "ports.drop",
    "hostkeys.regenerate",
    "ssh.key_only",
    "ssh.port",
    "self_steal",
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "xhttp.padding",
    "xhttp.uplink_get",
    "cdn.edge_only",
    "watch.install",
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


SSH_PORTS = (20000, 32767)  # below the ephemeral range (§10.3)


def choose_port(facts: dict, rng: random.Random) -> int:
    """A free port for SSH: random in 20000-32767, not listened on by anything."""
    busy = {s.get("port") for s in facts.get("listening", [])}
    while True:
        port = rng.randint(*SSH_PORTS)
        if port not in busy:
            return port


def node_params(
    fix_id: str, finding: Finding, facts: dict, panel_ip: str, rng: random.Random
) -> dict:
    if fix_id == "ssh.port":
        return {"port": choose_port(facts, rng)}
    if fix_id == "self_steal":
        return {"domain": None, "dns": "none", "siteSeed": 0}
    if fix_id == "fail2ban.sshd":
        return {"sshPorts": list(facts["ssh"]["ports"]), "panelIp": panel_ip}
    if fix_id == "node_api.panel_only":
        return {"port": facts["nodeApi"]["port"], "panelIp": panel_ip}
    if fix_id == "ports.drop":
        return {"ports": list(finding["evidence"].get("ports", []))}
    return {}


def build_plan(
    findings: list[Finding],
    data: CheckInput,
    admin: Optional[dict],
    panel_ips: dict,
    rng: Optional[random.Random] = None,
) -> list[PlanItem]:
    """`admin`: the choice of §8.5 ({mode, keys}); `panel_ips`: node uuid -> panel address."""
    rng = rng or random.SystemRandom()
    items: dict = {}
    for finding in findings:
        fix_id = finding["fixId"]
        if finding["ok"] or fix_id not in IMPLEMENTED or spec(finding["checkId"]).kind != "fix":
            continue
        kind, _, ref = finding["target"].partition(":")
        if kind != "node" or fix_id in PANEL_NODE_FIXES:
            panel_item(items, finding, data)
            continue
        node = data.node_data(ref)
        if node is None or node.facts is None or node.access != "ok":
            continue
        key = (finding["target"], fix_id)
        item = items.get(key)
        if item is None:
            params = node_params(fix_id, finding, node.facts, panel_ips.get(ref, ""), rng)
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
    used_layouts = site_layouts_in_use(data)
    for item in list(items.values()):
        node = data.node_data(item.node_uuid or "")
        facts = node.facts if node else {}
        if item.fix_id == "self_steal":
            item.blocked = self_steal_blocker(data, node)
            item.params["siteSeed"] = free_site_seed(used_layouts, rng)
        if item.fix_id == "cdn.edge_only":
            item.params = {"paths": edge_paths(data, node), "nets": None}
            if (facts.get("nginx") or {}).get("realip"):
                item.blocked = "realip_enabled"
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
        # Self-steal needs a domain typed in S7, the CDN filter a confirmed list of
        # nets: they get marked once that is done.
        item.selected = (
            item.blocked is None
            and item.risk in ("high", "medium")
            and item.fix_id not in ("ssh.port", "watch.install", *NEEDS_INPUT)
        )
    node_index = {n.node.uuid: i for i, n in enumerate(data.nodes)}
    return sorted(items.values(), key=lambda i: order_key(i, node_index))


def panel_item(items: dict, finding: Finding, data: CheckInput) -> None:
    """Fixes in the panel: subscription settings, one host, one template's hosts."""
    key = (finding["target"], finding["fixId"])
    item = items.get(key)
    if item is None:
        item = PlanItem(finding["fixId"], finding["target"], None, {}, finding["risk"])
        kind, _, ref = finding["target"].partition(":")
        if kind == "node":
            item.params = {"node": ref, "inbounds": []}
        if kind == "host":
            item.params = {"host": ref, "remark": finding["evidence"].get("host", "")}
        if kind == "template":
            hosts, paired = template_hosts(data, ref)
            item.params = {"template": ref, "name": finding["evidence"].get("template", ""),
                           "hosts": hosts, "paired": paired}  # fmt: skip
        items[key] = item
    elif RISK_RANK[finding["risk"]] < RISK_RANK[item.risk]:
        item.risk = finding["risk"]
    if finding["checkId"] not in item.checks:
        item.checks.append(finding["checkId"])
    inbound = finding["evidence"].get("inbound")
    if "inbounds" in item.params and inbound and inbound not in item.params["inbounds"]:
        item.params["inbounds"].append(inbound)


def edge_paths(data: CheckInput, node) -> list[str]:
    """Paths of the tunnel behind the CDN on this origin (§10.6)."""
    from kerberos.checks.rules import cdn_xhttp_hosts, xhttp_path

    if node is None:
        return []
    return list(dict.fromkeys(xhttp_path(inbound, host)
                              for inbound, host in cdn_xhttp_hosts(data, node)))  # fmt: skip


def template_hosts(data: CheckInput, template_uuid: str) -> tuple[list, list]:
    """Enabled hosts of the chosen nodes on a template; those whose node has a reserve."""
    from kerberos.checks.rules import reserves_of

    hosts, paired = [], []
    for node in data.nodes:
        has_reserve = bool(reserves_of(data, node))
        for host in data.snapshot.node_hosts(node.node):
            if host.is_disabled or host.template_uuid != template_uuid or host.uuid in hosts:
                continue
            hosts.append(host.uuid)
            if has_reserve:
                paired.append(host.uuid)
    return hosts, paired


def reserve_item(main: PlanItem, spare: PlanItem) -> PlanItem:
    """S7: the pair of a main and its reserve, applied after both got their domains."""
    return PlanItem("reserve", main.target, main.node_uuid, {"reserve": spare.node_uuid},
                    "medium", ["reserve.missing"], selected=True)  # fmt: skip


def site_layouts_in_use(data: CheckInput) -> set:
    return {s.get("template") for n in data.nodes for s in n.sites.values() if s}


def free_site_seed(used: set, rng: random.Random) -> int:
    """A random stub site whose markup no other node shows (site.same_template).

    The site is built from the seed alone, so its structure is known before
    the domain is typed in S7.
    """
    from kerberos.agent import SITE_SEEDS, site_html, template_hash

    seed = rng.randrange(SITE_SEEDS)
    for _ in range(64):
        layout = template_hash(site_html(seed, "example.com"))
        if layout not in used:
            used.add(layout)
            return seed
        seed = rng.randrange(SITE_SEEDS)
    return seed


def self_steal_blocker(data: CheckInput, node) -> Optional[str]:
    """§10.4 conditions; the reason text keys are plan.blocked.<reason>."""
    if node is None or not node.node.is_connected:
        return "node_offline"
    profile = data.snapshot.node_profile(node.node)
    if profile is None:
        return "no_profile"
    if len(profile.node_uuids) > 1:
        return "shared_profile"
    listening = (node.facts or {}).get("listening", [])
    if any(s["port"] == 80 and s["proto"] == "tcp" and s.get("process") != "nginx"
           for s in listening):  # fmt: skip
        return "port80_busy"
    on443 = [s for s in listening if s["port"] == 443 and s["proto"] == "tcp"]
    if on443 and not any(s.get("process") in ("xray", "rw-core") for s in on443):
        return "port443"
    return None


def follow_admin_key(items: list[PlanItem]) -> None:
    """The admin key goes with ssh.key_only: one is marked only with the other."""
    by_target = {}
    for item in items:
        by_target.setdefault(item.target, {})[item.fix_id] = item
    for fixes in by_target.values():
        admin, key_only = fixes.get("access.admin_keys"), fixes.get("ssh.key_only")
        if admin and key_only:
            admin.selected = key_only.selected

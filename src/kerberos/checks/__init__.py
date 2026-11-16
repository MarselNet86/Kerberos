"""Checks of tech.md §10.2: pure functions from collected data to findings.

`collect.py` gathers everything over the ports (agent, DNS, TLS, ping,
whois) into a `CheckInput`; the rules here never do I/O. A check that has
no data for a target (no agent access, whois declined) gives no finding
for it, so it does not count in the score (§12.2).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Optional

from kerberos.fixes.model import Finding
from kerberos.panel.model import Host, Node, PanelSnapshot
from kerberos.probe import HttpResult, TlsResult
from kerberos.whois import AsInfo


@dataclass
class NodeData:
    node: Node
    access: str = "none"
    ipv4: Optional[str] = None
    facts: Optional[dict] = None
    watch: Optional[dict] = None
    sites: dict = field(default_factory=dict)  # domain -> site-check answer


@dataclass
class CheckInput:
    snapshot: PanelSnapshot
    nodes: list[NodeData]
    dns: dict = field(default_factory=dict)  # name -> [addresses]
    tls: dict = field(default_factory=dict)  # node ipv4 -> TlsResult without SNI
    pages: dict = field(default_factory=dict)  # (ip, port, host, path) -> HttpResult
    pings: dict = field(default_factory=dict)  # ip -> bool
    asn: Optional[dict] = None  # ip -> AsInfo; None: whois not allowed
    panel_ssh: Optional[dict] = None  # `sshd -T` of the panel server
    panel_page: Optional[HttpResult] = None

    # -- helpers shared by the rules --------------------------------------
    def node_data(self, uuid: str) -> Optional[NodeData]:
        return next((n for n in self.nodes if n.node.uuid == uuid), None)

    def resolves_to(self, name: str, ips: list[str]) -> bool:
        return bool(set(self.dns.get(name.lower().rstrip("."), [])) & set(ips))

    def node_ips(self, data: NodeData) -> list[str]:
        ips = []
        if data.ipv4:
            ips.append(data.ipv4)
        if data.facts:
            ips += [ip for ip in data.facts.get("ipv4", []) + data.facts.get("ipv6", [])
                    if ip not in ips]  # fmt: skip
        return ips

    def own_domains(self, data: NodeData) -> list[str]:
        """Domains of the node: names the fleet uses that resolve to its addresses."""
        ips = self.node_ips(data)
        names: list[str] = []
        candidates = [data.node.address]
        for host in self.snapshot.node_hosts(data.node):
            candidates += [host.address, host.sni]
        for inbound in reality_inbounds(self.snapshot, data.node):
            candidates += list(reality_settings(inbound).get("serverNames") or [])
        if data.facts:
            candidates += [c["domain"] for c in (data.facts.get("certbot") or {}).get("certs", [])]
            for site in (data.facts.get("nginx") or {}).get("sites", []):
                candidates += site.get("serverNames", [])
        for name in candidates:
            if not name or is_ip(name) or "." not in name:
                continue
            name = name.lower().rstrip(".")
            if name not in names and self.resolves_to(name, ips):
                names.append(name)
        return names


@dataclass
class CheckSpec:
    check_id: str
    topic: str
    risk: str
    fix_id: Optional[str]
    kind: str  # fix | manual | explain | plan
    rule: Callable[[CheckInput], list[Finding]]
    panels: tuple = ("remnawave", "3x-ui")


REGISTRY: list[CheckSpec] = []


def check(check_id: str, topic: str, risk: str, fix_id: Optional[str], kind: str,
          panels: tuple = ("remnawave", "3x-ui")):  # fmt: skip
    """Register a rule; `panels`: the panels it means something for (§7.6)."""

    def register(rule: Callable[[CheckInput], list[Finding]]):
        REGISTRY.append(CheckSpec(check_id, topic, risk, fix_id, kind, rule, panels))
        return rule

    return register


def spec(check_id: str) -> CheckSpec:
    for item in REGISTRY:
        if item.check_id == check_id:
            return item
    raise KeyError(check_id)


def finding(check_id: str, target: str, ok: bool, evidence: Optional[dict] = None,
            fix_id: Optional[str] = "default") -> Finding:  # fmt: skip
    item = spec(check_id)
    return {
        "checkId": check_id,
        "topic": item.topic,  # type: ignore[typeddict-item]
        "risk": item.risk,  # type: ignore[typeddict-item]
        "target": target,
        "ok": ok,
        "evidence": evidence or {},
        "fixId": item.fix_id if fix_id == "default" else fix_id,
    }


def run_checks(data: CheckInput) -> list[Finding]:
    from kerberos.checks import rules  # noqa: F401 - registers the rules

    findings: list[Finding] = []
    for item in REGISTRY:
        if data.snapshot.kind in item.panels:
            findings += item.rule(data)
    return findings


# -- small helpers -------------------------------------------------------
def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def node_target(node: Node) -> str:
    return f"node:{node.uuid}"


def host_target(host: Host) -> str:
    return f"host:{host.uuid}"


def inbound_configs(snapshot: PanelSnapshot, node: Node) -> list[dict]:
    profile = snapshot.node_profile(node)
    if profile is None:
        return []
    tags = {i.tag for i in snapshot.node_inbounds(node)}
    return [
        i for i in profile.config.get("inbounds") or []
        if isinstance(i, dict) and (not tags or i.get("tag") in tags)
    ]  # fmt: skip


def stream(inbound: dict) -> dict:
    value = inbound.get("streamSettings")
    return value if isinstance(value, dict) else {}


def reality_settings(inbound: dict) -> dict:
    value = stream(inbound).get("realitySettings")
    return value if isinstance(value, dict) else {}


def reality_dest(settings: dict) -> str:
    """Newer Xray and 3x-ui call `dest` `target`; both mean the same."""
    return str(settings.get("target") or settings.get("dest") or "")


def reality_inbounds(snapshot: PanelSnapshot, node: Node) -> list[dict]:
    return [
        i for i in inbound_configs(snapshot, node)
        if i.get("protocol") == "vless" and stream(i).get("security") == "reality"
    ]  # fmt: skip


def hysteria_inbounds(snapshot: PanelSnapshot, node: Node) -> list[dict]:
    return [
        i for i in inbound_configs(snapshot, node) if i.get("protocol") in ("hysteria", "hysteria2")
    ]


def xhttp_inbounds(snapshot: PanelSnapshot, node: Node) -> list[dict]:
    return [i for i in inbound_configs(snapshot, node) if stream(i).get("network") == "xhttp"]


__all__ = [
    "AsInfo",
    "CheckInput",
    "NodeData",
    "TlsResult",
    "finding",
    "run_checks",
]

"""Gathering what the checks need (tech.md §6 S5): read-only.

Agent calls go to up to four nodes at once; nothing here changes a node or
the panel. Every external call goes through a port: NodeTransport, Prober,
Whois, Host.
"""

from __future__ import annotations

import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from kerberos.checks import CheckInput, NodeData, hysteria_inbounds, is_ip, reality_inbounds
from kerberos.checks.rules import cdn_xhttp_hosts, tls_listen_ports, xhttp_path
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, Target, TransportError
from kerberos.panel.model import PanelSnapshot

STEPS = ("facts", "watch", "site", "outside")
PARALLEL = 4


@dataclass
class Progress:
    """What S5 draws: one state per node and step."""

    cells: dict = field(default_factory=dict)  # (uuid, step) -> pending|running|ok|failed|skipped
    done: bool = False
    error: Optional[BaseException] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def set(self, uuid: str, step: str, state: str) -> None:
        with self.lock:
            self.cells[(uuid, step)] = state


def first_v4(addresses: list[str]) -> Optional[str]:
    for address in addresses:
        try:
            if ipaddress.ip_address(address).version == 4:
                return address
        except ValueError:
            continue
    return None


class Collector:
    def __init__(self, env: Any, snapshot: PanelSnapshot, selected: list[str], access: dict,
                 whois_allowed: bool, progress: Progress) -> None:  # fmt: skip
        self.env = env
        self.snapshot = snapshot
        self.whois_allowed = whois_allowed
        self.progress = progress
        state = env.state
        self.records = state.nodes() if state is not None else {}
        self.nodes = [
            NodeData(node, access=access.get(node.uuid, "none"))
            for node in snapshot.nodes
            if node.uuid in selected
        ]
        self.dns: dict = {}

    # -- helpers -----------------------------------------------------------
    def resolve(self, name: str) -> list[str]:
        key = name.lower().rstrip(".")
        if key not in self.dns:
            self.dns[key] = [name] if is_ip(name) else self.env.prober.resolve(key)
        return self.dns[key]

    def target(self, data: NodeData) -> Target:
        record = self.records.get(data.node.uuid)
        if record is not None:
            return record.target(data.node.address)
        return Target(data.node.uuid, data.node.name, data.node.address, 22)

    def agent(self, data: NodeData, command: str, payload: Optional[dict] = None) -> Optional[dict]:
        try:
            return self.env.transport.agent(self.target(data), command, payload)
        except TransportError as exc:
            data.access = "denied" if exc.kind == "hostkey_changed" else "none"
        except NodeAgentError:
            pass
        return None

    # -- steps ---------------------------------------------------------------
    def node_agent(self, data: NodeData) -> None:
        uuid = data.node.uuid
        if data.access != "ok":
            for step in ("facts", "watch", "site"):
                self.progress.set(uuid, step, "skipped")
            return
        self.progress.set(uuid, "facts", "running")
        try:
            data.facts = schema.facts(self.agent(data, "facts"))
            self.progress.set(uuid, "facts", "ok")
        except schema.BadAnswer:
            data.facts = None
            self.progress.set(uuid, "facts", "failed")
        self.progress.set(uuid, "watch", "running" if data.access == "ok" else "skipped")
        if data.access == "ok":
            try:
                data.watch = schema.watch(self.agent(data, "watch"))
                self.progress.set(uuid, "watch", "ok")
            except schema.BadAnswer:
                self.progress.set(uuid, "watch", "failed")

    def candidate_names(self) -> list[str]:
        names = [self.snapshot.panel_domain or ""]
        for data in self.nodes:
            names.append(data.node.address)
            for host in self.snapshot.node_hosts(data.node):
                names += [host.address, host.sni]
            for inbound in reality_inbounds(self.snapshot, data.node):
                settings = (inbound.get("streamSettings") or {}).get("realitySettings") or {}
                names += [n for n in settings.get("serverNames") or [] if isinstance(n, str)]
            for inbound in hysteria_inbounds(self.snapshot, data.node):
                hy = (inbound.get("streamSettings") or {}).get("hysteriaSettings") or {}
                names.append(urlsplit(str((hy.get("masquerade") or {}).get("url") or "")).hostname
                             or "")  # fmt: skip
            if data.facts:
                names += [c["domain"] for c in data.facts["certbot"].get("certs", [])]
                for site in data.facts["nginx"].get("sites", []):
                    names += site.get("serverNames", [])
        return [n for n in dict.fromkeys(names) if n and "." in n and not is_ip(n)]

    def sites(self, data: CheckInput, item: NodeData) -> None:
        if item.access != "ok" or item.facts is None:
            self.progress.set(item.node.uuid, "site", "skipped")
            return
        self.progress.set(item.node.uuid, "site", "running")
        for domain in data.own_domains(item)[:3]:
            try:
                item.sites[domain] = schema.site(self.agent(item, "site-check", {"domain": domain}))
            except schema.BadAnswer:
                continue
        self.progress.set(item.node.uuid, "site", "ok")

    def outside(self, data: CheckInput, item: NodeData) -> None:
        prober = self.env.prober
        uuid = item.node.uuid
        if not item.ipv4:
            self.progress.set(uuid, "outside", "skipped")
            return
        self.progress.set(uuid, "outside", "running")
        if reality_inbounds(self.snapshot, item.node):
            tls = prober.tls_names(item.ipv4, 443, None)
            data.tls[item.ipv4] = tls
            for name in tls.names:
                if self.resolve_into(data, name) and data.resolves_to(name, data.node_ips(item)):
                    data.pages[(item.ipv4, 443, name, "/")] = prober.http(item.ipv4, 443, name, "/")
                    break
        if item.facts:
            for inbound, host in cdn_xhttp_hosts(data, item):
                name = host.sni or host.address
                for port in tls_listen_ports(item.facts):
                    for path in (xhttp_path(inbound, host), "/cdn-check"):
                        data.pages[(item.ipv4, port, name, path)] = prober.http(
                            item.ipv4, port, name, path
                        )
        data.pings[item.ipv4] = prober.ping(item.ipv4)
        self.progress.set(uuid, "outside", "ok")

    def resolve_into(self, data: CheckInput, name: str) -> list[str]:
        addresses = self.resolve(name)
        data.dns[name.lower().rstrip(".")] = addresses
        return addresses

    def run(self) -> CheckInput:
        for item in self.nodes:
            item.ipv4 = first_v4(self.resolve(item.node.address))
            for step in STEPS:
                self.progress.set(item.node.uuid, step, "pending")
        with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
            list(pool.map(self.node_agent, self.nodes))
        for name in self.candidate_names():
            self.resolve(name)
        data = CheckInput(snapshot=self.snapshot, nodes=self.nodes, dns=dict(self.dns))
        for item in self.nodes:
            self.sites(data, item)
            self.outside(data, item)
        if self.whois_allowed:
            addresses = [n.ipv4 for n in self.nodes if n.ipv4]
            data.asn = self.env.whois.lookup(addresses) if addresses else {}
        host = self.env.host
        if host is not None:
            from kerberos.agent import parse_sshd_t

            result = host.run(["sshd", "-T"], timeout=20)
            data.panel_ssh = parse_sshd_t(result.stdout) if result.ok else None
        domain = self.snapshot.panel_domain
        if domain:
            address = first_v4(self.resolve_into(data, domain))
            if address:
                data.panel_page = self.env.prober.http(address, 443, domain, "/")
            if self.snapshot.kind != "3x-ui":
                from kerberos.fixes.portal import detect_caddy

                data.panel_proxy = detect_caddy(host, domain)  # read only
        masker = getattr(self.env, "masker", None)
        if masker is not None:
            # Names only the nodes know (their sites, certificates) are masked like the panel's.
            masker.register(*node_names(data))
        return data


def node_names(data: CheckInput) -> list[str]:
    """Domains learnt from the nodes: nginx server names, certbot and TLS certificate names."""
    names: list[str] = []
    for item in data.nodes:
        facts = item.facts or {}
        for site in (facts.get("nginx") or {}).get("sites", []):
            names += [n for n in site.get("serverNames", []) if isinstance(n, str)]
        names += [c.get("domain") for c in (facts.get("certbot") or {}).get("certs", [])]
    for tls in data.tls.values():
        names += list(tls.names)
    return [n for n in dict.fromkeys(names) if isinstance(n, str) and n and not is_ip(n)]


def collect_in_background(env: Any, snapshot: PanelSnapshot, selected: list[str], access: dict,
                          whois_allowed: bool) -> tuple[Progress, dict]:  # fmt: skip
    """Start collecting in a thread; the result lands in the returned dict."""
    progress = Progress()
    box: dict = {}
    collector = Collector(env, snapshot, selected, access, whois_allowed, progress)

    def work() -> None:
        try:
            box["input"] = collector.run()
        except BaseException as exc:  # noqa: BLE001 - reported to the screen thread
            progress.error = exc
        finally:
            progress.done = True

    thread = threading.Thread(target=work, name="kerberos-collect", daemon=True)
    box["thread"] = thread
    for item in collector.nodes:
        for step in STEPS:
            progress.set(item.node.uuid, step, "pending")
    thread.start()
    return progress, box

"""What the demo nodes report through the agent, and what the outside sees.

Every check of tech.md §10.2 finds something on this fleet: nl-1 and nl-2
come from one hoster image, de-1 and fi-1 got their own domains by hand
with one and the same stub site, fi-1 is an origin behind a CDN.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Optional

from kerberos.nodes.fake import FakeNode
from kerberos.nodes.fake_fixes import give_fixes
from kerberos.nodes.keys import demo_blob, fingerprint
from kerberos.probe import FakeProber, HttpResult, TlsResult
from kerberos.whois import AsInfo, FakeWhois

SITE_TEMPLATE = "5f1c2a9e0b7d3c48"


def host_key(seed: str) -> dict:
    return {"type": "ED25519", "fingerprint": fingerprint(demo_blob(seed))}


def listening(*extra: tuple) -> list[dict]:
    base = [
        ("tcp", "0.0.0.0", 22, "sshd"),
        ("tcp", "0.0.0.0", 443, "xray"),
        ("udp", "0.0.0.0", 443, "xray"),
        ("tcp", "0.0.0.0", 2222, "node"),
        ("tcp", "127.0.0.53", 53, "systemd-resolve"),
    ]
    rows = base + list(extra)
    return [
        {"proto": p, "address": a, "port": n, "process": proc, "docker": False,
         "firewalled": False}
        for p, a, n, proc in rows
    ]  # fmt: skip


def base_facts(address: str) -> dict:
    return {
        "protocol": 1,
        "agent": "0.3.0",
        "os": {"id": "ubuntu", "version": "24.04", "kernel": "6.8.0-49-generic"},
        "ipv4": [address],
        "ipv6": [],
        "python": "3.12.3",
        "listening": listening(),
        "ssh": {
            "ports": [22],
            "socketActivated": True,
            "passwordAuthentication": False,
            "kbdInteractive": False,
            "permitRootLogin": "prohibit-password",
            "adminKeys": 1,
        },  # fmt: skip
        "fail2ban": {"installed": False, "sshdJail": False, "jailPorts": []},
        "mptcp": {"enabled": True, "ipOptionsDrop": False, "sockets": 0},
        "nodeApi": {"port": 2222, "panelOnly": False, "otherPeers": 0, "panelPeer": True},
        "nftTables": ["ip nat", "ip filter"],
        "hostKeys": [host_key(address)],
        "firewall": {"ufw": "inactive"},
        "remnanode": {
            "present": True,
            "network": "host",
            "xrayVersion": "25.10.15",
            "nodePort": 2222,
            "letsencryptMounted": False,
        },  # fmt: skip
        "nginx": {"installed": False, "realip": False, "sites": []},
        "certbot": {"installed": False, "certs": []},
        "watch": {"installed": False},
    }


def facts_for(name: str, address: str) -> dict:
    facts = base_facts(address)
    if name in ("nl-1", "nl-2"):
        facts["hostKeys"] = [host_key("hoster-image")]
    if name == "nl-1":
        facts["ssh"].update(passwordAuthentication=True, permitRootLogin="yes", adminKeys=0)
        facts["listening"] = listening(("tcp", "0.0.0.0", 8080, "python3"))
        facts["nodeApi"]["otherPeers"] = 1
        facts["mptcp"]["sockets"] = 2
    if name == "nl-2":
        facts["fail2ban"] = {"installed": True, "sshdJail": True, "jailPorts": [22]}
        facts["watch"] = {"installed": True}
    if name == "de-1":
        facts["ssh"].update(passwordAuthentication=True)
        facts["fail2ban"] = {"installed": True, "sshdJail": True, "jailPorts": [22]}
        facts["mptcp"]["enabled"] = False
        facts["nodeApi"]["panelOnly"] = True
        facts["firewall"]["ufw"] = "active"
        facts["nftTables"].append("inet kerberos_node_api")
        facts["nginx"] = {"installed": True, "realip": False, "sites": [
            {"file": "/etc/nginx/sites-enabled/site", "serverNames": ["de-1.example.com"],
             "listen": ["127.0.0.1:8445 ssl"]},
        ]}  # fmt: skip
        facts["certbot"] = {"installed": True, "certs": [
            {"domain": "de-1.example.com", "notAfter": "2027-02-01T00:00:00Z"}]}  # fmt: skip
    if name == "fi-1":
        facts["nginx"] = {"installed": True, "realip": False, "sites": [
            {"file": "/etc/nginx/sites-enabled/cdn", "serverNames": ["cdn.example.com"],
             "listen": ["8443 ssl"]},
            {"file": "/etc/nginx/sites-enabled/site", "serverNames": ["fi-1.example.com"],
             "listen": ["127.0.0.1:8445 ssl"]},
        ]}  # fmt: skip
        facts["certbot"] = {"installed": True, "certs": [
            {"domain": "fi-1.example.com", "notAfter": "2027-01-20T00:00:00Z"}]}  # fmt: skip
        facts["watch"] = {"installed": True}
        facts["listening"] = listening(("tcp", "0.0.0.0", 8443, "nginx"))
    return facts


def watch_for(name: str) -> dict:
    v4 = {"connections": 120, "clientIps": 40, "cut": 1, "cutNets": [
        {"net": "198.51.0.0/16", "count": 1}]}  # fmt: skip
    xray = {"accepted5m": 820, "users5m": 31, "ruShare": 0.004}
    if name == "nl-2":
        v4 = {"connections": 30, "clientIps": 12, "cut": 9, "cutNets": [
            {"net": "198.51.0.0/16", "count": 6}, {"net": "203.0.0.0/16", "count": 3}]}  # fmt: skip
        xray = {"accepted5m": 15, "users5m": 0, "ruShare": 0.0}
    if name == "fi-1":
        xray = {"accepted5m": 400, "users5m": 14, "ruShare": 0.04}
    empty = {"connections": 0, "clientIps": 0, "cut": 0, "cutNets": []}
    return {"protocol": 1, "at": "2026-11-16T12:00:00Z", "port": 443, "v4": v4, "v6": empty,
            "xray": xray}  # fmt: skip


def give_agent(node: FakeNode) -> None:
    """Agent answers of a demo node; fixes in later tasks change node.state."""
    node.state.setdefault("facts", facts_for(node.name, node.address))
    node.state.setdefault("watch", watch_for(node.name))
    node.state.setdefault("sites", {
        "de-1.example.com": {"template": SITE_TEMPLATE, "altSvc": None, "status": 200},
        "fi-1.example.com": {"template": SITE_TEMPLATE, "altSvc": None, "status": 200},
    })  # fmt: skip
    node.state.setdefault("edges", [{"net": "192.0.2.0/24", "count": 5310}])
    node.state.setdefault(
        "site", {"de-1": "de-1.example.com", "fi-1": "fi-1.example.com"}.get(node.name)
    )
    node.handlers["facts"] = lambda n, _a, _d: copy.deepcopy(n.state["facts"])
    node.handlers["watch"] = lambda n, _a, _d: copy.deepcopy(n.state["watch"])
    node.handlers["site-check"] = lambda n, _a, d: n.state["sites"].get(
        d["domain"], {"template": None, "altSvc": None, "status": None}
    )
    node.handlers["edge-sources"] = lambda n, _a, _d: {"nets": n.state["edges"]}
    give_fixes(node)


def auth_methods_of(nodes: list[FakeNode], aliases: Optional[dict] = None):
    """What each demo node's SSH offers a stranger, from its current facts."""
    by_address = {n.address: n for n in nodes}
    aliases = aliases or {}

    def methods(ip: str, port: int):
        node = by_address.get(aliases.get(ip, ip))
        if node is None:
            return None
        ssh = node.state["facts"]["ssh"]
        offered = ["publickey"]
        if ssh.get("passwordAuthentication"):
            offered.append("password")
        if ssh.get("kbdInteractive"):
            offered.append("keyboard-interactive")
        return offered

    return methods


DNS = {
    "www.example.net": ["198.51.100.200"],
    "cdn.example.com": ["192.0.2.200"],
    "panel.example.com": ["198.51.100.5"],
    "nl-1.example.com": ["203.0.113.10"],
    "nl-2.example.com": ["203.0.113.11"],
    "de-1.example.com": ["198.51.100.20"],
    "fi-1.example.com": ["198.51.100.77"],
    "kz-1.example.com": ["192.0.2.60"],
}


CDN_EDGES = {"192.0.2.200": "198.51.100.77"}  # an edge of the CDN -> the origin behind it
TUNNEL_PATH = "/api/stream"
NOT_FOUND = HttpResult(404, {"content-type": "text/html"},
                       "<html><head><title>404 Not Found</title></head></html>")  # fmt: skip
PANEL_ADDRESS = "198.51.100.5"


class DemoProber(FakeProber):
    """The outside view of the demo fleet follows the panel and the nodes.

    TLS without SNI reaches Reality's dest: the own site when dest is the local
    stub of the node's domain, the foreign site otherwise.
    """

    def __init__(self, panel=None, nodes=None, xui=None, aliases=None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.panel = panel
        self.by_address = {n.address: n for n in nodes or []}
        self.xui = xui  # the 3x-ui server of the demo (§7.6)
        self.aliases = dict(aliases or {})  # public address -> address of the fake node

    def node_at(self, ip: str):
        return self.by_address.get(self.aliases.get(ip, ip))

    def _reality(self, ip: str) -> dict:
        if ip in self.aliases and self.xui is not None:
            for item in self.xui.inbounds:
                stream = self.xui.stream(item["id"])
                if item["enable"] and stream.get("security") == "reality":
                    return stream.get("realitySettings") or {}
            return {}
        if self.panel is None:
            return {}
        node = next((n for n in self.panel.nodes if n["address"] == ip), None)
        if node is None:
            return {}
        ref = (node.get("configProfile") or {}).get("activeConfigProfileUuid")
        profile = next((p for p in self.panel.profiles if p["uuid"] == ref), None)
        for inbound in (profile or {}).get("config", {}).get("inbounds", []):
            stream = inbound.get("streamSettings") or {}
            if stream.get("security") == "reality":
                return stream.get("realitySettings") or {}
        return {}

    def _own_site(self, ip: str) -> str:
        node = self.node_at(ip)
        reality = self._reality(ip)
        site = node.state.get("site") if node else None
        dest = reality.get("target") or reality.get("dest")
        if site and dest == "127.0.0.1:8445" and site in reality.get("serverNames", []):
            return site
        return ""

    def tls_names(self, ip: str, port: int = 443, sni=None) -> TlsResult:
        self.calls.append(("tls", ip, port, sni))
        if self.node_at(ip) is not None and port == 443:
            site = self._own_site(ip)
            return (
                TlsResult(True, [site])
                if site
                else TlsResult(True, ["www.example.net", "example.net"])
            )
        return super().tls_names(ip, port, sni)

    def _origin(self, node: FakeNode, source: str, path: str) -> HttpResult:
        """fi-1 behind the CDN: Xray answers on the tunnel path unless cdn.edge_only cuts it."""
        rule = node.state.get("edge_filter")
        allowed = rule is None or any(
            ipaddress.ip_address(source) in ipaddress.ip_network(net) for net in rule["nets"]
        )
        if path == TUNNEL_PATH and allowed:
            return HttpResult(400, {}, "")
        if path == "/cdn-check" and allowed:
            return HttpResult(204, {}, "")
        return NOT_FOUND

    def http(self, ip: str, port: int, host: str, path: str = "/", *, tls: bool = True,
             headers=None):  # fmt: skip
        if ip in CDN_EDGES and port == 443 and CDN_EDGES[ip] in self.by_address:
            self.calls.append(("http", ip, port, host, path))
            return self._origin(self.by_address[CDN_EDGES[ip]], ip, path)
        if ip in self.by_address and port == 8443:
            self.calls.append(("http", ip, port, host, path))
            return self._origin(self.by_address[ip], PANEL_ADDRESS, path)
        if self.node_at(ip) is not None and port == 443 and path == "/":
            self.calls.append(("http", ip, port, host, path))
            ok = self._own_site(ip) == host
            return (
                HttpResult(200, {"content-type": "text/html"}, "<html></html>")
                if ok
                else (HttpResult(None))
            )
        return super().http(ip, port, host, path, tls=tls, headers=headers)


def build_prober(panel=None, nodes=None) -> FakeProber:
    foreign = TlsResult(True, ["www.example.net", "example.net"])
    prober = DemoProber(panel, nodes, dns=copy.deepcopy(DNS))
    prober.tls = {
        "203.0.113.10": foreign,
        "203.0.113.11": foreign,
        "192.0.2.60": foreign,
        "198.51.100.20": TlsResult(True, ["de-1.example.com"]),
        "198.51.100.77": TlsResult(True, ["fi-1.example.com"]),
    }
    site = HttpResult(200, {"content-type": "text/html"}, "<html><body>Studio</body></html>")
    prober.pages = {
        ("198.51.100.20", 443, "de-1.example.com", "/"): site,
        ("198.51.100.77", 443, "fi-1.example.com", "/"): site,
        ("198.51.100.5", 443, "panel.example.com", "/"): HttpResult(
            200, {}, "<html><head><title>Remnawave</title></head></html>"
        ),
    }
    prober.pings = {ip: True for ip in ("203.0.113.10", "203.0.113.11", "198.51.100.20",
                                        "198.51.100.77", "192.0.2.60")}  # fmt: skip
    return prober


def build_whois() -> FakeWhois:
    return FakeWhois({
        "203.0.113.10": AsInfo("64500", "EXAMPLE-NL-HOSTING", "NL"),
        "203.0.113.11": AsInfo("64500", "EXAMPLE-NL-HOSTING", "NL"),
        "198.51.100.20": AsInfo("64501", "EXAMPLE-DE-CLOUD", "DE"),
        "198.51.100.77": AsInfo("64502", "EXAMPLE-FI-NET", "FI"),
        "192.0.2.60": AsInfo("64503", "EXAMPLE-KZ-TELECOM", "KZ"),
    })  # fmt: skip

"""A demo 3x-ui server (tech.md §7.6): the panel and the node on one machine.

Only documentation addresses. The server runs Reality with a foreign SNI,
lets SSH in by password, keeps MPTCP on and shows the 3x-ui panel to the
world on its default port without a secret path or TLS: every 3x-ui check
finds something, and «Исправление» has work to do.
"""

from __future__ import annotations

import json

from kerberos.demo.nodes import auth_methods_of, base_facts, give_agent, listening
from kerberos.host import CommandResult
from kerberos.nodes.fake import FakeNode
from kerberos.nodes.keys import PublicKey, demo_blob
from kerberos.panel.discover import XUI_BIN, XUI_DB
from kerberos.panel.xui_fake import FakeXui, raw_inbound

XUI_IP = "203.0.113.50"
XUI_NAME = "vpn-1"
XUI_VERSION = "3.11.0"
XUI_DOMAIN = "vpn.example.com"  # free for self-steal in the demo: A points to XUI_IP
FOREIGN_SNI = "www.example.net"
SETTINGS = {
    "webListen": "",
    "webPort": "2053",
    "webBasePath": "/",
    "webCertFile": "",
    "webDomain": "",
    "subEnable": "true",
    "subListen": "",
    "subPort": "2096",
    "subPath": "/sub/",
    "twoFactorEnable": "false",
}


def reality_stream() -> dict:
    return {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "xver": 0,
            "target": f"{FOREIGN_SNI}:443",
            "serverNames": [FOREIGN_SNI],
            "privateKey": "DEMO_KEY_XUI",
            "shortIds": ["", "a1b2c3d4"],
            "settings": {
                "publicKey": "DEMO_PUBLIC_XUI",
                "fingerprint": "chrome",
                "serverName": "",
                "spiderX": "/",
            },  # fmt: skip
        },
        "tcpSettings": {"header": {"type": "none"}},
    }


def build_xui() -> FakeXui:
    panel = FakeXui(version=3, accept_any_login=True)
    clients = [{"id": f"00000000-0000-4000-8000-00000000000{i}", "email": f"demo-user-{i}",
                "flow": "xtls-rprx-vision", "enable": True} for i in (1, 2, 3)]  # fmt: skip
    panel.inbounds = [
        raw_inbound(1, 443, "vless", reality_stream(), remark="Reality", clients=clients),
        raw_inbound(
            2,
            8880,
            "vless",
            {"network": "tcp", "security": "none"},
            remark="old test",
            enable=False,
        ),  # fmt: skip
    ]
    panel.online_emails = ["demo-user-1", "demo-user-2"]
    return panel


def xui_node() -> FakeNode:
    node = FakeNode(XUI_NAME, "127.0.0.1", PublicKey("ssh-ed25519", demo_blob("xui-1")),
                    panel_ip="127.0.0.1")  # fmt: skip
    facts = base_facts(XUI_IP)
    facts["ssh"].update(passwordAuthentication=True, permitRootLogin="yes", adminKeys=1,
                        socketActivated=False)  # fmt: skip
    facts["listening"] = listening(
        ("tcp", "0.0.0.0", 2053, "x-ui"), ("tcp", "0.0.0.0", 2096, "x-ui"),
        ("tcp", "0.0.0.0", 3306, "mysqld"), ("tcp", "127.0.0.1", 62789, "xray"),
    )  # fmt: skip
    facts["listening"] = [s for s in facts["listening"] if s["port"] != 2222]
    facts["nodeApi"] = {"port": None, "panelOnly": False, "otherPeers": 0, "panelPeer": False}
    facts["remnanode"] = {"present": False, "network": None, "xrayVersion": None,
                          "nodePort": None, "letsencryptMounted": True}  # fmt: skip
    # The installer of 3x-ui issues the panel a 6-day certificate on the IP through
    # acme.sh --standalone on :80: self-steal moves its renewal to nginx (§10.4, K16).
    facts["acme"] = [{"tool": "acme.sh", "name": XUI_IP, "names": [XUI_IP],
                      "notAfter": "2026-11-22T12:00:00Z"}]  # fmt: skip
    node.state["facts"] = facts
    node.state["sites"] = {}
    node.state["edges"] = []
    node.state["site"] = None
    give_agent(node)
    return node


def ip_addr() -> str:
    return json.dumps([
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": XUI_IP, "scope": "global"}]},
    ])  # fmt: skip


XUI_MAIN_PID = "4242"


def attach_xui_cli(host, panel) -> None:
    """`x-ui setting -port -webBasePath` writes the settings; SIGHUP to the main process
    makes the web server serve them, as the real 3x-ui does (§10.10)."""
    from kerberos.panel.discover import base_path

    def setting(argv, _stdin):
        args = list(argv[argv.index("setting") + 1 :])
        table = host.databases[XUI_DB]
        for flag, key in (("-port", "webPort"), ("-webBasePath", "webBasePath")):
            if flag in args:
                table[key] = args[args.index(flag) + 1]
        return CommandResult(0, "settings updated\n")

    def hup(_argv, _stdin):
        table = host.databases[XUI_DB]
        panel.base = base_path(table.get("webBasePath", "/"))
        panel.port = int(table.get("webPort") or 2053)
        return CommandResult(0)

    host.on([XUI_BIN, "setting"], setting)
    host.on(["systemctl", "show", "-p", "MainPID", "--value", "x-ui"],
            CommandResult(0, XUI_MAIN_PID + "\n"))  # fmt: skip
    host.on(["kill", "-HUP", XUI_MAIN_PID], hup)
    host.on(["ufw"], CommandResult(0))


def attach_xui(env) -> None:
    """Add the 3x-ui server to a demo environment: its panel, its node, its files."""
    node = xui_node()
    env.xui_transport = build_xui()
    env.transport.nodes[node.address] = node
    host = env.host
    host.databases[XUI_DB] = dict(SETTINGS)
    host.on([XUI_BIN, "-v"], CommandResult(0, f"{XUI_VERSION}\n"))
    attach_xui_cli(host, env.xui_transport)
    host.on(["ip", "-j", "addr", "show"], CommandResult(0, ip_addr()))
    host.on(["python3", "-"], lambda _argv, stdin: env.transport.local_bootstrap(stdin))
    host.files["/etc/ssh/ssh_host_ed25519_key.pub"] = (
        f"ssh-ed25519 {node.host_key.blob} root@{XUI_NAME}\n"
    )
    prober = env.prober
    prober.auth = auth_methods_of(list(env.transport.nodes.values()), {XUI_IP: node.address})
    prober.by_address[node.address] = node
    prober.aliases[XUI_IP] = node.address
    prober.xui = env.xui_transport
    prober.dns[XUI_DOMAIN] = [XUI_IP]
    prober.pings[XUI_IP] = True

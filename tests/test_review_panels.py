"""Review K13, panels, checks, plan and masking: each test replays a review scenario."""

from helpers import make_app, seen, typed
from test_review_logic import APPLY, DONE, fix_run

from kerberos.demo.nodes import listening
from kerberos.panel import xui_model
from kerberos.panel.xui_fake import raw_inbound

X_CHOOSE = ["down", "enter"]
X_LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
X_TO_PLAN = X_CHOOSE + X_LOGIN + ["enter", "enter", "enter"]


def xui_inbound(ident, port, protocol, stream, *, listen="", settings=None, enable=True):
    item = raw_inbound(ident, port, protocol, stream, enable=enable)
    item.update(listen=listen, settings=settings or {"clients": []})
    return xui_model.inbound(item)


# -- app 1: on 3x-ui every running inbound's port is public on purpose ------------------------
def test_3xui_inbound_ports_count_whatever_they_listen_on():
    inbounds = [
        xui_inbound(1, 8443, "vless", {"network": "tcp", "security": "none"},
                    listen="203.0.113.50"),
        xui_inbound(2, 8388, "shadowsocks", {"network": "tcp"},
                    settings={"method": "2022-blake3-aes-128-gcm", "network": "tcp,udp"}),
        xui_inbound(3, 4443, "hysteria", {"network": "hysteria"}),
        xui_inbound(4, 9999, "vless", {"network": "tcp"}, enable=False),
    ]  # fmt: skip
    snap = xui_model.snapshot("3.11.0", inbounds, "203.0.113.50", "vpn-1", {"port": 2053})
    ports = snap.open_ports[xui_model.LOCAL]
    assert {(8443, "tcp"), (8388, "tcp"), (8388, "udp"), (4443, "udp")} <= set(ports)
    assert not {p for p in ports if p[0] == 9999}, "a switched-off inbound listens nowhere"


def test_3xui_inbound_ports_are_not_dropped():
    app, _term = make_app(X_TO_PLAN + APPLY + DONE, panel_kind=None, height=44)
    pinned = raw_inbound(4, 8443, "vless", {"network": "tcp", "security": "none"}, remark="pin")
    pinned["listen"] = "203.0.113.50"
    ss = raw_inbound(5, 8388, "shadowsocks", {"network": "tcp", "security": "none"}, remark="ss")
    ss["settings"] = {"method": "2022-blake3-aes-128-gcm", "network": "tcp,udp", "clients": []}
    app.env.xui_transport.inbounds += [pinned, ss]
    node = app.env.transport.nodes["127.0.0.1"]
    node.state["facts"]["listening"] += listening(
        ("tcp", "203.0.113.50", 8443, "xray-linux-amd6"),
        ("tcp", "0.0.0.0", 8388, "xray-linux-amd6"),
        ("udp", "0.0.0.0", 8388, "xray-linux-amd6"),
    )[-3:]
    app.run("fix")
    run = fix_run(app)
    found = next(f for f in run["findings"] if f["checkId"] == "ports.public")
    assert found["evidence"]["ports"] == ["3306/tcp"]
    drops = [c["params"]["ports"] for c in run["changes"] if c["fixId"] == "ports.drop"]
    assert drops == [["3306/tcp"]]
    assert not [s for s in node.state["facts"]["listening"] if s["port"] in (8443, 8388)
                and s.get("firewalled")]  # fmt: skip


# -- app 6: 3x-ui runs Xray as xray-linux-<arch>; self-steal is not blocked by the name ---------
def test_3xui_xray_binary_name_does_not_block_self_steal():
    from kerberos.copy import t
    from kerberos.fixes.plan import is_xray

    app, term = make_app(X_TO_PLAN + ["esc", "esc", "q", "enter"], panel_kind=None, height=44)
    node = app.env.transport.nodes["127.0.0.1"]
    for sock in node.state["facts"]["listening"]:
        if sock["port"] == 443:
            sock["process"] = "xray-linux-amd6"  # how ss shows /usr/local/x-ui/bin/xray-linux-amd64
    app.run("fix")
    steal = next(i for i in app.session.data["plan"] if i.fix_id == "self_steal")
    assert steal.blocked is None and not seen(term, t("plan.blocked.port443"))
    assert is_xray("xray") and is_xray("rw-core") and is_xray("xray-linux-arm6")
    assert not is_xray("nginx") and not is_xray(None)


# -- agent 5: node_api.panel_only waits for the panel to be seen at KERBEROS's address ----------
def test_node_api_rule_is_blocked_when_the_panel_comes_from_elsewhere():
    from demo_input import demo_input

    from kerberos.checks import run_checks
    from kerberos.fixes.plan import build_plan

    _env, data = demo_input()
    nl1 = next(n for n in data.nodes if n.node.name == "nl-1")
    fi1 = next(n for n in data.nodes if n.node.name == "fi-1")
    nl1.facts["nodeApi"]["panelPeer"] = False  # the backend connects over another address
    fi1.facts["nodeApi"].pop("panelPeer", None)  # an agent that cannot tell: not blocked
    plan = {(i.node_uuid, i.fix_id): i for i in build_plan(run_checks(data), data, None, {})}
    assert plan[(nl1.node.uuid, "node_api.panel_only")].blocked == "panel_peer"
    assert plan[(nl1.node.uuid, "node_api.panel_only")].selected is False
    assert plan[(fi1.node.uuid, "node_api.panel_only")].blocked is None


# -- app 11: the secret base path of 3x-ui never reaches the screen ----------------------------
def test_3xui_error_names_the_panel_without_its_secret_path():
    from kerberos.demo.xui import SETTINGS
    from kerberos.panel.client import Unreachable
    from kerberos.panel.discover import XUI_DB

    keys = X_CHOOSE + X_LOGIN + ["esc", "esc", "esc", "q", "enter"]
    app, term = make_app(keys, panel_kind=None, height=44)
    app.env.host.databases[XUI_DB] = dict(SETTINGS, webBasePath="/s3cr3tpathXYZ/")

    def refused(*_args, **_kwargs):
        raise Unreachable("[Errno 61] Connection refused")

    app.env.xui_transport = refused  # x-ui is stopped
    app.run("check")
    assert seen(term, "http://127.0.0.1:2053")
    assert not seen(term, "s3cr3tpathXYZ")


# -- app 13: a fresh client writes hosts in the panel's own form -------------------------------
def test_fresh_client_writes_hosts_in_the_tag_form():
    from kerberos.clock import FakeClock
    from kerberos.demo.fleet import build_panel
    from kerberos.panel.client import PanelClient

    panel = build_panel("tag")
    client = PanelClient("http://127.0.0.1:3000/api", panel, FakeClock())
    client.login("admin", "any")  # as `kerberos rollback` does: no host read before the write
    host = next(h for h in panel.hosts if h["remark"] == "DE Reality")
    client.patch_host(host["uuid"], {"tags": ["DE1_BACK"], "isHidden": False})
    assert host["tag"] == "DE1_BACK" and "tags" not in host
    writes = [body for method, path, body in panel.log if (method, path) == ("PATCH", "/hosts")]
    assert writes and "tag" in writes[-1] and "tags" not in writes[-1]


def test_reserve_rollback_on_a_tag_panel():
    from test_review_logic import ROLLBACK, fix, fleet
    from test_review_self_steal import reserve_keys

    from kerberos.demo.fleet import build_panel
    from kerberos.flow import EXIT_OK

    _panel, nodes = fleet()
    panel = build_panel("tag")
    app, _term, code = fix(reserve_keys() + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    assert {c["state"] for c in fix_run(app)["changes"]} == {"rolled_back"}

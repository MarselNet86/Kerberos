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

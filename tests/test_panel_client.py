"""PanelClient against the fake panel (tech.md §7, §17): both host forms, errors."""

import pytest

from kerberos.clock import FakeClock
from kerberos.demo.fleet import build_panel
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError
from kerberos.panel.fake import FakePanel, raw_host, raw_profile

API = "http://127.0.0.1:3000/api"


def client_for(panel: FakePanel, clock=None) -> PanelClient:
    client = PanelClient(API, panel, clock or FakeClock())
    client.set_token(panel.add_api_token())
    return client


@pytest.mark.parametrize("shape", ["tags", "tag"])
def test_snapshot_reads_both_host_forms(shape):
    panel = build_panel(shape)
    client = client_for(panel)
    snap = client.snapshot("2.8.1", "panel.example.com")
    assert snap.host_shape == shape
    assert len(snap.nodes) == 6 and len(snap.hosts) == 10
    cdn = next(h for h in snap.hosts if h.remark == "FI CDN")
    assert cdn.tags == ["FI1"]
    assert cdn.xhttp_extra["uplinkHTTPMethod"] == "POST"
    reserve = next(h for h in snap.hosts if h.remark == "NL-2 reserve")
    assert reserve.is_hidden and reserve.tags == ["NL2"]
    nl1 = next(n for n in snap.nodes if n.name == "nl-1")
    assert [h.remark for h in snap.node_hosts(nl1)] == ["NL Reality"]
    assert snap.templates[0].json is not None, "XRAY_JSON bodies are fetched one by one"


@pytest.mark.parametrize("shape", ["tags", "tag"])
def test_writes_use_the_form_the_panel_answered_with(shape):
    panel = build_panel(shape)
    client = client_for(panel)
    snap = client.snapshot("2.8.1")
    source = next(h for h in snap.hosts if h.remark == "FI CDN")
    fields = {k: v for k, v in source.raw.items() if k not in ("uuid", "viewPosition")}
    fields.pop("tags", None), fields.pop("tag", None)
    fields.pop("xhttpExtraParams", None), fields.pop("xHttpExtraParams", None)
    fields.update(
        {
            "tags": ["KRB_FI1_VLESS"],
            "xhttpExtraParams": {"uplinkHTTPMethod": "GET"},
            "sni": "fi-1.example.com",
        }
    )
    copy = client.create_host(fields)
    assert copy.tags == ["KRB_FI1_VLESS"] and copy.xhttp_extra == {"uplinkHTTPMethod": "GET"}
    stored = panel.host(copy.uuid)
    if shape == "tags":
        assert stored["tags"] == ["KRB_FI1_VLESS"] and "tag" not in stored
    else:
        assert stored["tag"] == "KRB_FI1_VLESS" and "tags" not in stored
    patched = client.patch_host(copy.uuid, {"fingerprint": "firefox", "sni": ""})
    assert patched.fingerprint == "firefox" and patched.sni == ""
    client.disable_hosts([source.uuid])
    assert panel.host(source.uuid)["isDisabled"] is True
    client.enable_hosts([source.uuid])
    assert panel.host(source.uuid)["isDisabled"] is False
    client.delete_host(copy.uuid)
    assert all(h["uuid"] != copy.uuid for h in panel.hosts)


def test_templates_squads_and_settings_round_trip():
    panel = build_panel()
    client = client_for(panel)
    tpl = client.create_template("KERBEROS")
    client.patch_template(tpl.uuid, {"log": {"loglevel": "none"}})
    assert client.template(tpl.uuid).json == {"log": {"loglevel": "none"}}
    squad = client.squads()[0]
    client.patch_squad(squad.uuid, squad.inbound_uuids[:1])
    assert client.squads()[0].inbound_uuids == squad.inbound_uuids[:1]
    settings = client.sub_settings()
    client.patch_sub_settings(settings.uuid, {**settings.headers, "ping-type": "proxy-head"})
    assert client.sub_settings().headers["ping-type"] == "proxy-head"


def test_login_and_password_status():
    panel = FakePanel(credentials=("admin", "s3cret"))
    client = PanelClient(API, panel, FakeClock())
    assert client.password_enabled() is True
    with pytest.raises(PanelError) as exc:
        client.login("admin", "wrong")
    assert exc.value.code == "unauthorized" and not client.authenticated
    client.login("admin", "s3cret")
    assert client.authenticated
    assert client.nodes() == []


def test_token_401_and_403():
    panel = FakePanel()
    client = PanelClient(API, panel, FakeClock())
    client.set_token("not-a-token")
    with pytest.raises(PanelError) as exc:
        client.nodes()
    assert exc.value.code == "unauthorized"
    client.set_token(panel.add_api_token())
    panel.forbidden.add(("PATCH", "/hosts"))
    with pytest.raises(PanelError) as exc:
        client.patch_host("x", {"fingerprint": "firefox"})
    assert exc.value.code == "forbidden" and exc.value.operation == "PATCH /hosts"


def test_5xx_is_retried_after_1_4_15_seconds():
    panel = build_panel()
    clock = FakeClock()
    client = client_for(panel, clock)
    panel.fail("GET", "/nodes", 502, times=3)
    assert len(client.nodes()) == 6
    assert clock.slept == [1, 4, 15]
    panel.fail("GET", "/nodes", 500, times=4)
    with pytest.raises(PanelError) as exc:
        client.nodes()
    assert exc.value.code == "server_error" and exc.value.status == 500


def test_timeout_is_retried_then_reported():
    panel = build_panel()
    clock = FakeClock()
    client = client_for(panel, clock)
    panel.fail("GET", "/hosts", "timeout", times=4)
    with pytest.raises(PanelError) as exc:
        client.hosts()
    assert exc.value.code == "timeout"
    assert clock.slept == [1, 4, 15]


def test_post_without_answer_is_not_repeated():
    panel = build_panel()
    clock = FakeClock()
    client = client_for(panel, clock)
    snap = client.snapshot("2.8.1")
    source = snap.hosts[0]
    fields = {k: v for k, v in source.raw.items() if k not in ("uuid", "viewPosition")}
    before = len(panel.hosts)
    panel.fail("POST", "/hosts", "lost")
    with pytest.raises(PanelError) as exc:
        client.create_host(fields)
    assert exc.value.code == "no_response"
    assert len(panel.hosts) == before + 1, "the host was created, the answer was lost"
    assert [m for m in panel.log if m[:2] == ("POST", "/hosts")].__len__() == 1
    assert clock.slept == []


def test_refused_connection():
    panel = build_panel()
    clock = FakeClock()
    client = client_for(panel, clock)
    panel.fail("GET", "/nodes", "refused", times=4)
    with pytest.raises(PanelError) as exc:
        client.nodes()
    assert exc.value.code == "unreachable"


def test_every_request_carries_forward_headers():
    seen = []

    def transport(method, url, headers, body, timeout):
        seen.append(headers)
        return 200, b'{"response": {"authentication": {"password": {"enabled": true}}}}'

    PanelClient(API, transport, FakeClock()).password_enabled()
    assert seen[0]["x-forwarded-proto"] == "https"
    assert seen[0]["x-forwarded-for"] == "127.0.0.1"
    assert seen[0]["x-real-ip"] == "127.0.0.1"
    assert "authorization" not in seen[0]


def test_fake_panel_rejects_requests_without_headers():
    panel = FakePanel()
    status, _ = panel("GET", API + "/auth/status", {}, None, 15)
    assert status == 400


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"no": "envelope"}',
        b'{"response": [{"uuid": 5}]}',
        b'{"response": [{"uuid": "a", "name": "n"}]}',
        b"not json",
    ],
)
def test_answers_off_schema_are_bad_response(body):
    client = PanelClient(API, lambda *a: (200, body), FakeClock())
    client.set_token("t")
    with pytest.raises(PanelError) as exc:
        client.nodes()
    assert exc.value.code == "bad_response"


@pytest.mark.parametrize(
    "fields, message",
    [
        ({"unknownField": 1}, "unknown host fields"),
        ({"sni": None}, "sni must be a string"),
        ({"tags": ["lower-case"]}, "does not match"),
        ({"port": "443"}, "port must be a number"),
    ],
)
def test_fake_panel_fails_on_garbage(fields, message):
    panel = build_panel()
    client = client_for(panel)
    snap = client.snapshot("2.8.1")
    with pytest.raises(PanelError) as exc:
        client.patch_host(snap.hosts[0].uuid, fields)
    assert exc.value.code == "bad_request" and message in exc.value.detail


def test_profile_patch_keeps_inbound_uuids_by_tag():
    panel = FakePanel()
    profile = raw_profile("P", {"inbounds": [{"tag": "A", "protocol": "vless", "port": 443}]})
    panel.profiles = [profile]
    panel.hosts = [raw_host("tags", profile, "A", "h", "198.51.100.1")]
    client = client_for(panel)
    before = client.profiles()[0].inbounds[0].uuid
    config = {
        "inbounds": [
            {"tag": "A", "protocol": "vless", "port": 443},
            {"tag": "B", "protocol": "hysteria", "port": 443},
        ]
    }
    after = client.patch_profile(profile["uuid"], config)
    assert after.inbounds[0].uuid == before and after.inbounds[1].tag == "B"

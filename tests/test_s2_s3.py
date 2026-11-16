"""S2 panel and S3 nodes: key scenarios (tech.md §6, §7, K1)."""

from helpers import assert_snapshot, login_keys, make_app, typed

from kerberos.copy import t
from kerberos.demo.fleet import build_panel
from kerberos.flow import EXIT_PANEL
from kerberos.host import FakeHost
from kerberos.panel.fake import FakePanel


def strict_panel(**kwargs) -> FakePanel:
    panel = build_panel()
    panel.accept_any_login = False
    for key, value in kwargs.items():
        setattr(panel, key, value)
    return panel


def test_s2_connects_without_typing_an_address():
    keys = ["enter"] + login_keys() + ["enter", "enter", "x", "q", "enter"]
    app, term = make_app(keys, panel=strict_panel())
    assert app.run("check") == 0
    assert any(t("panel.found", version="2.8.1") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=9) in f for f in term.frames)
    assert any(t("nodes.title") in f for f in term.frames)


def test_s2_wrong_password_then_right_one():
    keys = typed("admin") + ["enter"] + typed("nope") + ["enter"]
    keys += typed("admin-password") + ["enter", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert any(t("panel.err.login") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=9) in f for f in term.frames)


def test_password_and_token_never_reach_the_screen():
    panel = strict_panel(password_enabled=False)
    token = panel.add_api_token("rw-0123456789abcdef")
    keys = typed(token) + ["enter", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert all(token not in f for f in term.frames)
    assert any(t("panel.token") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=9) in f for f in term.frames)
    keys = typed("admin") + ["enter"] + typed("admin-password") + ["enter", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert all("admin-password" not in f for f in term.frames)


def test_wrong_token_is_reported():
    panel = strict_panel(password_enabled=False)
    keys = typed("bad-token") + ["enter", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert any(t("panel.err.token") in f for f in term.frames)


def test_panel_not_found_asks_for_the_api_address():
    keys = ["enter"] + login_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, host=FakeHost(), panel=strict_panel())
    app.run("check")
    assert t("panel.not_found") in term.frames[1]
    assert any(t("panel.ok", nodes=6, hosts=9) in f for f in term.frames)


def test_server_error_offers_retry_and_esc_exits_with_3():
    panel = strict_panel()
    panel.fail("GET", "/auth/status", 503, times=4)
    app, term = make_app(["esc"], panel=panel)
    assert app.run("check") == EXIT_PANEL
    assert t("panel.err.server", status=503, operation="GET /auth/status") in term.last
    panel = strict_panel()
    panel.fail("GET", "/auth/status", 503, times=4)
    keys = ["enter"] + login_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert any(t("panel.ok", nodes=6, hosts=9) in f for f in term.frames)


def test_forbidden_while_reading_is_shown_with_the_operation():
    panel = strict_panel()
    panel.forbidden.add(("GET", "/internal-squads"))
    keys = login_keys() + ["esc"]
    app, term = make_app(keys, panel=panel)
    assert app.run("check") == EXIT_PANEL
    assert any(t("panel.err.forbidden", operation="GET /internal-squads") in f for f in term.frames)


def test_s3_snapshot_and_disabled_node():
    keys = login_keys() + ["enter", "down", "down", "down", "down", "space", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel(), height=24)
    app.run("check")
    s3 = next(f for f in term.frames if t("nodes.title") in f)
    assert_snapshot("s3", s3)
    us = next(line for line in s3.splitlines() if "us-1" in line)
    assert " - " in us and t("nodes.status.disabled") in us


def test_s3_needs_at_least_one_node():
    keys = login_keys() + ["enter", "a", "enter", "a", "enter", "x", "q", "enter"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert any(t("nodes.need_one") in f for f in term.frames)
    assert any(t("access.title") in f for f in term.frames)


def test_check_mode_makes_no_changes_in_the_panel():
    panel = strict_panel()
    keys = login_keys() + ["enter", "enter", "x", "q", "enter"]
    app, _ = make_app(keys, panel=panel)
    app.run("check")
    assert panel.mutations == []


def test_s3_masks_addresses():
    keys = login_keys() + ["enter", "m", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    masked = next(f for f in term.frames if t("nodes.title") in f and t("hdr.mask") in f)
    # documentation addresses are already safe and stay as they are
    assert "203.0.113.10" in masked

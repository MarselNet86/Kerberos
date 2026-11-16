"""S1: logo, the phrase about the product and the mode menu (tech.md §6, K0)."""

from conftest import assert_snapshot
from helpers import make_app

from kerberos.copy import t


def test_s1_snapshot():
    app, term = make_app(["q", "enter"], height=24)
    assert app.run() == 0
    s1 = term.frames[0]
    for key in ("mode.check", "mode.fix", "mode.rollback", "mode.reports", "app.tagline"):
        assert t(key) in s1
    assert_snapshot("s1", s1)


def test_s1_keys_scenario():
    # down, down, up: the cursor sits on "Исправление"; help opens and closes;
    # m turns masking on (flag in the header); q asks, Esc stays, q + Enter leaves.
    app, term = make_app(["down", "down", "up", "?", "x", "m", "q", "esc", "q", "enter"])
    assert app.run() == 0
    pointer_line = [line for line in term.frames[3].splitlines() if "›" in line]
    assert pointer_line and t("mode.fix") in pointer_line[0]
    assert t("help.title") in term.frames[4]
    assert t("hdr.mask") in term.frames[6]
    assert t("quit.confirm") in term.frames[7]
    assert t("quit.confirm") in term.frames[-1]
    assert term.remaining == []


def test_s1_russian_layout_quit():
    app, term = make_app(["й", "enter"])
    assert app.run() == 0


def test_s1_menu_number_opens_item():
    app, term = make_app(["1", "x", "q", "enter"])
    assert app.run() == 0
    assert t("app.soon") in term.frames[1]


def test_s1_ctrl_c_asks_before_leaving():
    app, term = make_app(["ctrl-c", "esc", "ctrl-c", "enter"])
    assert app.run() == 0
    assert t("quit.confirm") in term.frames[1]


def test_s1_fits_80_columns():
    app, term = make_app(["q", "enter"], width=80, height=24)
    app.run()
    assert all(len(line) <= 80 for line in term.frames[0].splitlines())
    assert t("mode.fix") in term.frames[0]

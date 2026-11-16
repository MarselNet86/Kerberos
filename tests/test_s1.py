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
    app, term = make_app(["4", "x", "q", "enter"])
    assert app.run() == 0
    assert t("app.soon") in term.frames[1]


def test_s1_ctrl_c_asks_before_leaving():
    app, term = make_app(["ctrl-c", "esc", "ctrl-c", "enter"])
    assert app.run() == 0
    assert t("quit.confirm") in term.frames[1]


def test_logo_is_red_pixels_on_s1_and_a_line_in_the_header():
    from kerberos.ui.logo import LOGO, LOGO_ART
    from kerberos.ui.palette import PALETTE
    from kerberos.ui.terminal import frame_text

    assert LOGO == "/// kerberos"
    assert PALETTE["logo"] == "bold red"
    assert len(LOGO_ART) == 2 and len(LOGO_ART[0]) == len(LOGO_ART[1])
    app, term = make_app(["q", "enter"], height=24)
    app.run()
    lines = term.frames[0].splitlines()
    assert lines[0].startswith(LOGO)
    assert LOGO_ART[0].rstrip() in lines[3] and LOGO_ART[1].rstrip() in lines[4]
    colored = frame_text(app.frame("", app.s1_body(_menu()), ()), 100, 24, color=True)
    assert "\x1b[1;31m/// kerberos" in colored
    assert "\x1b[1;31m" + LOGO_ART[0] in colored
    # The selected menu row is red like the logo, and still marked with the pointer.
    assert "\x1b[1;31m" + t("mode.check") in colored
    assert "\x1b[1;31m›" in colored


def _menu():
    from kerberos.ui.widgets import Menu

    return Menu([("check", t("mode.check"), "")])


def test_s1_fits_80_columns():
    app, term = make_app(["q", "enter"], width=80, height=24)
    app.run()
    assert all(len(line) <= 80 for line in term.frames[0].splitlines())
    assert t("mode.fix") in term.frames[0]

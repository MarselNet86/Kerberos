import io

from rich.text import Text

from kerberos.copy import t
from kerberos.ui.terminal import FakeTerminal, frame_text, make_console
from kerberos.ui.widgets import (
    Checklist,
    Consent,
    FindingItem,
    FindingList,
    Menu,
    Notice,
    Pager,
    ProgressBoard,
    ScoreBadge,
    Screen,
    TextInput,
)


def render(renderable, width=100, height=30) -> str:
    term = FakeTerminal(width=width, height=height)
    term.draw(renderable)
    return term.last


def test_menu_wraps_and_selects():
    menu = Menu([("a", "A", ""), ("b", "B", "hint")])
    assert menu.handle("up") is None and menu.selected == 1
    assert menu.handle("enter") == "b"
    assert menu.handle("1") == "a"
    assert "hint" in render(menu)


def test_checklist_skips_disabled_and_selects_all_enabled():
    rows = [["nl-1"], ["us-1"], ["de-1"]]
    cl = Checklist(rows, ["Нода"], disabled={1})
    cl.handle("down")
    assert cl.cursor == 2
    cl.handle("space")
    assert cl.selected == {2}
    cl.handle("a")
    assert cl.selected == {0, 2}
    cl.handle("a")
    assert cl.selected == set()
    cl.handle("ф")  # Russian layout
    assert cl.selected == {0, 2}
    assert cl.handle("enter") == "done"
    frame = render(cl)
    assert " - " in frame and "[✓]" in frame


def test_checklist_scrolls_to_cursor():
    rows = [[f"node-{i}"] for i in range(40)]
    cl = Checklist(rows, ["Нода"])
    cl.viewport = 8
    for _ in range(30):
        cl.handle("down")
    frame = render(cl)
    assert "node-30" in frame and "node-0 " not in frame


def test_text_input_editing_and_validation():
    field = TextInput("Домен", validate=lambda v: None if "." in v else "нужна точка")
    for key in "examplecom":
        field.handle(key)
    for _ in range(3):
        field.handle("left")
    field.handle(".")
    assert field.value == "example.com"
    field.handle("end")
    field.handle("backspace")
    assert field.handle("enter") == "example.co"
    field.value, field.pos = "nodot", 5
    assert field.handle("enter") is None
    assert "нужна точка" in render(field)
    field.handle("space")
    assert field.value == "nodot "


def test_secret_input_never_shows_characters():
    field = TextInput(t("panel.password"), secret=True)
    for key in "s3cr3t":
        field.handle(key)
    frame = render(field)
    assert "s3cr3t" not in frame and "••••••" in frame
    assert t("input.hidden") in frame


def test_consent_accepts_only_enter():
    consent = Consent(Text("plan"), t("consent.accept"))
    assert Consent.handle("enter") is True
    assert Consent.handle("y") is False and Consent.handle("space") is False
    assert t("consent.accept") in render(consent)


def test_progress_board_symbols():
    board = ProgressBoard(["nl-1"], ["бэкап", "применение"])
    board.start("nl-1", "mptcp.guard")
    board.set("nl-1", "бэкап", "ok")
    board.set("nl-1", "применение", "failed")
    frame = render(board)
    assert "✓" in frame and "✗" in frame


def test_score_badge_words_and_colours():
    assert t("score.red") in render(ScoreBadge(42))
    assert t("score.yellow") in render(ScoreBadge(60))
    assert t("score.green") in render(ScoreBadge(85, before=40))
    assert t("score.before_after", before=40, score=85) in render(ScoreBadge(85, before=40))


def test_finding_list_groups_and_expands():
    items = [
        FindingItem("high", "Тема 1", "nl-1", "Вход по паролю", "Перебор", "исправит KERBEROS",
                    details="sshd -T: passwordauthentication yes"),
        FindingItem("medium", "Тема 2", "de-1", "Порт 22", "Сканеры", "вручную"),
    ]
    fl = FindingList(items)
    frame = render(fl)
    assert "Тема 1" in frame and "Тема 2" in frame and "sshd -T" not in frame
    fl.handle("enter")
    assert "sshd -T" in render(fl)
    fl.handle("down")
    assert fl.cursor == 1


def test_notice_has_a_word_title():
    assert t("notice.error") in render(Notice("error", "boom"))


def test_pager_scrolls():
    pager = Pager("\n".join(f"line {i}" for i in range(100)))
    pager.viewport = 10
    render(pager)
    pager.handle("pgdn")
    frame = render(pager)
    assert "line 9" in frame and "line 0\n" not in frame
    pager.handle("end")
    assert "line 99" in render(pager)


def test_screen_keeps_footer_when_body_overflows():
    body = Text("\n".join(f"row {i}" for i in range(100)))
    frame = render(Screen("Заголовок", body, [("q", t("keys.quit"))]), height=20)
    lines = frame.splitlines()
    assert len(lines) == 20
    assert t("keys.quit") in lines[-1]


def test_color_frames_use_palette_and_no_color_strips_it():
    styled = frame_text(Text("x", style="risk.high"), 20, 2, color=True)
    assert "\x1b[" in styled
    plain = frame_text(Text("x", style="risk.high"), 20, 2, color=False)
    assert "\x1b[" not in plain


def test_markup_is_never_interpreted():
    console = make_console(io.StringIO(), 40, 5, color=False, record=True)
    console.print("[bold]not markup[/bold]")
    assert "[bold]" in console.export_text()

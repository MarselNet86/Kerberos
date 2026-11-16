"""Screen scenario S1-S9 (tech.md §6).

The app owns the loop: it draws a frame, reads one key and gives it to the
widget of the current screen. Global keys (`m` masking, `?` help, `q` quit)
work on every screen except while a text field has the focus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, TypeVar

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos import __version__
from kerberos.clock import Clock
from kerberos.copy import t
from kerberos.mask import Masker
from kerberos.ui.keys import hotkey
from kerberos.ui.logo import LOGO
from kerberos.ui.terminal import Terminal
from kerberos.ui.widgets import Body, KeyHints, Menu, Notice, Screen

T = TypeVar("T")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PANEL = 3
EXIT_PARTIAL = 4
EXIT_ROLLBACK_FAILED = 5
EXIT_INTERRUPTED = 130


class QuitApp(Exception):
    """The person chose to leave KERBEROS."""


@dataclass
class Env:
    """Ports and settings of one KERBEROS process (tech.md §4)."""

    terminal: Terminal
    clock: Clock
    masker: Masker
    demo: bool = False


def keys_menu() -> KeyHints:
    return (
        ("↑↓", t("keys.select")),
        ("Enter", t("keys.next")),
        ("m", t("keys.mask")),
        ("?", t("keys.help")),
        ("q", t("keys.quit")),
    )


class App:
    def __init__(self, env: Env) -> None:
        self.env = env
        self.busy = False

    @property
    def term(self) -> Terminal:
        return self.env.terminal

    def mask(self, value: str) -> str:
        return self.env.masker(value)

    # -- frame and loop ------------------------------------------------
    def flags(self) -> list[str]:
        flags = []
        if self.env.demo:
            flags.append(t("hdr.demo"))
        if self.env.masker.enabled:
            flags.append(t("hdr.mask"))
        return flags

    def frame(self, title: str, body: Body, keys: KeyHints) -> Screen:
        return Screen(title, body, keys, flags=self.flags())

    def interact(
        self,
        title: str,
        body: Body,
        keys: KeyHints,
        handle: Callable[[str], Optional[T]],
        *,
        typing: bool = False,
        timeout: Optional[float] = None,
        tick: Optional[Callable[[], Optional[T]]] = None,
    ) -> T:
        """Draw and dispatch keys until `handle` or `tick` returns a value."""
        while True:
            if not self.term.has_pending():
                self.term.draw(self.frame(title, body, keys))
            key = self.term.read_key(timeout)
            if key is None:
                if tick is not None:
                    result = tick()
                    if result is not None:
                        return result
                continue
            if key == "ctrl-c":
                if self.confirm_quit():
                    raise QuitApp
                continue
            if not typing:
                hk = hotkey(key)
                if hk == "m":
                    self.env.masker.toggle()
                    continue
                if hk == "?":
                    self.show_help()
                    continue
                if hk == "q":
                    if self.confirm_quit():
                        raise QuitApp
                    continue
            result = handle(key)
            if result is not None:
                return result

    def confirm_quit(self) -> bool:
        text = t("quit.confirm_busy") if self.busy else t("quit.confirm")
        body = Group(
            Notice("warning", text),
            Text(f"{t('quit.yes')}    {t('quit.no')}", style="muted"),
        )
        self.term.draw(self.frame(t("keys.quit"), body, ()))
        return self.term.read_key() == "enter"

    def show_help(self) -> None:
        body = Group(Text(t("help.body")), Text(""), Text(t("help.close"), style="muted"))
        self.term.draw(self.frame(t("help.title"), body, ()))
        self.term.read_key()

    def notice(self, kind: str, message: str, title: str = "") -> None:
        """Show a plate until any key."""
        body = Group(Notice(kind, message), Text(""), Text(t("help.close"), style="muted"))
        self.term.draw(self.frame(title, body, ()))
        self.term.read_key()

    # -- screens -------------------------------------------------------
    def run(self, command: Optional[str] = None, arg: Optional[str] = None) -> int:
        try:
            if command is None:
                return self.main_menu()
            self.notice("info", t("app.soon"))
            return EXIT_OK
        except QuitApp:
            return EXIT_OK

    def s1_body(self, menu: Menu) -> Callable[[int, int], RenderableType]:
        def body(_width: int, _height: int) -> RenderableType:
            logo = Text("\n".join(LOGO), style="accent")
            return Group(
                Text(""),
                logo,
                Text(""),
                Text(t("app.tagline"), style="bold"),
                Text(t("cli.version", version=__version__), style="muted"),
                Text(""),
                menu,
            )

        return body

    def main_menu(self) -> int:
        """S1: logo, one phrase about the product, the mode menu."""
        menu = Menu(
            [
                ("check", t("mode.check"), ""),
                ("fix", t("mode.fix"), ""),
                ("rollback", t("mode.rollback"), ""),
                ("reports", t("mode.reports"), ""),
            ]
        )
        while True:
            self.interact("", self.s1_body(menu), keys_menu(), menu.handle)
            self.notice("info", t("app.soon"))

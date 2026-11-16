"""Screen scenario S1-S9 (tech.md §6).

The app owns the loop: it draws a frame, reads one key and gives it to the
widget of the current screen. Global keys (`m` masking, `?` help, `q` quit)
work on every screen except while a text field has the focus. Screens live
in `kerberos.screens`; this module keeps their order and the shared state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos import __version__
from kerberos.clock import Clock
from kerberos.copy import t
from kerberos.flow import BACK, EXIT_OK, NEXT
from kerberos.host import Host
from kerberos.mask import Masker
from kerberos.panel.client import PanelClient, Transport
from kerberos.panel.discover import PanelLocation
from kerberos.panel.model import PanelSnapshot
from kerberos.ui.keys import hotkey
from kerberos.ui.logo import LOGO
from kerberos.ui.terminal import Terminal
from kerberos.ui.widgets import Body, KeyHints, Menu, Notice, Screen

T = TypeVar("T")


class QuitApp(Exception):
    """The person chose to leave KERBEROS."""


@dataclass
class Env:
    """Ports and settings of one KERBEROS process (tech.md §4)."""

    terminal: Terminal
    clock: Clock
    masker: Masker
    host: Optional[Host] = None
    panel_transport: Optional[Transport] = None
    demo: bool = False


@dataclass
class Session:
    """State of one run of «Проверка» or «Исправление»."""

    mode: str
    location: Optional[PanelLocation] = None
    panel: Optional[PanelClient] = None
    snapshot: Optional[PanelSnapshot] = None
    selected: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


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

    def draw(self, title: str, body: Body, keys: KeyHints = ()) -> None:
        self.term.draw(self.frame(title, body, keys))

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
                self.draw(title, body, keys)
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
        self.draw(t("keys.quit"), body)
        return self.term.read_key() == "enter"

    def show_help(self) -> None:
        body = Group(Text(t("help.body")), Text(""), Text(t("help.close"), style="muted"))
        self.draw(t("help.title"), body)
        self.term.read_key()

    def notice(self, kind: str, message: str, title: str = "") -> None:
        """Show a plate until any key."""
        body = Group(Notice(kind, message), Text(""), Text(t("help.close"), style="muted"))
        self.draw(title, body)
        self.term.read_key()

    def ask_retry(self, title: str, message: str) -> bool:
        """Error plate: Enter retries, Esc gives up."""
        body = Group(
            Notice("error", message),
            Text(f"{t('error.retry')}    {t('error.back')}", style="muted"),
        )

        def handle(key: str) -> Optional[bool]:
            if key == "enter":
                return True
            if key == "esc":
                return False
            return None

        return self.interact(title, body, (), handle)

    # -- scenario ------------------------------------------------------
    def run(self, command: Optional[str] = None, arg: Optional[str] = None) -> int:
        try:
            if command is None:
                return self.main_menu()
            if command in ("check", "fix"):
                result = self.run_mode(command)
                return EXIT_OK if result is None else result
            self.notice("info", t("app.soon"))
            return EXIT_OK
        except QuitApp:
            return EXIT_OK

    def steps(self, session: Session) -> list[Callable[[Session], Any]]:
        from kerberos.screens import nodes, panel

        return [panel.step, nodes.step, self.step_soon]

    def run_mode(self, mode: str) -> Optional[int]:
        """Walk the screens of a mode. None: the person went back to S1."""
        session = Session(mode)
        steps = self.steps(session)
        index = 0
        while 0 <= index < len(steps):
            result = steps[index](self, session)
            if result == NEXT:
                index += 1
            elif result == BACK:
                index -= 1
            elif isinstance(result, int):
                return result
        return EXIT_OK if index >= len(steps) else None

    @staticmethod
    def step_soon(app: App, session: Session) -> Any:
        app.notice("info", t("app.soon"))
        return NEXT

    def s1_body(self, menu: Menu) -> Callable[[int, int], RenderableType]:
        def body(_width: int, _height: int) -> RenderableType:
            return Group(
                Text(""),
                Text(LOGO, style="logo"),
                Text(""),
                Text(t("app.tagline"), style="bold"),
                Text(t("app.version", version=__version__), style="muted"),
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
            choice = self.interact("", self.s1_body(menu), keys_menu(), menu.handle)
            if choice in ("check", "fix"):
                self.run_mode(choice)
            else:
                self.notice("info", t("app.soon"))

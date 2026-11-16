"""Terminal port (tech.md §4, §14.4): live (termios) and fake (scripted keys).

Screens draw whole frames and read one key at a time. The live terminal uses
the alternate screen and a raw-ish mode where Ctrl+C arrives as a key, so the
app decides what an interruption means (§11.5). The fake terminal replays a
key script and records every frame as plain text for tests and snapshots.
"""

from __future__ import annotations

import io
import os
import select
import shutil
import sys
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from typing import Callable, Optional, Protocol

from rich.console import Console, RenderableType

from kerberos.ui.keys import KeyDecoder
from kerberos.ui.palette import theme

# A lone ESC is the Esc key unless more bytes of a sequence follow quickly.
ESC_TIMEOUT = 0.05


class Terminal(Protocol):
    color: bool

    @property
    def size(self) -> tuple[int, int]: ...

    def draw(self, renderable: RenderableType) -> None: ...

    def read_key(self, timeout: Optional[float] = None) -> Optional[str]: ...

    def has_pending(self) -> bool: ...

    def suspend(self, message: str = "") -> AbstractContextManager[None]: ...

    def close(self) -> None: ...


def make_console(
    file: io.TextIOBase, width: int, height: int, color: bool, record: bool = False
) -> Console:
    """Console with the settings every KERBEROS frame uses.

    Markup, emoji and highlighting are off: texts come from copy.py and data
    from servers, and neither may be reinterpreted as Rich markup.
    """
    return Console(
        file=file,
        width=width,
        height=height,
        theme=theme(),
        force_terminal=color,
        no_color=not color,
        color_system="auto" if color else None,
        markup=False,
        emoji=False,
        highlight=False,
        record=record,
        legacy_windows=False,
        soft_wrap=False,
    )


def frame_text(renderable: RenderableType, width: int, height: int, color: bool) -> str:
    """Render one frame to a string (with ANSI styles when `color`)."""
    buf = io.StringIO()
    console = make_console(buf, width, height, color)
    console.print(renderable, end="")
    return buf.getvalue()


class LiveTerminal:
    """The real terminal: alternate screen, keys without echo, Ctrl+C as a key."""

    def __init__(self, color: bool, stdin: Optional[int] = None, stdout=None) -> None:
        import termios

        self._termios = termios
        self.color = color
        self._fd = sys.stdin.fileno() if stdin is None else stdin
        self._out = stdout or sys.stdout
        self._saved = termios.tcgetattr(self._fd)
        self._decoder = KeyDecoder()
        self._queue: deque[str] = deque()
        self._active = False
        self._enter()

    @property
    def size(self) -> tuple[int, int]:
        cols, rows = shutil.get_terminal_size((100, 30))
        return max(cols, 20), max(rows, 10)

    def _enter(self) -> None:
        termios = self._termios
        attrs = termios.tcgetattr(self._fd)
        attrs[0] &= ~(termios.IXON | termios.ICRNL)
        attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG | termios.IEXTEN)
        attrs[6][termios.VMIN] = 1
        attrs[6][termios.VTIME] = 0
        termios.tcsetattr(self._fd, termios.TCSADRAIN, attrs)
        self._out.write("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
        self._out.flush()
        self._active = True

    def _leave(self) -> None:
        if not self._active:
            return
        self._out.write("\x1b[?25h\x1b[?1049l")
        self._out.flush()
        self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN, self._saved)
        self._active = False

    def draw(self, renderable: RenderableType) -> None:
        width, height = self.size
        text = frame_text(renderable, width, height, self.color)
        lines = text.split("\n")[:height]
        # Clear each line's tail instead of the whole screen: no flicker.
        self._out.write("\x1b[H" + "\x1b[K\r\n".join(lines) + "\x1b[K\x1b[J")
        self._out.flush()

    def has_pending(self) -> bool:
        if self._queue:
            return True
        ready, _, _ = select.select([self._fd], [], [], 0)
        return bool(ready)

    def read_key(self, timeout: Optional[float] = None) -> Optional[str]:
        while not self._queue:
            wait = ESC_TIMEOUT if self._decoder.waiting_escape else timeout
            ready, _, _ = select.select([self._fd], [], [], wait)
            if not ready:
                if self._decoder.waiting_escape:
                    self._queue.extend(self._decoder.flush())
                    continue
                return None
            data = os.read(self._fd, 1024)
            if not data:
                return "ctrl-d"
            self._queue.extend(self._decoder.feed(data))
        return self._queue.popleft()

    @contextmanager
    def suspend(self, message: str = "") -> Iterator[None]:
        """Give the terminal to a child process (ssh asking for a password)."""
        self._leave()
        if message:
            self._out.write(message + "\n")
            self._out.flush()
        try:
            yield
        finally:
            self._enter()

    def close(self) -> None:
        self._leave()


class ScriptExhausted(Exception):
    """The fake terminal ran out of scripted keys while a screen waited."""


class FakeTerminal:
    """Scripted keys and recorded frames (tech.md §14.4, §17).

    A script item is a key name, or "tick" to let one timeout pass (screens
    that poll background work see `None`). When the script is empty, timed
    reads advance the fake clock and return None; a blocking read raises
    ScriptExhausted so a broken scenario fails instead of hanging.
    """

    def __init__(
        self,
        keys: Sequence[str] = (),
        width: int = 100,
        height: int = 30,
        color: bool = False,
        on_idle: Optional[Callable[[float], None]] = None,
        max_idle: int = 5000,
    ) -> None:
        self.color = color
        self.width = width
        self.height = height
        self.frames: list[str] = []
        self.suspended = 0
        self.messages: list[str] = []
        self._keys: deque[str] = deque(keys)
        self._on_idle = on_idle
        self._idle = 0
        self._max_idle = max_idle

    @property
    def size(self) -> tuple[int, int]:
        return self.width, self.height

    def feed(self, *keys: str) -> None:
        self._keys.extend(keys)

    @property
    def remaining(self) -> list[str]:
        return list(self._keys)

    def draw(self, renderable: RenderableType) -> None:
        buf = io.StringIO()
        console = make_console(buf, self.width, self.height, color=False, record=True)
        console.print(renderable, end="")
        text = console.export_text()
        self.frames.append("\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n"))

    @property
    def last(self) -> str:
        return self.frames[-1] if self.frames else ""

    def has_pending(self) -> bool:
        # Every scripted key is a separate keystroke: draw a frame before each.
        return False

    def read_key(self, timeout: Optional[float] = None) -> Optional[str]:
        # A non-blocking poll while work runs (S5, S8): the person has typed only
        # an interruption so far; other scripted keys belong to the next screen.
        if timeout == 0 and self._keys and self._keys[0] != "ctrl-c":
            return None
        if self._keys:
            key = self._keys.popleft()
            if key == "tick":
                if self._on_idle and timeout:
                    self._on_idle(timeout)
                return None if timeout is not None else self.read_key(timeout)
            self._idle = 0
            return key
        if timeout is None:
            raise ScriptExhausted("no keys left; last frame:\n" + self.last)
        self._idle += 1
        if self._idle > self._max_idle:
            raise ScriptExhausted("screen idles forever; last frame:\n" + self.last)
        if self._on_idle:
            self._on_idle(timeout)
        return None

    @contextmanager
    def suspend(self, message: str = "") -> Iterator[None]:
        self.suspended += 1
        self.messages.append(message)
        yield

    def close(self) -> None:
        pass

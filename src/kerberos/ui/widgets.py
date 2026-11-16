"""Widgets (tech.md §14.4).

Each widget renders with Rich; interactive ones take key names from the
Terminal port through `handle(key)`. Widgets never read keys themselves and
never print: the app draws whole frames through the terminal.
Texts arrive already masked (`Masker`) and come from copy.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from rich import box
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from kerberos.copy import t
from kerberos.ui.keys import hotkey
from kerberos.ui.logo import big_number
from kerberos.ui.palette import (
    SYMBOL_FAIL,
    SYMBOL_OK,
    SYMBOL_RISK,
    SYMBOL_ROLLED_BACK,
    SYMBOL_RUNNING,
    risk_style,
    score_style,
)

Body = Union[RenderableType, Callable[[int, int], RenderableType]]
KeyHints = Sequence[tuple[str, str]]

POINTER = "›"


def text(value: Union[str, Text], style: str = "") -> Text:
    """Plain Text from a string; never parsed as markup."""
    if isinstance(value, Text):
        return value
    return Text(value, style=style)


class Screen:
    """Frame of every screen: header, body, footer with the keys of this screen."""

    def __init__(
        self,
        title: str,
        body: Body,
        keys: KeyHints = (),
        *,
        flags: Sequence[str] = (),
    ) -> None:
        self.title = title
        self.body = body
        self.keys = keys
        self.flags = flags

    @staticmethod
    def chrome_height() -> int:
        """Lines taken by header, rules and footer."""
        return 4

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        height = options.height or console.height
        header = Table.grid(expand=True)
        header.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        header.add_column(justify="right", no_wrap=True)
        header.add_row(
            Text.assemble((t("app.name"), "accent"), "  ", (self.title, "bold")),
            Text(" · ".join(self.flags), style="muted"),
        )
        footer = Text(no_wrap=True, overflow="ellipsis")
        for i, (glyph, label) in enumerate(self.keys):
            if i:
                footer.append("  ")
            footer.append(glyph, style="bold")
            footer.append(" " + label, style="muted")
        body_height = max(1, height - self.chrome_height())
        body = self.body(max(10, width - 2), body_height) if callable(self.body) else self.body
        parts: list[tuple[RenderableType, int]] = [
            (header, 1),
            (Rule(style="muted"), 1),
            (Padding(body, (0, 1)), body_height),
            (Rule(style="muted"), 1),
            (footer, 1),
        ]
        first = True
        for renderable, lines_count in parts:
            lines = console.render_lines(
                renderable, options.update(width=width, height=lines_count), pad=True
            )
            for line in lines:
                if not first:
                    yield Segment.line()
                first = False
                yield from line


class Menu:
    """Choice of one item: ↑ ↓ move, Enter or the item number selects."""

    def __init__(self, items: Sequence[tuple[str, str, str]], selected: int = 0) -> None:
        self.items = list(items)
        self.selected = selected

    def handle(self, key: str) -> Optional[str]:
        if not self.items:
            return None
        if key == "up":
            self.selected = (self.selected - 1) % len(self.items)
        elif key == "down":
            self.selected = (self.selected + 1) % len(self.items)
        elif key == "enter":
            return self.items[self.selected][0]
        elif len(key) == 1 and key.isdigit() and 1 <= int(key) <= len(self.items):
            self.selected = int(key) - 1
            return self.items[self.selected][0]
        return None

    def __rich__(self) -> RenderableType:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column(no_wrap=True, overflow="ellipsis")
        grid.add_column(overflow="ellipsis")
        for i, (_key, label, hint) in enumerate(self.items):
            current = i == self.selected
            grid.add_row(
                Text(POINTER if current else " ", style="accent"),
                Text(label, style="accent" if current else ""),
                Text(hint or "", style="muted"),
            )
        return grid


def _scroll(offset: int, cursor: int, visible: int) -> int:
    if cursor < offset:
        return cursor
    if cursor >= offset + visible:
        return cursor - visible + 1
    return offset


class Checklist:
    """Table with marks (S3, S7): Space marks, `a` marks all, Enter goes on.

    Disabled rows are muted, never get a mark and the cursor skips them.
    """

    def __init__(
        self,
        rows: Sequence[Sequence[Union[str, Text]]],
        columns: Sequence[str],
        selected: Optional[set[int]] = None,
        disabled: Optional[set[int]] = None,
    ) -> None:
        self.rows = [list(r) for r in rows]
        self.columns = list(columns)
        self.disabled = set(disabled or ())
        self.selected = set(selected or ()) - self.disabled
        enabled = self.enabled
        self.cursor = enabled[0] if enabled else 0
        self.viewport: Optional[int] = None
        self._offset = 0

    @property
    def enabled(self) -> list[int]:
        return [i for i in range(len(self.rows)) if i not in self.disabled]

    def _move(self, step: int) -> None:
        enabled = self.enabled
        if not enabled:
            return
        if self.cursor not in enabled:
            self.cursor = enabled[0]
            return
        idx = enabled.index(self.cursor) + step
        self.cursor = enabled[max(0, min(len(enabled) - 1, idx))]

    def handle(self, key: str) -> Optional[str]:
        if key == "up":
            self._move(-1)
        elif key == "down":
            self._move(1)
        elif key == "space":
            if self.cursor in self.enabled:
                self.selected ^= {self.cursor}
        elif hotkey(key) == "a":
            enabled = set(self.enabled)
            self.selected = set() if enabled <= self.selected else enabled
        elif key == "enter":
            return "done"
        return None

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        height = self.viewport or options.height or len(self.rows) + 3
        visible = max(1, height - 3)
        self._offset = _scroll(self._offset, self.cursor, visible)
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
        table.add_column("", no_wrap=True, width=5)
        for column in self.columns:
            table.add_column(column, no_wrap=True, overflow="ellipsis", header_style="muted")
        for i in range(self._offset, min(len(self.rows), self._offset + visible)):
            off = i in self.disabled
            mark = " - " if off else ("[✓]" if i in self.selected else "[ ]")
            pointer = POINTER if i == self.cursor and not off else " "
            style = "muted" if off else ("accent" if i == self.cursor else "")
            cells = [text(c) for c in self.rows[i]]
            table.add_row(Text(f"{pointer} {mark}"), *cells, style=style)
        yield table


class TextInput:
    """One-line input; `secret` hides the characters (passwords, tokens)."""

    def __init__(
        self,
        label: str,
        hint: str = "",
        secret: bool = False,
        validate: Optional[Callable[[str], Optional[str]]] = None,
        value: str = "",
    ) -> None:
        self.label = label
        self.hint = hint
        self.secret = secret
        self.validate = validate
        self.value = value
        self.pos = len(value)
        self.error: Optional[str] = None

    def handle(self, key: str) -> Optional[str]:
        """Return the value on Enter when it is valid; None otherwise."""
        if key == "enter":
            self.error = self.validate(self.value) if self.validate else None
            return None if self.error else self.value
        if key == "backspace":
            if self.pos > 0:
                self.value = self.value[: self.pos - 1] + self.value[self.pos :]
                self.pos -= 1
        elif key == "delete":
            self.value = self.value[: self.pos] + self.value[self.pos + 1 :]
        elif key == "left":
            self.pos = max(0, self.pos - 1)
        elif key == "right":
            self.pos = min(len(self.value), self.pos + 1)
        elif key == "home":
            self.pos = 0
        elif key == "end":
            self.pos = len(self.value)
        else:
            char = " " if key == "space" else key
            if len(char) != 1 or not char.isprintable():
                return None
            self.value = self.value[: self.pos] + char + self.value[self.pos :]
            self.pos += 1
        self.error = None
        return None

    def __rich__(self) -> RenderableType:
        shown = "•" * len(self.value) if self.secret else self.value
        line = Text(POINTER + " ", style="accent")
        line.append(shown[: self.pos])
        line.append(shown[self.pos] if self.pos < len(shown) else " ", style="reverse")
        line.append(shown[self.pos + 1 :])
        parts: list[RenderableType] = [Text(self.label, style="bold"), line]
        hint = self.hint
        if self.secret:
            hint = (hint + " " if hint else "") + t("input.hidden")
        if hint:
            parts.append(Text(hint, style="muted"))
        if self.error:
            parts.append(
                Text(f"{SYMBOL_FAIL} " + t("input.invalid", reason=self.error), style="risk.high")
            )
        return Group(*parts)


class Consent:
    """Consent screen of S7: only Enter on the accept button agrees."""

    def __init__(self, summary: RenderableType, accept_label: str, keys_hint: str = "") -> None:
        self.summary = summary
        self.accept_label = accept_label
        self.keys_hint = keys_hint

    @staticmethod
    def handle(key: str) -> bool:
        """True: accepted. Any other key returns to the plan."""
        return key == "enter"

    def __rich__(self) -> RenderableType:
        button = Panel(
            Text(f"{SYMBOL_OK} {self.accept_label}", style="ok"),
            box=box.HEAVY,
            border_style="ok",
            expand=False,
        )
        parts: list[RenderableType] = [self.summary, Text(""), button]
        if self.keys_hint:
            parts.append(Text(self.keys_hint, style="muted"))
        return Group(*parts)


STEP_VIEW = {
    "pending": ("·", "muted"),
    "running": (SYMBOL_RUNNING, "accent"),
    "ok": (SYMBOL_OK, "ok"),
    "failed": (SYMBOL_FAIL, "risk.high"),
    "rolled_back": (SYMBOL_ROLLED_BACK, "risk.medium"),
    "skipped": ("–", "muted"),
}


class ProgressBoard:
    """Apply board of S8: nodes by rows, steps of the current fix by columns."""

    def __init__(self, nodes: Sequence[str], steps: Sequence[str]) -> None:
        self.nodes = list(nodes)
        self.steps = list(steps)
        self.cells: dict[tuple[str, str], str] = {}
        self.current: dict[str, str] = {n: "" for n in self.nodes}
        self.result: dict[str, Text] = {n: Text("") for n in self.nodes}
        self.node_title = ""
        self.fix_title = ""
        self.result_title = ""
        self.legend = ""

    def start(self, node: str, fix_label: str) -> None:
        self.current[node] = fix_label
        for step in self.steps:
            self.cells[(node, step)] = "pending"

    def set(self, node: str, step: str, state: str) -> None:
        self.cells[(node, step)] = state

    def finish(self, node: str, result: Text) -> None:
        self.result[node] = result

    def __rich__(self) -> RenderableType:
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
        table.add_column(self.node_title, no_wrap=True, overflow="ellipsis", header_style="muted")
        table.add_column(self.fix_title, no_wrap=True, overflow="ellipsis", header_style="muted")
        for step in self.steps:
            table.add_column(step, no_wrap=True, justify="center", header_style="muted")
        table.add_column(self.result_title, overflow="ellipsis", header_style="muted")
        for node in self.nodes:
            cells = []
            for step in self.steps:
                symbol, style = STEP_VIEW[self.cells.get((node, step), "pending")]
                cells.append(Text(symbol, style=style))
            table.add_row(Text(node), Text(self.current.get(node, "")), *cells, self.result[node])
        parts: list[RenderableType] = [table]
        if self.legend:
            parts.append(Text(self.legend, style="muted"))
        return Group(*parts)


class ScoreBadge:
    """Large score with the colour of §12.2 and a word, so it reads without colour."""

    def __init__(self, score: int, before: Optional[int] = None) -> None:
        self.score = max(0, min(100, score))
        self.before = before

    def level(self) -> str:
        if self.score >= 85:
            return t("score.green")
        if self.score >= 60:
            return t("score.yellow")
        return t("score.red")

    def __rich__(self) -> RenderableType:
        style = score_style(self.score)
        digits = Text("\n".join(big_number(self.score)), style=style)
        filled = self.score // 5
        bar = Text("█" * filled, style=style)
        bar.append("░" * (20 - filled), style="muted")
        lines: list[RenderableType] = [
            digits,
            Text(t("report.score", score=self.score), style="bold"),
            bar,
            Text(self.level(), style=style),
        ]
        if self.before is not None:
            lines.append(Text(t("score.before_after", before=self.before, score=self.score)))
        return Panel(Group(*lines), box=box.ROUNDED, border_style=style, expand=False)


@dataclass
class FindingItem:
    """One finding as the screen shows it; texts are ready and masked."""

    risk: str
    group: str
    target: str
    title: str
    threat: str
    action: str
    action_style: str = "muted"
    details: str = ""
    passed: bool = False
    extra: dict = field(default_factory=dict)


class FindingList:
    """Findings grouped by topic; Enter or Space opens the details of one."""

    def __init__(self, items: Sequence[FindingItem], group_by: str = "group") -> None:
        self.items = list(items)
        self.group_by = group_by
        self.cursor = 0
        self.expanded: set[int] = set()
        self.viewport: Optional[int] = None
        self._offset = 0

    def handle(self, key: str) -> Optional[str]:
        if not self.items:
            return None
        if key == "up":
            self.cursor = max(0, self.cursor - 1)
        elif key == "down":
            self.cursor = min(len(self.items) - 1, self.cursor + 1)
        elif key in ("space", "enter"):
            self.expanded ^= {self.cursor}
        return None

    def _block(self, i: int, item: FindingItem) -> list[Text]:
        current = i == self.cursor
        style = "ok" if item.passed else risk_style(item.risk)
        symbol = SYMBOL_OK if item.passed else SYMBOL_RISK
        head = Text(POINTER + " " if current else "  ", style="accent")
        head.append(f"{symbol} ", style=style)
        head.append(f"{t('risk.' + item.risk):<8} ", style=style)
        head.append(f"{item.target}  ", style="bold")
        head.append(item.title, style="accent" if current else "")
        lines = [head]
        if item.threat:
            lines.append(Text("    " + item.threat, style="muted"))
        if item.action:
            lines.append(Text("    " + item.action, style=item.action_style))
        if i in self.expanded and item.details:
            for detail in item.details.split("\n"):
                lines.append(Text("      " + detail, style="muted"))
        return lines

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        height = self.viewport or options.height or 10**6
        rendered: list[Text] = []
        start_of: dict[int, int] = {}
        end_of: dict[int, int] = {}
        group = None
        for i, item in enumerate(self.items):
            key = getattr(item, self.group_by)
            if key != group:
                if rendered:
                    rendered.append(Text(""))
                rendered.append(Text(key, style="bold"))
                group = key
            start_of[i] = len(rendered)
            for line in self._block(i, item):
                rendered.extend(line.wrap(console, width))
            end_of[i] = len(rendered)
        if self.items:
            start, end = start_of[self.cursor], end_of[self.cursor]
            if start < self._offset:
                self._offset = max(0, start - 1)
            elif end > self._offset + height:
                self._offset = end - height
        yield from rendered[self._offset : self._offset + height]


NOTICE_STYLE = {"info": "accent", "warning": "risk.medium", "error": "risk.high"}


class Notice:
    """Plate with a word in the title (info, warning, error): not colour alone."""

    def __init__(self, kind: str, text_value: str) -> None:
        self.kind = kind
        self.text = text_value

    def __rich__(self) -> RenderableType:
        style = NOTICE_STYLE.get(self.kind, "accent")
        title_style = "danger.bg" if self.kind == "error" else style
        return Panel(
            Text(self.text),
            title=Text(f" {t('notice.' + self.kind)} ", style=title_style),
            title_align="left",
            border_style=style,
            box=box.ROUNDED,
        )


class Pager:
    """Scrolling of a long text (full report on `s`)."""

    def __init__(self, text_value: str) -> None:
        self.text = text_value
        self.offset = 0
        self.viewport: Optional[int] = None
        self._page = 1
        self._total = 0

    def handle(self, key: str) -> Optional[str]:
        step = {"up": -1, "down": 1, "pgup": -self._page, "pgdn": self._page, "space": self._page}
        if key in step:
            self.offset += step[key]
        elif key == "home":
            self.offset = 0
        elif key == "end":
            self.offset = self._total
        self.offset = max(0, min(self.offset, max(0, self._total - self._page)))
        return None

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        height = self.viewport or options.height or 20
        lines: list[Text] = []
        for raw in self.text.split("\n"):
            wrapped = Text(raw).wrap(console, width)
            lines.extend(wrapped if len(wrapped) else [Text("")])
        self._page = max(1, height - 1)
        self._total = len(lines)
        self.offset = max(0, min(self.offset, max(0, self._total - self._page)))
        yield from lines[self.offset : self.offset + self._page]
        end = min(self._total, self.offset + self._page)
        yield Text(
            t("pager.position", start=self.offset + 1, end=end, total=self._total), style="muted"
        )

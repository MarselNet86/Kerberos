"""Shared builders for app-level tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.demo.fleet import build_host, build_nodes, build_panel
from kerberos.host import FakeHost
from kerberos.mask import Masker
from kerberos.nodes.fake import FakeNode, FakeTransport
from kerberos.panel.fake import FakePanel
from kerberos.state import State
from kerberos.ui.terminal import FakeTerminal

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = ROOT / "tests" / "snapshots"


def assert_snapshot(name: str, text: str) -> None:
    """Compare with tests/snapshots/<name>.txt; KERBEROS_UPDATE_SNAPSHOTS=1 rewrites it."""
    path = SNAPSHOTS / f"{name}.txt"
    if os.environ.get("KERBEROS_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        return
    assert path.exists(), f"no snapshot {path}; run with KERBEROS_UPDATE_SNAPSHOTS=1"
    expected = path.read_text(encoding="utf-8").rstrip("\n")
    assert text == expected, f"snapshot {name} differs"


def flat(frame: str) -> str:
    """Frame text without box borders and line breaks: wrapped plates read as one line."""
    import re

    text = re.sub(r"[│╭╮╰╯─]", " ", frame)
    return re.sub(r"\s+", " ", text)


def seen(term, text: str) -> bool:
    return any(text in flat(frame) for frame in term.frames)


LOGIN = ["enter"]  # S1: «Проверка» is the first item


def typed(text: str) -> list[str]:
    return ["space" if ch == " " else ch for ch in text]


def login_keys(user: str = "admin", password: str = "admin-password") -> list[str]:
    return typed(user) + ["enter"] + typed(password) + ["enter"]


def make_app(
    keys: Sequence[str],
    *,
    width: int = 100,
    height: int = 30,
    demo: bool = True,
    mask: bool = False,
    panel: Optional[FakePanel] = None,
    host: Optional[FakeHost] = None,
    nodes: Optional[list[FakeNode]] = None,
    state: Optional[State] = None,
) -> tuple[App, FakeTerminal]:
    clock = FakeClock()
    term = FakeTerminal(keys, width=width, height=height, on_idle=clock.advance)
    env = Env(terminal=term, clock=clock, masker=Masker(mask), demo=demo)
    env.host = host if host is not None else build_host()
    env.panel_transport = panel if panel is not None else build_panel()
    env.state = state or State(Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    env.transport = FakeTransport(nodes if nodes is not None else build_nodes(), env.state)
    return App(env), term

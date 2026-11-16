"""Shared builders for app-level tests."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Optional

from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.demo.fleet import build_host, build_panel
from kerberos.host import FakeHost
from kerberos.mask import Masker
from kerberos.panel.fake import FakePanel
from kerberos.ui.terminal import FakeTerminal

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
) -> tuple[App, FakeTerminal]:
    clock = FakeClock()
    term = FakeTerminal(keys, width=width, height=height, on_idle=clock.advance)
    env = Env(terminal=term, clock=clock, masker=Masker(mask), demo=demo)
    env.host = host if host is not None else build_host()
    env.panel_transport = panel if panel is not None else build_panel()
    return App(env), term

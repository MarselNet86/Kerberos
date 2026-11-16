"""Shared builders for app-level tests."""

from __future__ import annotations

from collections.abc import Sequence

from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.mask import Masker
from kerberos.ui.terminal import FakeTerminal


def make_app(
    keys: Sequence[str],
    *,
    width: int = 100,
    height: int = 30,
    demo: bool = True,
    mask: bool = False,
) -> tuple[App, FakeTerminal]:
    clock = FakeClock()
    term = FakeTerminal(keys, width=width, height=height, on_idle=clock.advance)
    env = Env(terminal=term, clock=clock, masker=Masker(mask), demo=demo)
    return App(env), term

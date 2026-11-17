"""Shared builders for app-level tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Optional

from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.demo.fleet import build_host, build_nodes, build_panel
from kerberos.demo.nodes import auth_methods_of, build_prober, build_whois
from kerberos.demo.xui import attach_xui
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


TOKEN = "rw-test-token"  # the demo panel takes any API token (§7.3)


def login_keys(token: str = TOKEN) -> list[str]:
    """S2 with no saved token: the API token typed in, then Enter."""
    return typed(token) + ["enter"]


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
    panel_kind: Optional[str] = "remnawave",
) -> tuple[App, FakeTerminal]:
    clock = FakeClock()
    term = FakeTerminal(keys, width=width, height=height, on_idle=clock.advance)
    env = Env(terminal=term, clock=clock, masker=Masker(mask), demo=demo)
    env.host = host if host is not None else build_host()
    env.panel_transport = panel if panel is not None else build_panel()
    env.state = state or State(Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    env.transport = FakeTransport(nodes if nodes is not None else build_nodes(), env.state)
    env.prober = build_prober(env.panel_transport, list(env.transport.nodes.values()))
    env.prober.auth = auth_methods_of(list(env.transport.nodes.values()))
    env.whois = build_whois()
    # Scenarios of Remnawave skip the question of S2; tests of the choice pass None.
    env.panel_kind = panel_kind
    attach_xui(env)
    return App(env), term


@cache
def plan_rows() -> tuple[tuple[str, str], ...]:
    """S7 rows of the demo fleet as (who, fixId) in screen order, as TO_PLAN reaches it.

    `who` is the node name for node targets, else host, template or panel. Reserve
    rows appear only after `r`, so they are not here.
    """
    from demo_input import demo_input

    from kerberos.checks import run_checks
    from kerberos.fixes.plan import build_plan

    _env, data = demo_input()
    admin = {"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]}
    names = {n.node.uuid: n.node.name for n in data.nodes}
    rows = []
    for item in build_plan(run_checks(data), data, admin, {}):
        kind, _, ref = item.target.partition(":")
        rows.append((names.get(ref, ref) if kind == "node" else kind, item.fix_id))
    return tuple(rows)


def row_of(who: str, fix_id: str) -> int:
    """Index of a row of S7: how many times to press ↓ from the top."""
    return plan_rows().index((who, fix_id))

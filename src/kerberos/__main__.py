"""Command line (tech.md §5.3)."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

from kerberos import __version__
from kerberos.copy import t

COMMANDS = ("check", "fix", "rollback", "report", "finalize", "ssh")
WITH_OPTIONAL_RUN = ("rollback", "report", "finalize")
WITHOUT_TTY = ("report", "finalize")


@dataclass
class Options:
    command: Optional[str] = None
    arg: Optional[str] = None
    demo: bool = False
    mask: bool = False
    color: bool = True
    help: bool = False
    version: bool = False
    panel: Optional[str] = None  # --panel remnawave|3x-ui (§7.6)


class UsageError(Exception):
    pass


def parse_args(argv: Sequence[str], environ: Optional[dict] = None) -> Options:
    environ = os.environ if environ is None else environ
    opts = Options()
    positional: list[str] = []
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "--panel" or arg.startswith("--panel="):
            value = arg.split("=", 1)[1] if "=" in arg else (args.pop(0) if args else "")
            if value not in ("remnawave", "3x-ui"):
                raise UsageError(t("cli.bad_panel", value=value))
            opts.panel = value
        elif arg == "--demo":
            opts.demo = True
        elif arg == "--mask":
            opts.mask = True
        elif arg == "--no-color":
            opts.color = False
        elif arg in ("--help", "-h"):
            opts.help = True
        elif arg == "--version":
            opts.version = True
        elif arg.startswith("-") and arg != "-":
            raise UsageError(t("cli.unknown_flag", flag=arg))
        else:
            positional.append(arg)
    if positional:
        command, rest = positional[0], positional[1:]
        if command not in COMMANDS:
            raise UsageError(t("cli.unknown_command", command=command))
        opts.command = command
        if command in WITH_OPTIONAL_RUN:
            if len(rest) > 1:
                raise UsageError(t("cli.extra_arg", arg=rest[1]))
            opts.arg = rest[0] if rest else None
        elif command == "ssh":
            if not rest:
                raise UsageError(t("cli.missing_node"))
            if len(rest) > 1:
                raise UsageError(t("cli.extra_arg", arg=rest[1]))
            opts.arg = rest[0]
        elif rest:
            raise UsageError(t("cli.extra_arg", arg=rest[0]))
    # https://no-color.org: any non-empty value turns colour off.
    if environ.get("NO_COLOR"):
        opts.color = False
    return opts


def _utf8_streams() -> None:
    """Russian texts must not crash on a server whose locale is not UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if enc != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: Optional[Sequence[str]] = None) -> int:
    _utf8_streams()
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        opts = parse_args(argv)
    except UsageError as exc:
        print(t("cli.bad_args", detail=exc), file=sys.stderr)
        print(t("cli.usage"), file=sys.stderr)
        return 2
    if opts.help:
        print(t("cli.help"))
        return 0
    if opts.version:
        print(t("cli.version", version=__version__))
        return 0
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    if not tty:
        if opts.command == "report":
            return print_report(opts)
        if opts.command == "finalize":
            return finalize_unattended(opts)
        print(t("cli.no_tty"), file=sys.stderr)
        return 2

    if opts.command == "ssh":
        return admin_ssh(opts)

    from kerberos.app import App, Env
    from kerberos.clock import SystemClock
    from kerberos.mask import Masker
    from kerberos.state import Locked
    from kerberos.ui.terminal import LiveTerminal

    env = Env(terminal=None, clock=SystemClock(), masker=Masker(opts.mask), demo=opts.demo)
    env.panel_kind = opts.panel
    if opts.demo:
        from kerberos.demo.fleet import attach

        attach(env)
    else:
        from kerberos.host import LiveHost
        from kerberos.nodes.transport import SshTransport
        from kerberos.panel.client import urllib_transport
        from kerberos.panel.xui import XuiSession
        from kerberos.probe import LiveProber
        from kerberos.state import State
        from kerberos.whois import CymruWhois

        env.host = LiveHost()
        env.panel_transport = urllib_transport
        env.xui_transport = XuiSession()
        env.state = State()
        env.transport = SshTransport(env.state)
        env.prober = LiveProber()
        env.whois = CymruWhois()
    try:
        with env.state.lock():
            env.terminal = LiveTerminal(color=opts.color)
            try:
                return App(env).run(opts.command, opts.arg)
            finally:
                env.terminal.close()
    except Locked:
        print(t("lock.busy"), file=sys.stderr)
        return 2


def finalize_unattended(opts: Options, state=None) -> int:
    """`kerberos finalize` from the systemd timer: no terminal, the saved token."""
    from kerberos.clock import SystemClock
    from kerberos.fixes.finalize import unattended
    from kerberos.fixes.journal import RunStore
    from kerberos.panel.client import urllib_transport
    from kerberos.state import State

    clock = SystemClock()
    return unattended(RunStore(state or State(), clock), urllib_transport, clock, opts.arg)


def print_report(opts: Options, state=None) -> int:
    """`kerberos report` without a terminal: report.md to stdout (§5.3)."""
    from kerberos.clock import SystemClock
    from kerberos.fixes.journal import RunStore
    from kerberos.mask import Masker
    from kerberos.state import State

    store = RunStore(state or State(), SystemClock())
    run_id = opts.arg
    if run_id is None:
        runs = store.runs()
        run_id = runs[0]["runId"] if runs else None
    text = store.report_text(run_id) if run_id else None
    if text is None:
        print(t("report.empty"), file=sys.stderr)
        return 2
    print(Masker(opts.mask)(text), end="")
    return 0


def admin_ssh(opts: Options) -> int:
    """`kerberos ssh <node>`: log in with the administrator key (§8.5)."""
    if opts.demo:
        print(t("ssh.demo"))
        return 0
    from kerberos.nodes.transport import SshTransport
    from kerberos.state import State

    state = State()
    record = state.find_node(opts.arg or "")
    if record is None:
        print(t("ssh.unknown_node", node=opts.arg), file=sys.stderr)
        return 2
    if not state.admin_key.exists():
        print(t("ssh.no_admin_key"), file=sys.stderr)
        return 2
    return SshTransport(state).admin_shell(record.target(record.address))


if __name__ == "__main__":
    sys.exit(main())

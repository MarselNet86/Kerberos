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


class UsageError(Exception):
    pass


def parse_args(argv: Sequence[str], environ: Optional[dict] = None) -> Options:
    environ = os.environ if environ is None else environ
    opts = Options()
    positional: list[str] = []
    for arg in argv:
        if arg == "--demo":
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
        if opts.command in WITHOUT_TTY:
            print(t("app.soon"))
            return 0
        print(t("cli.no_tty"), file=sys.stderr)
        return 2

    from kerberos.app import App, Env
    from kerberos.clock import SystemClock
    from kerberos.mask import Masker
    from kerberos.ui.terminal import LiveTerminal

    terminal = LiveTerminal(color=opts.color)
    env = Env(terminal=terminal, clock=SystemClock(), masker=Masker(opts.mask), demo=opts.demo)
    try:
        return App(env).run(opts.command, opts.arg)
    finally:
        terminal.close()


if __name__ == "__main__":
    sys.exit(main())

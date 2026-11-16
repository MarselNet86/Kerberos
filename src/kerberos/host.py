"""Host port: commands and files of the panel server itself (tech.md §4).

KERBEROS runs on the panel server and asks it a few things: docker for the
panel (§7.1), ssh-keygen and ssh-keyscan (§8), sshd -T for its own SSH, the
hostname. Live runs subprocesses; the fake answers from a table, so tests
and --demo never touch the machine they run on.
"""

from __future__ import annotations

import socket
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Union


@dataclass
class CommandResult:
    code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.code == 0


class Host(Protocol):
    def run(
        self, argv: Sequence[str], *, input: Optional[str] = None, timeout: float = 60
    ) -> CommandResult: ...

    def read_env_keys(self, path: str, keys: Sequence[str]) -> dict[str, str]: ...

    def read_text(self, path: str) -> Optional[str]: ...

    def hostname(self) -> str: ...


def parse_env_keys(text: str, keys: Sequence[str]) -> dict[str, str]:
    """Values of `keys` only; every other line of the file is skipped unread."""
    wanted = set(keys)
    found: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        if not sep or name.strip() not in wanted:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        found[name.strip()] = value
    return found


class LiveHost:
    def run(
        self, argv: Sequence[str], *, input: Optional[str] = None, timeout: float = 60
    ) -> CommandResult:
        try:
            proc = subprocess.run(
                list(argv),
                input=input,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", f"{argv[0]}: timeout")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def read_env_keys(self, path: str, keys: Sequence[str]) -> dict[str, str]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return parse_env_keys(fh.read(), keys)
        except OSError:
            return {}

    def read_text(self, path: str) -> Optional[str]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def hostname(self) -> str:
        return socket.gethostname()


Responder = Union[CommandResult, Callable[[Sequence[str], Optional[str]], CommandResult]]


@dataclass
class FakeHost:
    """Commands answered by the longest matching argv prefix; files from a dict."""

    commands: dict[tuple[str, ...], Responder] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    name: str = "panel"
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def on(self, prefix: Sequence[str], result: Responder) -> None:
        self.commands[tuple(prefix)] = result

    def run(
        self, argv: Sequence[str], *, input: Optional[str] = None, timeout: float = 60
    ) -> CommandResult:
        argv = tuple(argv)
        self.calls.append(argv)
        best: Optional[tuple[str, ...]] = None
        for prefix in self.commands:
            if argv[: len(prefix)] == prefix and (best is None or len(prefix) > len(best)):
                best = prefix
        if best is None:
            return CommandResult(127, "", f"{argv[0]}: not found")
        responder = self.commands[best]
        return responder(argv, input) if callable(responder) else responder

    def read_env_keys(self, path: str, keys: Sequence[str]) -> dict[str, str]:
        text = self.files.get(path)
        return parse_env_keys(text, keys) if text is not None else {}

    def read_text(self, path: str) -> Optional[str]:
        return self.files.get(path)

    def hostname(self) -> str:
        return self.name

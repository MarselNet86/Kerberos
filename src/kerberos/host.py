"""Host port: commands and files of the panel server itself (tech.md §4).

KERBEROS runs on the panel server and asks it a few things: docker for the
panel (§7.1), ssh-keygen and ssh-keyscan (§8), sshd -T for its own SSH, the
hostname. The portal in front of the panel (§10.10) also writes files there:
Caddyfile, compose, an env file. Live runs subprocesses and touches the disk;
the fake answers from a table, so tests and --demo never touch the machine
they run on.
"""

from __future__ import annotations

import os
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

    def write_text(self, path: str, text: str, mode: Optional[int] = None) -> None: ...

    def file_mode(self, path: str) -> Optional[int]: ...

    def remove(self, path: str) -> None: ...

    def read_settings(self, path: str, keys: Sequence[str]) -> Optional[dict[str, str]]: ...

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

    def write_text(self, path: str, text: str, mode: Optional[int] = None) -> None:
        """Atomically, with `mode` (or the file's own one, or 0644 for a new file)."""
        keep = self.file_mode(path)
        tmp = f"{path}.kerberos-tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode if mode is not None else (keep if keep is not None else 0o644))
        os.replace(tmp, path)

    def file_mode(self, path: str) -> Optional[int]:
        try:
            return os.stat(path).st_mode & 0o7777
        except OSError:
            return None

    def remove(self, path: str) -> None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def hostname(self) -> str:
        return socket.gethostname()

    def read_settings(self, path: str, keys: Sequence[str]) -> Optional[dict[str, str]]:
        """Only the named keys of the `settings` table, read-only (3x-ui, §7.6).

        None: no database or no sqlite3 module (python3-minimal lacks it).
        """
        try:
            import sqlite3
        except ImportError:
            return None
        if not os.path.exists(path):
            return None
        marks = ",".join("?" for _ in keys)
        try:
            db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
            try:
                rows = db.execute(
                    "SELECT key, value FROM settings WHERE key IN (" + marks + ")", list(keys)
                ).fetchall()
            finally:
                db.close()
        except sqlite3.Error:
            return None
        return {str(key): "" if value is None else str(value) for key, value in rows}


Responder = Union[CommandResult, Callable[[Sequence[str], Optional[str]], CommandResult]]


@dataclass
class FakeHost:
    """Commands answered by the longest matching argv prefix; files from a dict."""

    commands: dict[tuple[str, ...], Responder] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    modes: dict[str, int] = field(default_factory=dict)
    name: str = "panel"
    databases: dict[str, dict[str, str]] = field(default_factory=dict)  # path -> settings
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

    def write_text(self, path: str, text: str, mode: Optional[int] = None) -> None:
        keep = self.modes.get(path, 0o644 if path not in self.files else 0o644)
        self.files[path] = text
        self.modes[path] = mode if mode is not None else keep

    def file_mode(self, path: str) -> Optional[int]:
        return self.modes.get(path, 0o644) if path in self.files else None

    def remove(self, path: str) -> None:
        self.files.pop(path, None)
        self.modes.pop(path, None)

    def hostname(self) -> str:
        return self.name

    def read_settings(self, path: str, keys: Sequence[str]) -> Optional[dict[str, str]]:
        table = self.databases.get(path)
        if table is None:
            return None
        return {key: table[key] for key in keys if key in table}

#!/usr/bin/env python3
"""KERBEROS agent (tech.md §9): one file, Python 3.9+, standard library only.

Installed on a node as /usr/local/sbin/kerberos-agent and reached only
through the restricted KERBEROS key (`command=` in authorized_keys), so the
requested command arrives in SSH_ORIGINAL_COMMAND. The rollback timer of
systemd calls it with arguments instead. Only the commands of §9.1 are
accepted; parameters are checked with regular expressions and data comes as
JSON on stdin. The answer is one JSON object on stdout; on an error the exit
code is not 0 and the body is {"error": {"code", "message"}}.

Every function works on a `System`: the root of the file system and the
command runner, so tests run the same code against a temporary directory
and recorded command outputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from typing import Any, Callable, Optional

PROTOCOL = 1
AGENT_VERSION = "0.2.0"
AGENT_PATH = "/usr/local/sbin/kerberos-agent"
STATE_DIR = "/var/lib/kerberos"

ERROR_CODES = frozenset(
    """bad_params unknown_command sha_mismatch no_admin_key sshd_test_failed ssh_port
    port_busy bridge_network docker_published mptcp_absent port80_busy certbot_failed
    nginx_test_failed realip_enabled apt_failed change_conflict no_backup backup_damaged
    not_implemented""".split()
)

FIX_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
CHANGE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AgentError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown agent error code {code}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Result:
    def __init__(self, code: int, stdout: str = "", stderr: str = "") -> None:
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.code == 0


def run_command(argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
    try:
        proc = subprocess.run(
            argv,
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
    except FileNotFoundError:
        return Result(127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return Result(124, "", f"{argv[0]}: timeout")
    return Result(proc.returncode, proc.stdout, proc.stderr)


class System:
    """File system root, command runner and environment of one agent call."""

    def __init__(
        self,
        root: str = "/",
        run: Callable[..., Result] = run_command,
        environ: Optional[dict] = None,
    ) -> None:
        self.root = root
        self._run = run
        self.environ = dict(os.environ if environ is None else environ)

    def path(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.path(path))

    def read(self, path: str) -> Optional[str]:
        try:
            with open(self.path(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def read_bytes(self, path: str) -> Optional[bytes]:
        try:
            with open(self.path(path), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def write_bytes(self, path: str, data: bytes, mode: int) -> None:
        """Atomic write: a temporary file in the same directory, then rename."""
        full = self.path(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = f"{full}.kerberos-tmp-{os.getpid()}"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, full)

    def write(self, path: str, text: str, mode: int = 0o644) -> None:
        self.write_bytes(path, text.encode("utf-8"), mode)

    def run(self, argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
        return self._run(argv, input=input, timeout=timeout)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def own_source(system: System) -> bytes:
    data = system.read_bytes(AGENT_PATH)
    if data is None:
        with open(os.path.abspath(__file__), "rb") as fh:
            data = fh.read()
    return data


# -- commands ---------------------------------------------------------------
def cmd_version(system: System, args: list[str], data: Any) -> dict:
    return {
        "protocol": PROTOCOL,
        "agent": AGENT_VERSION,
        "sha256": sha256_bytes(own_source(system)),
    }


VERSION_RE = re.compile(rb'^AGENT_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.M)


def cmd_update(system: System, args: list[str], data: bytes) -> dict:
    expected = args[0]
    if sha256_bytes(data) != expected:
        raise AgentError("sha_mismatch", "the new agent file does not match its sha256")
    match = VERSION_RE.search(data)
    if not match:
        raise AgentError("bad_params", "the new file is not a KERBEROS agent")
    system.write_bytes(AGENT_PATH, data, 0o755)
    if sha256_bytes(system.read_bytes(AGENT_PATH) or b"") != expected:
        raise AgentError("sha_mismatch", "the written agent differs from the sent one")
    return {"agent": match.group(1).decode()}


def not_implemented(system: System, args: list[str], data: Any) -> dict:
    raise AgentError("not_implemented", "this agent does not support the command yet")


# name -> (handler, argument patterns, stdin: None | "json" | "bytes")
COMMANDS: dict[str, tuple[Callable[[System, list[str], Any], dict], tuple, Optional[str]]] = {
    "version": (cmd_version, (), None),
    "facts": (not_implemented, (), None),
    "watch": (not_implemented, (), None),
    "site-check": (not_implemented, (), "json"),
    "edge-sources": (not_implemented, (), "json"),
    "plan": (not_implemented, (FIX_ID,), "json"),
    "apply": (not_implemented, (FIX_ID, CHANGE_ID), "json"),
    "confirm": (not_implemented, (CHANGE_ID,), None),
    "rollback": (not_implemented, (CHANGE_ID,), None),
    "update": (cmd_update, (SHA256,), "bytes"),
}


def dispatch(system: System, words: list[str], stdin: bytes) -> dict:
    if not words:
        raise AgentError("unknown_command", "no command")
    name, args = words[0], words[1:]
    if name not in COMMANDS:
        raise AgentError("unknown_command", name)
    handler, patterns, stdin_kind = COMMANDS[name]
    if len(args) != len(patterns) or not all(p.match(a) for p, a in zip(patterns, args)):
        raise AgentError("bad_params", f"{name} expects {len(patterns)} valid arguments")
    data: Any = None
    if stdin_kind == "bytes":
        data = stdin
    elif stdin_kind == "json":
        try:
            data = json.loads(stdin.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentError("bad_params", "stdin is not JSON") from exc
        if not isinstance(data, dict):
            raise AgentError("bad_params", "stdin must be a JSON object")
    return handler(system, args, data)


def command_words(argv: list[str], environ: dict) -> list[str]:
    if argv:
        return list(argv)
    try:
        return shlex.split(environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError as exc:
        raise AgentError("bad_params", "cannot parse the command") from exc


def main(
    argv: Optional[list[str]] = None,
    system: Optional[System] = None,
    stdin: Optional[bytes] = None,
    out: Any = None,
) -> int:
    system = system or System()
    out = out or sys.stdout
    argv = sys.argv[1:] if argv is None else argv
    try:
        words = command_words(argv, system.environ)
        needs_stdin = bool(words) and COMMANDS.get(words[0], (None, (), None))[2] is not None
        if stdin is None:
            stdin = sys.stdin.buffer.read() if needs_stdin else b""
        answer = dispatch(system, words, stdin)
    except AgentError as exc:
        out.write(json.dumps({"error": {"code": exc.code, "message": exc.message}}) + "\n")
        return 1
    out.write(json.dumps(answer, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

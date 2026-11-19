"""NodeTransport port (tech.md §8): SSH to the nodes; live system ssh, fake in tests.

Agent commands go with the KERBEROS key through one ControlMaster per node
(socket in /run/kerberos/). Bootstrap uses a separate master opened either
with the root keys of the panel server and a key forwarded with `ssh -A`
(BatchMode) or interactively: the terminal is handed to `ssh`, which reads the
node password itself, so KERBEROS never sees it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from kerberos.host import CommandResult
from kerberos.nodes.keys import PublicKey, scan_key
from kerberos.state import State

RUN_DIR = "/run/kerberos"
AGENT_TIMEOUT = 120
APT_TIMEOUT = 600
# Commands that change a node may install packages (the agent gives apt at most
# APT_TIMEOUT in all), run certbot and wait for the agent's lock: KERBEROS waits longer
# than the agent can work, or a slow apt looks like a failure while it goes on.
CHANGE_TIMEOUT = APT_TIMEOUT + 600
CHANGE_COMMANDS = ("apply", "confirm", "rollback", "undo", "update")


class TransportError(Exception):
    """SSH itself failed: refused, timeout, unreachable, auth, hostkey_changed, failed."""

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}".strip())
        self.kind = kind
        self.message = message


class NodeAgentError(Exception):
    """The agent answered with an error code of §9.2."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}".strip())
        self.code = code
        self.message = message


@dataclass
class Target:
    uuid: str
    name: str
    address: str
    port: int = 22


class NodeTransport(Protocol):
    def keyscan(self, address: str, port: int) -> Optional[PublicKey]: ...

    def open_root(self, target: Target, *, interactive: bool) -> bool: ...

    def offered_methods(self, target: Target) -> Optional[list[str]]:
        """How root may log in, as the node said when the key login failed; None: unknown."""
        ...

    @property
    def agent_forwarded(self) -> bool:
        """A key forwarded with `ssh -A` is there for the key login (§8.2)."""
        ...

    def root_run(
        self, target: Target, command: str, stdin: Optional[str] = None, timeout: float = 120
    ) -> CommandResult: ...

    def close_root(self, target: Target) -> None: ...

    def agent(
        self,
        target: Target,
        command: str,
        payload: Optional[dict] = None,
        *,
        data: Optional[bytes] = None,
        timeout: float = AGENT_TIMEOUT,
        fresh: bool = False,
    ) -> dict: ...

    def admin_shell(self, target: Target) -> int: ...

    def close(self) -> None: ...


def ssh_host(address: str, resolve: Optional[Callable[[str], list]] = None) -> str:
    """§8.2: a node given by name is reached on the IPv4 of the name. Over IPv6 the node
    would see the panel server at another address than the panel's own connections to
    the node API, and node_api.panel_only would let the wrong one in."""
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        pass
    found = [str(a) for a in (resolve(address) if resolve is not None else [])]
    return next((a for a in found if ":" not in a), address)


def classify(stderr: str) -> str:
    text = stderr.lower()
    if "remote host identification has changed" in text or "host key verification failed" in text:
        return "hostkey_changed"
    if "permission denied" in text or "too many authentication failures" in text:
        return "auth"
    if "connection refused" in text:
        return "refused"
    if "timed out" in text:
        return "timeout"
    if "no route to host" in text or "network is unreachable" in text or "resolve" in text:
        return "unreachable"
    return "failed"


def parse_answer(stdout: str) -> dict:
    """The agent prints one JSON object; take the last JSON line."""
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise TransportError("failed", "the agent printed no JSON")


def denied_methods(stderr: str) -> Optional[list[str]]:
    """«Permission denied (publickey,password)»: what the server still lets root try."""
    match = re.search(r"Permission denied \(([^)]*)\)", stderr)
    return [m.strip() for m in match.group(1).split(",") if m.strip()] if match else None


class SshTransport:
    def __init__(self, state: State) -> None:
        self.state = state
        self._used: dict[str, Target] = {}
        self._offered: dict[str, list[str]] = {}

    @property
    def agent_forwarded(self) -> bool:
        return bool(os.environ.get("SSH_AUTH_SOCK"))

    def offered_methods(self, target: Target) -> Optional[list[str]]:
        return self._offered.get(target.address)

    def _run_dir(self) -> str:
        os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
        os.chmod(RUN_DIR, 0o700)
        return RUN_DIR

    def _common(self, port: int) -> list[str]:
        return [
            "-F", "/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.state.known_hosts}",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=15",
            "-o", "LogLevel=ERROR",
            "-p", str(port),
        ]  # fmt: skip

    def _boot_socket(self, target: Target) -> str:
        return os.path.join(self._run_dir(), f"boot-{target.uuid[:12]}")

    def keyscan(self, address: str, port: int) -> Optional[PublicKey]:
        try:
            proc = subprocess.run(
                ["ssh-keyscan", "-T", "10", "-t", "ed25519", "-p", str(port), address],
                capture_output=True, text=True, timeout=30, check=False,
            )  # fmt: skip
        except (OSError, subprocess.TimeoutExpired):
            return None
        return scan_key(proc.stdout)

    def open_root(self, target: Target, *, interactive: bool) -> bool:
        argv = ["ssh", *self._common(target.port), "-M", "-S", self._boot_socket(target), "-fN"]
        argv += ["-o", "ControlPersist=300"]
        if interactive:
            argv += [
                "-o", "BatchMode=no",
                "-o", "PubkeyAuthentication=no",
                "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "NumberOfPasswordPrompts=3",
            ]  # fmt: skip
        else:
            # No IdentitiesOnly: the agent of `ssh -A` offers the person's own key (§8.2).
            argv += ["-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey"]
        argv.append(f"root@{target.address}")
        try:
            if interactive:
                return subprocess.run(argv, timeout=300, check=False).returncode == 0
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if proc.returncode != 0:
            methods = denied_methods(proc.stderr)
            if methods is not None:
                self._offered[target.address] = methods
        return proc.returncode == 0

    def root_run(
        self, target: Target, command: str, stdin: Optional[str] = None, timeout: float = 120
    ) -> CommandResult:
        argv = ["ssh", *self._common(target.port), "-S", self._boot_socket(target)]
        argv += ["-o", "ControlMaster=no", "-o", "BatchMode=yes", f"root@{target.address}", command]
        try:
            proc = subprocess.run(
                argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", "timeout")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def close_root(self, target: Target) -> None:
        argv = ["ssh", *self._common(target.port), "-S", self._boot_socket(target), "-O", "exit"]
        argv.append(f"root@{target.address}")
        subprocess.run(argv, capture_output=True, timeout=30, check=False)

    def _agent_argv(self, target: Target, command: str, fresh: bool) -> list[str]:
        argv = ["ssh", *self._common(target.port)]
        argv += ["-i", str(self.state.key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        if fresh:
            # A new connection proves that access works after a change (§11.3).
            argv += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        else:
            argv += ["-o", "ControlMaster=auto", "-o", f"ControlPath={self._run_dir()}/%C"]
            argv += ["-o", "ControlPersist=120"]
        return argv + [f"root@{target.address}", command]

    def agent(
        self,
        target: Target,
        command: str,
        payload: Optional[dict] = None,
        *,
        data: Optional[bytes] = None,
        timeout: float = AGENT_TIMEOUT,
        fresh: bool = False,
    ) -> dict:
        stdin = (
            data
            if data is not None
            else (json.dumps(payload).encode("utf-8") if payload is not None else b"")
        )
        if not fresh:
            self._used[f"{target.address}:{target.port}"] = target
        if command.split(" ", 1)[0] in CHANGE_COMMANDS:
            timeout = max(timeout, CHANGE_TIMEOUT)
        try:
            proc = subprocess.run(
                self._agent_argv(target, command, fresh),
                input=stdin, capture_output=True, timeout=timeout + 15, check=False,
            )  # fmt: skip
        except subprocess.TimeoutExpired as exc:
            raise TransportError("timeout", command.split()[0]) from exc
        stderr = proc.stderr.decode("utf-8", "replace")
        if proc.returncode == 255:
            raise TransportError(classify(stderr), stderr.strip()[:300])
        answer = parse_answer(proc.stdout.decode("utf-8", "replace"))
        error = answer.get("error")
        if isinstance(error, dict):
            raise NodeAgentError(str(error.get("code")), str(error.get("message", "")))
        return answer

    def admin_shell(self, target: Target) -> int:
        argv = ["ssh", *self._common(target.port), "-i", str(self.state.admin_key)]
        argv += ["-o", "IdentitiesOnly=yes", f"root@{target.address}"]
        return subprocess.call(argv)

    def close(self) -> None:
        for target in self._used.values():
            argv = ["ssh", *self._common(target.port), "-o", f"ControlPath={RUN_DIR}/%C"]
            argv += ["-O", "exit", f"root@{target.address}"]
            subprocess.run(argv, capture_output=True, timeout=30, check=False)
        self._used.clear()

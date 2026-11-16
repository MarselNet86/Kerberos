"""Fake nodes and the fake NodeTransport (tests and --demo).

A FakeNode models what KERBEROS can observe of a server: SSH port, host key,
how root may log in, python, authorized_keys and the installed agent. The
fake transport checks every call against the contract: agent commands and
their arguments must pass the real agent's command table, bootstrap scripts
must carry a payload, the pinned host key must match. A violation raises
ContractError, so a bug in KERBEROS fails the test instead of passing quietly.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from kerberos import agent as agent_module
from kerberos.host import CommandResult
from kerberos.nodes.bootstrap import INSTALL_PYTHON, NO_PYTHON, REMOTE_COMMAND, read_payload
from kerberos.nodes.keys import AGENT_PATH, PublicKey, parse_authorized_keys
from kerberos.nodes.transport import NodeAgentError, Target, TransportError
from kerberos.state import State


class ContractError(AssertionError):
    """KERBEROS used the node transport outside the contract of §8 and §9."""


@dataclass
class FakeNode:
    name: str
    address: str
    host_key: PublicKey
    ssh_port: int = 22
    reachable: bool = True
    root_keys: bool = False
    password_ok: bool = True
    python: bool = True
    panel_ip: str = "198.51.100.5"
    authorized_keys: list[str] = field(default_factory=list)
    agent_sha: Optional[str] = None
    agent_version: str = ""
    # Agent behaviour beyond version and update (facts, apply...): name -> handler
    handlers: dict[str, Callable[[FakeNode, list[str], Any], dict]] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def kerberos_keys(self) -> list[PublicKey]:
        return [k for k in parse_authorized_keys("\n".join(self.authorized_keys)) if k.is_kerberos]


class FakeTransport:
    def __init__(self, nodes: list[FakeNode], state: State) -> None:
        self.nodes = {n.address: n for n in nodes}
        self.state = state
        self.log: list[tuple[str, str]] = []
        self._root_open: set[str] = set()
        self.interactive_logins = 0

    # -- helpers -----------------------------------------------------------
    def _node(self, target: Target) -> FakeNode:
        node = self.nodes.get(target.address)
        if node is None or not node.reachable:
            raise TransportError("unreachable", target.address)
        if target.port in node.state.get("closed_ports", ()):
            raise TransportError("timeout", f"{target.address}:{target.port} is filtered")
        if target.port not in [node.ssh_port] + node.state.get("extra_ports", []):
            raise TransportError("refused", f"{target.address}:{target.port}")
        return node

    def _check_hostkey(self, target: Target, node: FakeNode) -> None:
        pinned = self.state.pinned(target.address, target.port)
        if pinned is None:
            raise ContractError(f"host key of {target.address} used before pinning")
        if pinned != node.host_key.blob:
            raise TransportError("hostkey_changed", "REMOTE HOST IDENTIFICATION HAS CHANGED")

    # -- port ------------------------------------------------------------
    def keyscan(self, address: str, port: int) -> Optional[PublicKey]:
        node = self.nodes.get(address)
        self.log.append((address, f"keyscan {port}"))
        if node is None or not node.reachable or port in node.state.get("closed_ports", ()):
            return None
        if port not in [node.ssh_port] + node.state.get("extra_ports", []):
            return None
        return node.host_key

    def open_root(self, target: Target, *, interactive: bool) -> bool:
        node = self._node(target)
        self._check_hostkey(target, node)
        self.log.append((target.address, "open_root interactive" if interactive else "open_root"))
        if interactive:
            self.interactive_logins += 1
        ok = node.password_ok if interactive else node.root_keys
        if ok:
            self._root_open.add(target.address)
        return ok

    def root_run(
        self, target: Target, command: str, stdin: Optional[str] = None, timeout: float = 120
    ) -> CommandResult:
        node = self._node(target)
        if target.address not in self._root_open:
            raise ContractError("root command without an open root session")
        self.log.append((target.address, f"root {command[:40]}"))
        if command == INSTALL_PYTHON:
            node.python = True
            return CommandResult(0)
        if command != REMOTE_COMMAND:
            raise ContractError(f"unexpected root command {command!r}")
        if not node.python:
            return CommandResult(NO_PYTHON)
        return self._bootstrap(node, stdin)

    def local_bootstrap(self, stdin: Optional[str]) -> CommandResult:
        """`python3 -` run by KERBEROS on its own 3x-ui server (§7.6): the node at 127.0.0.1."""
        node = self.nodes.get("127.0.0.1")
        if node is None:
            raise ContractError("no local node in the fake fleet")
        if 'os.environ["SSH_CONNECTION"]' not in (stdin or "") and "remove" not in str(
            read_payload(stdin or "") or {}
        ):
            raise ContractError("a local install must set SSH_CONNECTION to this server")
        self.log.append(("127.0.0.1", "local python3"))
        return self._bootstrap(node, stdin)

    def _bootstrap(self, node: FakeNode, stdin: Optional[str]) -> CommandResult:
        payload = read_payload(stdin or "")
        if payload is None:
            raise ContractError("bootstrap script without a payload")
        blob = payload["publicKey"].split()[1]
        if payload["mode"] == "remove":
            before = len(node.authorized_keys)
            node.authorized_keys = [k for k in node.authorized_keys if blob not in k]
            return CommandResult(0, json.dumps({"removed": before - len(node.authorized_keys)}))
        data = base64.b64decode(payload["agent"])
        if hashlib.sha256(data).hexdigest() != payload["sha256"]:
            return CommandResult(1, json.dumps({"error": "sha_mismatch"}))
        node.agent_sha = payload["sha256"]
        node.agent_version = agent_module.AGENT_VERSION
        line = (
            f'from="{node.panel_ip}",command="{AGENT_PATH}",restrict {payload["publicKey"].strip()}'
        )
        added = line not in node.authorized_keys
        if added:
            node.authorized_keys = [k for k in node.authorized_keys if blob not in k] + [line]
        answer = {"panelIp": node.panel_ip, "python": "3.12.3", "keyAdded": added}
        return CommandResult(0, json.dumps(answer) + "\n")

    def close_root(self, target: Target) -> None:
        self._root_open.discard(target.address)

    def agent(
        self,
        target: Target,
        command: str,
        payload: Optional[dict] = None,
        *,
        data: Optional[bytes] = None,
        timeout: float = 120,
        fresh: bool = False,
    ) -> dict:
        node = self._node(target)
        self._check_hostkey(target, node)
        public = self.state.public_key()
        if public is None:
            raise ContractError("agent call before the KERBEROS key exists")
        blob = public.split()[1]
        if (
            not any(
                blob in line and f'from="{node.panel_ip}"' in line for line in node.authorized_keys
            )
            or node.agent_sha is None
        ):
            raise TransportError("auth", "Permission denied (publickey)")
        words = shlex.split(command)
        name, args = words[0], words[1:]
        spec = agent_module.COMMANDS.get(name)
        if spec is None:
            raise ContractError(f"unknown agent command {name}")
        _, patterns, stdin_kind = spec
        if len(args) != len(patterns) or not all(p.match(a) for p, a in zip(patterns, args)):
            raise ContractError(f"bad arguments for {name}: {args}")
        if stdin_kind == "json" and payload is not None and not isinstance(payload, dict):
            raise ContractError("agent stdin must be a JSON object")
        if stdin_kind is None and (payload is not None or data is not None):
            raise ContractError(f"{name} takes no stdin")
        self.log.append((target.address, command + (" (fresh)" if fresh else "")))
        if name == "version":
            return {"protocol": 1, "agent": node.agent_version, "sha256": node.agent_sha}
        if name == "update":
            if data is None or hashlib.sha256(data).hexdigest() != args[0]:
                raise NodeAgentError("sha_mismatch", "update data")
            node.agent_sha = args[0]
            node.agent_version = agent_module.AGENT_VERSION
            return {"agent": node.agent_version}
        handler = node.handlers.get(name)
        if handler is None:
            raise NodeAgentError("not_implemented", name)
        return copy.deepcopy(handler(node, args, data if stdin_kind == "bytes" else payload))

    def admin_shell(self, target: Target) -> int:
        self._node(target)
        self.log.append((target.address, "admin shell"))
        return 0

    def close(self) -> None:
        self._root_open.clear()

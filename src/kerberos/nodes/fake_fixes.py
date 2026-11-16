"""Agent changes of a fake node: a model of §9.3 on the node's facts.

The real agent changes files and is tested on its own (tests/agent). Here a
fix changes the facts the agent would report afterwards, so the demo and
the app tests see findings disappear, come back after rollback, and hit the
same errors (no_admin_key, bridge_network, docker_published, change_conflict).
"""

from __future__ import annotations

import copy
from typing import Any, Callable

from kerberos.nodes.fake import FakeNode
from kerberos.nodes.keys import PublicKey, demo_blob, fingerprint
from kerberos.nodes.transport import NodeAgentError, TransportError

ACCESS = {"ssh.key_only", "ssh.port", "hostkeys.regenerate"}


def _table(facts: dict, name: str, add: bool) -> None:
    tables = facts.setdefault("nftTables", [])
    if add and name not in tables:
        tables.append(name)
    if not add and name in tables:
        tables.remove(name)


def apply_mptcp(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    saved = copy.deepcopy(facts["mptcp"])
    facts["mptcp"].update(enabled=False, ipOptionsDrop=True)
    _table(facts, "inet kerberos_mptcp", True)

    def undo() -> None:
        facts["mptcp"] = saved
        _table(facts, "inet kerberos_mptcp", False)

    return {}, undo


def apply_fail2ban(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    saved = copy.deepcopy(facts["fail2ban"])
    facts["fail2ban"] = {"installed": True, "sshdJail": True, "jailPorts": list(params["sshPorts"])}

    def undo() -> None:
        facts["fail2ban"] = saved

    return {}, undo


def apply_node_api(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    if facts["remnanode"].get("network") == "bridge":
        raise NodeAgentError("bridge_network", "remnanode publishes its port through Docker")
    saved = copy.deepcopy(facts["nodeApi"])
    facts["nodeApi"]["panelOnly"] = True
    _table(facts, "inet kerberos_node_api", True)

    def undo() -> None:
        facts["nodeApi"] = saved
        _table(facts, "inet kerberos_node_api", False)

    return {"port": params["port"], "panelIp": params["panelIp"]}, undo


def apply_ports(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    wanted = set(params["ports"])
    changed = []
    for sock in facts["listening"]:
        label = f"{sock['port']}/{sock['proto']}"
        if label in wanted:
            if sock.get("docker"):
                raise NodeAgentError("docker_published", label)
            changed.append((sock, sock.get("firewalled", False)))
    for sock, _before in changed:
        sock["firewalled"] = True
    added = "inet kerberos_ports" not in facts.get("nftTables", [])
    _table(facts, "inet kerberos_ports", True)

    def undo() -> None:
        for sock, before in changed:
            sock["firewalled"] = before
        if added:
            _table(facts, "inet kerberos_ports", False)

    return {"ports": sorted(wanted)}, undo


def apply_hostkeys(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    saved_facts = copy.deepcopy(facts["hostKeys"])
    saved_key = node.host_key
    new = PublicKey("ssh-ed25519", demo_blob(f"{node.name}-{change_id}"))
    node.host_key = new
    facts["hostKeys"] = [{"type": "ED25519", "fingerprint": fingerprint(new.blob)}]

    def undo() -> None:
        node.host_key = saved_key
        facts["hostKeys"] = saved_facts

    return {"hostKeys": copy.deepcopy(facts["hostKeys"])}, undo


def apply_key_only(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    if not facts["ssh"].get("adminKeys"):
        raise NodeAgentError("no_admin_key", "no key of the administrator besides KERBEROS")
    saved = copy.deepcopy(facts["ssh"])
    facts["ssh"].update(passwordAuthentication=False, kbdInteractive=False,
                        permitRootLogin="prohibit-password")  # fmt: skip

    def undo() -> None:
        facts["ssh"].update({k: saved[k] for k in ("passwordAuthentication", "kbdInteractive",
                                                    "permitRootLogin")})  # fmt: skip

    return {}, undo


def apply_admin_keys(node: FakeNode, params: dict, change_id: str) -> tuple[dict, Callable]:
    facts = node.state["facts"]
    keys = [k for k in params.get("keys", []) if k not in node.authorized_keys]
    saved_keys = list(node.authorized_keys)
    saved_count = facts["ssh"].get("adminKeys", 0)
    node.authorized_keys = node.authorized_keys + keys
    facts["ssh"]["adminKeys"] = saved_count + len(keys)

    def undo() -> None:
        node.authorized_keys = saved_keys
        facts["ssh"]["adminKeys"] = saved_count

    return {"added": len(keys)}, undo


def apply_ssh_port(node: FakeNode, params: dict, change_id: str) -> tuple:
    facts = node.state["facts"]
    new = params["port"]
    if any(s["port"] == new for s in facts["listening"]):
        raise NodeAgentError("port_busy", str(new))
    saved = copy.deepcopy({k: facts[k] for k in ("ssh", "fail2ban", "listening")})
    saved_main = node.ssh_port
    old = list(facts["ssh"]["ports"])
    facts["ssh"]["ports"] = old + [new]
    node.state.setdefault("extra_ports", []).append(new)
    listener = {"proto": "tcp", "address": "0.0.0.0", "port": new, "process": "sshd"}
    facts["listening"].append({**listener, "docker": False, "firewalled": False})
    if node.state.get("hoster_firewall"):
        node.state.setdefault("closed_ports", []).append(new)
    if facts["fail2ban"].get("sshdJail"):
        facts["fail2ban"]["jailPorts"] = sorted(set(facts["fail2ban"]["jailPorts"]) | {new})

    def confirm() -> None:
        facts["ssh"]["ports"] = [new]
        node.ssh_port = new
        node.state["extra_ports"] = [p for p in node.state["extra_ports"] if p != new]
        facts["listening"] = [s for s in facts["listening"]
                              if not (s["process"] == "sshd" and s["port"] in old)]  # fmt: skip
        if facts["fail2ban"].get("sshdJail"):
            facts["fail2ban"]["jailPorts"] = [new]

    def undo() -> None:
        facts.update(copy.deepcopy(saved))
        node.ssh_port = saved_main
        node.state["extra_ports"] = [p for p in node.state.get("extra_ports", []) if p != new]

    details = {"newPort": new, "oldPorts": old, "socket": facts["ssh"].get("socketActivated")}
    return details, undo, confirm


MODEL: dict = {
    "mptcp.guard": apply_mptcp,
    "fail2ban.sshd": apply_fail2ban,
    "node_api.panel_only": apply_node_api,
    "ports.drop": apply_ports,
    "hostkeys.regenerate": apply_hostkeys,
    "ssh.key_only": apply_key_only,
    "access.admin_keys": apply_admin_keys,
    "ssh.port": apply_ssh_port,
}


def _answer(change_id: str, record: dict, state: str = "") -> dict:
    return {
        "protocol": 1,
        "changeId": change_id,
        "fixId": record["fixId"],
        "state": state or record["state"],
        "files": [],
        "details": record["details"],
    }


def give_fixes(node: FakeNode, model: dict = MODEL) -> None:
    changes = node.state.setdefault("changes", {})
    node.state.setdefault("fail", {})  # fixId -> error code, read on every apply

    def apply(n: FakeNode, args: list, params: Any) -> dict:
        fix_id, change_id = args
        if change_id in changes:
            return _answer(change_id, changes[change_id], "noop")
        if fix_id not in model:
            raise NodeAgentError("not_implemented", fix_id)
        if any(c["state"] == "pending_confirm" for c in changes.values()):
            raise NodeAgentError("change_conflict", "a change waits for confirmation")
        failures = n.state.get("fail", {})
        if fix_id in failures:
            raise NodeAgentError(failures[fix_id], f"injected for {fix_id}")
        result = model[fix_id](n, params or {}, change_id)
        details, undo = result[0], result[1]
        second = result[2] if len(result) > 2 else None
        state = "pending_confirm" if fix_id in ACCESS else "applied"
        changes[change_id] = {"fixId": fix_id, "state": state, "details": details, "undo": undo,
                              "confirm": second}  # fmt: skip
        return _answer(change_id, changes[change_id])

    def confirm(n: FakeNode, args: list, _data: Any) -> dict:
        record = changes.get(args[0])
        if record is None:
            raise NodeAgentError("no_backup", args[0])
        if n.state.get("confirm_fails"):
            raise TransportError("timeout", "the new connection did not come up")
        if record["state"] != "pending_confirm":
            return _answer(args[0], record, "noop")
        if record.get("confirm"):
            record["confirm"]()
        record["state"] = "confirmed"
        return _answer(args[0], record)

    def rollback(n: FakeNode, args: list, _data: Any) -> dict:
        record = changes.get(args[0])
        if record is None:
            raise NodeAgentError("no_backup", args[0])
        if n.state.get("rollback_fails"):
            raise TransportError("timeout", "no answer")
        if record["state"] == "rolled_back":
            return _answer(args[0], record, "noop")
        record["undo"]()
        record["state"] = "rolled_back"
        return _answer(args[0], record)

    def plan(n: FakeNode, args: list, _params: Any) -> dict:
        return {"files": [], "commands": [], "packages": []}

    node.handlers.update(apply=apply, confirm=confirm, rollback=rollback, plan=plan)

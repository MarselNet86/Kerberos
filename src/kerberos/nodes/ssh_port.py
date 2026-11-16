"""Rollback of a confirmed ssh.port, the way it came (tech.md §9.3, §10.3, K13).

The agent answers `rollback` of a confirmed ssh.port with `rollback_pending`: SSH
listens on the old and the new port again and the undo timer runs. A new
connection to the old port proves it and calls `confirm`, which leaves only the
old port. When the old port does not answer (the hoster's firewall), `undo` goes
back to the confirmed new port; the timer does the same after three minutes. On
3x-ui KERBEROS reaches its own server on 127.0.0.1 and cannot see that firewall:
the person tries the old port from outside first (`ask_outside`).

Shared by `kerberos rollback` and by the engine, which rolls a change back when
its recheck fails.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from kerberos.nodes.transport import NodeAgentError, Target, TransportError

LOCAL_ADDRESS = "127.0.0.1"  # a 3x-ui server reaching itself (§7.6)
CONFIRM_WINDOW = 60  # as long as a new port gets at apply (§11.3)
CONFIRM_RETRY = 5


def old_port(answer: dict, change: dict) -> int:
    details = answer.get("details") or {}
    ports = details.get("oldPorts") or change["details"].get("oldPorts") or [22]
    return int(ports[0])


def roll_back_port(
    env: Any,
    target: Target,
    change: dict,
    ask_outside: Optional[Callable[[int], bool]] = None,
    window: float = CONFIRM_WINDOW,
    retry: float = CONFIRM_RETRY,
) -> tuple:
    """(error, back): back is True when SSH is on the old port only, as before the change.

    error None: done. "command_failed": the old layout is back but an undo command
    failed. Any other error: the confirmed new port stays (port_closed when the old
    port did not answer, else the code or kind of the failure).
    """
    transport, state = env.transport, env.state
    change_id = change["changeId"]
    try:
        answer = transport.agent(target, f"rollback {change_id}")
    except TransportError as exc:
        return exc.kind, False
    except NodeAgentError as exc:
        return exc.code, False  # the first phase did not come up: the new port stays
    if answer.get("state") != "rollback_pending":
        return None, True  # an agent from before K13 restores at once
    old = old_port(answer, change)
    blob = state.pinned(target.address, target.port)
    if blob:
        state.pin(target.address, old, "ssh-ed25519", blob)  # the same sshd on both
    old_target = Target(target.uuid, target.name, target.address, old)
    result = "port_closed"
    if target.address == LOCAL_ADDRESS:
        if ask_outside is not None and ask_outside(old):
            result = confirm_old_port(env, old_target, change_id, 0, 0)
    else:
        result = confirm_old_port(env, old_target, change_id, window, retry)
    if result == "ok":
        return None, True
    if result == "command_failed":
        return result, True
    try:  # back to the confirmed port now; the agent's timer would do it in three minutes
        transport.agent(target, f"undo {change_id}", fresh=True)
    except (NodeAgentError, TransportError):
        pass
    return result, False


def confirm_old_port(env: Any, target: Target, change_id: str, window: float, retry: float) -> str:
    """Answers ok, port_closed or the error code of the agent."""
    clock = env.clock
    deadline = clock.monotonic() + window
    while True:
        try:
            answer = env.transport.agent(target, f"confirm {change_id}", fresh=True)
        except NodeAgentError as exc:
            return exc.code
        except TransportError:
            if clock.monotonic() + retry >= deadline:
                return "port_closed"
            clock.sleep(retry)
            continue
        # noop: the timer brought the confirmed port back before the confirm came.
        return "ok" if answer.get("state") == "rolled_back" else "port_closed"

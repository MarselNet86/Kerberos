"""The demo fleet with KERBEROS access set up directly, for check tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from kerberos.app import Env
from kerberos.checks.collect import Collector, Progress
from kerberos.clock import FakeClock
from kerberos.demo.fleet import attach
from kerberos.mask import Masker
from kerberos.nodes import bootstrap
from kerberos.nodes.keys import kerberos_line
from kerberos.panel.client import PanelClient


def demo_env() -> Env:
    env = Env(terminal=None, clock=FakeClock(), masker=Masker(), demo=True)
    attach(env, Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    return env


def grant_access(env: Env) -> dict:
    """What S4 would leave behind: pinned keys, the agent and the KERBEROS key."""
    state = env.state
    state.ensure()
    env.host.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kerberos@panel",
                  "-f", str(state.key)])  # fmt: skip
    public = state.public_key()
    access = {}
    for node in env.transport.nodes.values():
        if not node.reachable:
            continue
        state.pin(node.address, node.ssh_port, node.host_key.type, node.host_key.blob)
        node.authorized_keys = [kerberos_line(node.panel_ip, public)]
        node.agent_sha = bootstrap.agent_sha256()
        node.agent_version = "0.3.0"
    return access


def demo_snapshot(env: Env):
    client = PanelClient("http://127.0.0.1:3000/api", env.panel_transport, env.clock)
    client.set_token(env.panel_transport.add_api_token())
    return client, client.snapshot("2.8.1", "panel.example.com")


def demo_input(whois: bool = True):
    env = demo_env()
    grant_access(env)
    _client, snapshot = demo_snapshot(env)
    selected = [n.uuid for n in snapshot.nodes if not n.is_disabled]
    reachable = {n.address for n in env.transport.nodes.values() if n.reachable}
    access = {n.uuid: "ok" if n.address in reachable else "none" for n in snapshot.nodes}
    data = Collector(env, snapshot, selected, access, whois, Progress()).run()
    return env, data


__all__ = ["Collector", "Progress", "demo_env", "demo_input", "demo_snapshot", "grant_access"]

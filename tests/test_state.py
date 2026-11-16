"""State on the panel server (tech.md §5.4)."""

import json
import stat

import pytest

from kerberos.nodes.keys import demo_blob
from kerberos.state import Locked, NodeRecord, State


def test_nodes_json_round_trip_and_mode(tmp_path):
    state = State(tmp_path / "k")
    state.save_node(
        NodeRecord("u1", "nl-1", "203.0.113.10", 2222, "SHA256:x", "0.2.0", "198.51.100.5", "ok")
    )
    raw = json.loads(state.nodes_file.read_text())
    assert raw["u1"]["sshPort"] == 2222 and raw["u1"]["panelIp"] == "198.51.100.5"
    assert state.node("u1").ssh_port == 2222
    assert state.find_node("nl-1").uuid == "u1"
    assert stat.S_IMODE(state.nodes_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.root.stat().st_mode) == 0o700


def test_pin_replaces_the_previous_key(tmp_path):
    state = State(tmp_path)
    state.pin("203.0.113.10", 22, "ssh-ed25519", demo_blob("a"))
    state.pin("203.0.113.10", 2222, "ssh-ed25519", demo_blob("b"))
    state.pin("203.0.113.10", 22, "ssh-ed25519", demo_blob("c"))
    assert state.pinned("203.0.113.10", 22) == demo_blob("c")
    assert state.pinned("203.0.113.10", 2222) == demo_blob("b")
    assert len(state.known_hosts.read_text().splitlines()) == 2


def test_one_run_at_a_time(tmp_path):
    state = State(tmp_path)
    with state.lock():
        with pytest.raises(Locked):
            with State(tmp_path).lock():
                pass
    with state.lock():
        pass


def test_broken_nodes_json_is_ignored(tmp_path):
    state = State(tmp_path)
    state.ensure()
    state.nodes_file.write_text("{not json")
    assert state.nodes() == {}

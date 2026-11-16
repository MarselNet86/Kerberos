"""The bootstrap script itself, run against a temporary root (tech.md §8.2)."""

import json
import os
import stat
import subprocess
import sys

import pytest

from kerberos.nodes import bootstrap
from kerberos.nodes.keys import demo_blob, parse_authorized_keys

PUBLIC = f"ssh-ed25519 {demo_blob('kerberos')} kerberos@panel"


def run(script, root, panel_ip="198.51.100.5"):
    env = {"KERBEROS_TEST_ROOT": str(root), "PATH": os.environ.get("PATH", "")}
    if panel_ip:
        env["SSH_CONNECTION"] = f"{panel_ip} 50022 203.0.113.10 22"
    proc = subprocess.run(
        [sys.executable, "-I", "-"], input=script, capture_output=True, text=True, env=env
    )
    return proc.returncode, bootstrap.parse_result(proc.stdout)


def keys(root):
    path = root / "root" / ".ssh" / "authorized_keys"
    return path.read_text().splitlines() if path.exists() else []


def test_install_writes_agent_and_one_restricted_key(tmp_path):
    (tmp_path / "root" / ".ssh").mkdir(parents=True)
    (tmp_path / "root" / ".ssh" / "authorized_keys").write_text(
        f"ssh-ed25519 {demo_blob('admin')} admin@laptop\n"
    )
    code, answer = run(bootstrap.install_script(PUBLIC), tmp_path)
    assert code == 0 and answer["panelIp"] == "198.51.100.5" and answer["keyAdded"] is True
    agent = tmp_path / "usr" / "local" / "sbin" / "kerberos-agent"
    assert agent.read_bytes() == bootstrap.agent_source()
    assert stat.S_IMODE(agent.stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "var" / "lib" / "kerberos").stat().st_mode) == 0o700
    ak = tmp_path / "root" / ".ssh" / "authorized_keys"
    assert stat.S_IMODE(ak.stat().st_mode) == 0o600
    lines = keys(tmp_path)
    assert lines[0].endswith("admin@laptop")
    assert lines[1] == (
        'from="198.51.100.5",command="/usr/local/sbin/kerberos-agent",restrict ' + PUBLIC
    )


def test_second_bootstrap_changes_nothing(tmp_path):
    run(bootstrap.install_script(PUBLIC), tmp_path)
    before = keys(tmp_path)
    code, answer = run(bootstrap.install_script(PUBLIC), tmp_path)
    assert code == 0 and answer["keyAdded"] is False
    assert keys(tmp_path) == before
    assert sum(1 for k in parse_authorized_keys("\n".join(before)) if k.is_kerberos) == 1


def test_new_panel_address_replaces_the_old_line(tmp_path):
    run(bootstrap.install_script(PUBLIC), tmp_path)
    run(bootstrap.install_script(PUBLIC), tmp_path, panel_ip="198.51.100.6")
    lines = keys(tmp_path)
    assert len(lines) == 1 and lines[0].startswith('from="198.51.100.6"')


def test_remove_takes_only_the_kerberos_line(tmp_path):
    (tmp_path / "root" / ".ssh").mkdir(parents=True)
    admin = f"ssh-ed25519 {demo_blob('admin')} admin@laptop"
    (tmp_path / "root" / ".ssh" / "authorized_keys").write_text(admin + "\n")
    run(bootstrap.install_script(PUBLIC), tmp_path)
    code, answer = run(bootstrap.remove_script(PUBLIC), tmp_path)
    assert code == 0 and answer == {"removed": 1}
    assert keys(tmp_path) == [admin]


def test_damaged_agent_is_refused(tmp_path):
    payload = bootstrap.read_payload(bootstrap.install_script(PUBLIC))
    payload["sha256"] = "0" * 64
    code, answer = run(bootstrap.script(payload), tmp_path)
    assert code == 1 and answer == {"error": "sha_mismatch"}
    assert not (tmp_path / "usr" / "local" / "sbin" / "kerberos-agent").exists()


def test_without_ssh_connection_no_key_is_added(tmp_path):
    code, answer = run(bootstrap.install_script(PUBLIC), tmp_path, panel_ip="")
    assert code == 1 and answer["error"] == "no_ssh_connection"
    assert keys(tmp_path) == []


def test_payload_round_trip():
    payload = bootstrap.read_payload(bootstrap.remove_script(PUBLIC))
    assert payload["mode"] == "remove" and payload["publicKey"] == PUBLIC


@pytest.mark.parametrize("command", [bootstrap.REMOTE_COMMAND, bootstrap.INSTALL_PYTHON])
def test_remote_commands_are_plain_shell(command):
    assert "\n" not in command and "python3" in command
    assert json.dumps(command)

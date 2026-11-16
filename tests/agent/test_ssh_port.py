"""ssh.port in two phases (tech.md §10.3, K5): old port closes only after the new one works."""

import json
import os
import uuid

import pytest
from agent_helpers import call

from kerberos import agent

UFW_ACTIVE = "Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n"


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


@pytest.fixture
def base(system, recorder):
    for prefix in (["systemctl"], ["sshd", "-t"], ["systemd-run"], ["ufw", "allow"],
                   ["ufw", "delete"]):  # fmt: skip
        recorder.on(prefix, agent.Result(0))
    recorder.on(
        ["ss"],
        agent.Result(0, 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'),
    )
    recorder.on(["ufw", "status"], agent.Result(0, "Status: inactive\n"))
    return system


@pytest.fixture
def socket_node(base, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(0, "active\n"))
    recorder.on(["systemctl", "show", "ssh.socket"],
                agent.Result(0, "Listen=0.0.0.0:22 (Stream) [::]:22 (Stream)\n"))  # fmt: skip
    return base


@pytest.fixture
def config_node(base, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(3, "inactive\n"))
    recorder.on(["systemctl", "show", "ssh.socket"], agent.Result(0, "Listen=\n"))
    recorder.on(["sshd", "-T"], agent.Result(0, "port 22\npasswordauthentication no\n"))
    recorder.on(["ufw", "status"], agent.Result(0, UFW_ACTIVE))
    write(base, agent.SSHD_MAIN, "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    write(base, agent.SSHD_CONF, "PasswordAuthentication no\n")
    return base


def apply_port(system, port=24622):
    change = str(uuid.uuid4())
    code, answer = call(system, ["apply", "ssh.port", change], json.dumps({"port": port}).encode())
    return change, code, answer


def test_socket_activation_listens_on_both_then_only_the_new_port(socket_node, recorder):
    change, code, answer = apply_port(socket_node)
    assert code == 0 and answer["state"] == "pending_confirm"
    assert answer["details"] == {"newPort": 24622, "oldPorts": [22], "socket": True}
    dropin = read(socket_node, agent.SOCKET_DROPIN)
    assert dropin.splitlines()[:2] == ["[Socket]", "ListenStream="]
    for line in ("0.0.0.0:22", "[::]:22", "0.0.0.0:24622", "[::]:24622"):
        assert f"ListenStream={line}" in dropin
    assert ["systemctl", "restart", "ssh.socket"] in recorder.calls
    assert not any(c[:2] == ["ufw", "allow"] for c in recorder.calls), "ufw is inactive"
    code, answer = call(socket_node, ["confirm", change])
    assert code == 0 and answer["state"] == "confirmed"
    dropin = read(socket_node, agent.SOCKET_DROPIN)
    assert "24622" in dropin and ":22\n" not in dropin
    # A confirmed port goes back in two phases too: both ports, then the old one only.
    code, answer = call(socket_node, ["rollback", change])
    assert code == 0 and answer["state"] == "rollback_pending"
    dropin = read(socket_node, agent.SOCKET_DROPIN)
    assert "ListenStream=0.0.0.0:22" in dropin and "ListenStream=0.0.0.0:24622" in dropin
    code, answer = call(socket_node, ["confirm", change])
    assert answer["state"] == "rolled_back" and read(socket_node, agent.SOCKET_DROPIN) is None


def test_config_ports_ufw_and_the_main_file(config_node, recorder):
    change, code, _answer = apply_port(config_node)
    assert code == 0
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\nPort 22\nPort 24622\n"
    assert ["ufw", "allow", "24622/tcp"] in recorder.calls
    assert read(config_node, agent.SSHD_MAIN).endswith("Port 22\n"), "phase 1 keeps port 22"
    call(config_node, ["confirm", change])
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\nPort 24622\n"
    assert "# Port 22" in read(config_node, agent.SSHD_MAIN)
    code, answer = call(config_node, ["rollback", change])
    assert answer["state"] == "rollback_pending"
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\nPort 22\nPort 24622\n"
    call(config_node, ["confirm", change])
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\n"
    assert read(config_node, agent.SSHD_MAIN).endswith("\nPort 22\n")
    assert ["ufw", "delete", "allow", "24622/tcp"] in recorder.calls


def test_fail2ban_jail_follows_the_ports(config_node):
    write(config_node, agent.JAIL_FILE, "[sshd]\nenabled = true\nport = 22\nbackend = systemd\n")
    change, _code, _answer = apply_port(config_node)
    assert "port = 22,24622" in read(config_node, agent.JAIL_FILE)
    call(config_node, ["confirm", change])
    assert "port = 24622" in read(config_node, agent.JAIL_FILE)


def test_busy_port(socket_node, recorder):
    recorder.on(["ss"], agent.Result(0, "tcp LISTEN 0 5 0.0.0.0:24622 0.0.0.0:*\n"))
    _change, code, answer = apply_port(socket_node)
    assert code == 1 and answer["error"]["code"] == "port_busy"


def test_low_ports_are_refused(socket_node):
    _change, code, answer = apply_port(socket_node, 80)
    assert code == 1 and answer["error"]["code"] == "bad_params"


def test_the_timer_returns_both_phases_files(config_node):
    change, _code, _answer = apply_port(config_node)
    code, answer = call(config_node, ["rollback", change])  # what the timer runs
    assert answer["state"] == "rolled_back"
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\n"


def test_second_phase_failure_restores_everything(config_node, recorder):
    change, _code, _answer = apply_port(config_node)
    recorder.on(["sshd", "-t"], agent.Result(255, "", "bad"))
    code, answer = call(config_node, ["confirm", change])
    assert code == 1 and answer["error"]["code"] == "sshd_test_failed"
    assert read(config_node, agent.SSHD_CONF) == "PasswordAuthentication no\n"
    assert read(config_node, agent.SSHD_MAIN).endswith("\nPort 22\n")

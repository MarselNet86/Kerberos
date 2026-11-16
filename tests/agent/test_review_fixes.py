"""What the review of the node side found (K13): each test is a failure scenario."""

import json
import os
import uuid

import pytest
from agent_helpers import call

from kerberos import agent

ADMIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkLQ1Bbnn3QgWxB8dkF5rQ7m+9Cqg admin@laptop"


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


def apply(system, fix_id, params=None, change=None):
    change = change or str(uuid.uuid4())
    code, answer = call(system, ["apply", fix_id, change], json.dumps(params or {}).encode())
    return change, code, answer


def ss_line(port, owners='("sshd",pid=812,fd=3)', proto="tcp"):
    return f"{proto} LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:({owners})\n"


@pytest.fixture
def node(system, recorder):
    for prefix in (["systemctl"], ["sshd", "-t"], ["systemd-run"], ["apt-get"], ["sysctl"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(["docker"], agent.Result(0, ""))
    recorder.on(["ss"], agent.Result(0, ""))
    write(system, "/usr/sbin/nft", "")
    write(system, "/root/.ssh/authorized_keys", ADMIN + "\n", 0o600)
    write(system, "/proc/sys/net/mptcp/enabled", "1\n")
    system.environ["SSH_CONNECTION"] = "198.51.100.5 50000 203.0.113.10 22"
    return system


# -- 1. ports.drop dropped the port of the live SSH session --------------------------
def test_ports_drop_refuses_the_port_this_session_came_in_on(node, recorder):
    """Debian 12 with `ListenAddress 0.0.0.0:2222`: facts said 22, ss showed sshd on 2222."""
    node.environ["SSH_CONNECTION"] = "198.51.100.5 50000 203.0.113.10 2222"
    recorder.on(["ss"], agent.Result(0, ss_line(2222)))
    _change, code, answer = apply(node, "ports.drop", {"ports": ["2222/tcp"]})
    assert code == 1 and answer["error"]["code"] == "ssh_port"
    assert read(node, "/etc/kerberos/ports.nft") is None, "no drop rule for SSH"


def test_ports_drop_refuses_every_port_sshd_holds(node, recorder):
    recorder.on(["ss"], agent.Result(0, ss_line(22) + ss_line(2200)))
    _change, code, answer = apply(node, "ports.drop", {"ports": ["8080/tcp", "2200/tcp"]})
    assert code == 1 and answer["error"]["code"] == "ssh_port"
    assert "2200/tcp" in answer["error"]["message"]


def test_ports_drop_refuses_a_port_of_ssh_socket(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(0, "active\n"))
    recorder.on(["systemctl", "show", "ssh.socket"],
                agent.Result(0, "Listen=0.0.0.0:2200 (Stream) [::]:2200 (Stream)\n"))  # fmt: skip
    recorder.on(["ss"], agent.Result(0, ss_line(2200, '("systemd",pid=1,fd=101)')))
    _change, code, answer = apply(node, "ports.drop", {"ports": ["2200/tcp"]})
    assert code == 1 and answer["error"]["code"] == "ssh_port"


def test_ports_drop_still_drops_ports_that_are_not_ssh(node, recorder):
    recorder.on(["ss"], agent.Result(0, ss_line(2222) + ss_line(8080, '("python3",pid=9,fd=3)')))
    _change, code, answer = apply(node, "ports.drop", {"ports": ["8080/tcp", "2222/udp"]})
    assert code == 0, answer
    nft = read(node, "/etc/kerberos/ports.nft")
    assert "tcp dport 8080 drop" in nft and "udp dport 2222 drop" in nft
    assert "tcp dport 2222" not in nft


def test_sshd_t_ports_come_from_listen_addresses():
    values = agent.parse_sshd_t(
        "port 22\naddressfamily any\nlistenaddress 0.0.0.0:2222\n"
        "listenaddress [2001:db8::10]:2222 rdomain blue\npasswordauthentication no\n"
    )
    assert values["port"] == [2222], "ListenAddress with a port wins over Port"
    listen = "".join(f"listenaddress {a}:{p}\n" for p in (22, 24622) for a in ("[::]", "0.0.0.0"))
    plain = agent.parse_sshd_t("port 22\nport 24622\n" + listen)
    assert plain["port"] == [22, 24622]
    assert agent.parse_sshd_t("port 22\nport 22\n")["port"] == [22]


def test_ssh_ports_from_ss_when_sshd_t_does_not_answer(node, recorder):
    recorder.on(["sshd", "-T"], agent.Result(255, "", "Missing privilege separation directory"))
    recorder.on(["ss"], agent.Result(0, ss_line(2222) + ss_line(443, '("xray",pid=7,fd=7)')))
    assert agent.collect_ssh(node)["ports"] == [2222], "not a guess of 22"


def test_ssh_ports_of_a_listen_address_reach_the_facts(node, recorder):
    recorder.on(["sshd", "-T"], agent.Result(0, "port 22\nlistenaddress 0.0.0.0:2222\n"
                                                "passwordauthentication no\n"))  # fmt: skip
    ssh = agent.collect_ssh(node)
    assert ssh["ports"] == [2222] and ssh["socketActivated"] is False

"""SshTransport builds the ssh command of tech.md §8.1; errors are classified."""

import subprocess

import pytest

from kerberos.nodes.transport import (
    NodeAgentError,
    SshTransport,
    Target,
    TransportError,
    classify,
    parse_answer,
)
from kerberos.state import State


class Done:
    def __init__(self, code=0, stdout=b'{"protocol": 1}\n', stderr=b""):
        self.returncode, self.stdout, self.stderr = code, stdout, stderr


def capture(monkeypatch, result):
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("kerberos.nodes.transport.SshTransport._run_dir", lambda self: "/tmp/k")
    return seen


def test_agent_command_has_every_option_of_8_1(monkeypatch, tmp_path):
    seen = capture(monkeypatch, Done())
    transport = SshTransport(State(tmp_path))
    transport.agent(Target("u", "nl-1", "203.0.113.10", 2222), "facts")
    argv = seen[0]
    joined = " ".join(argv)
    for part in (
        "-F /dev/null",
        f"-i {tmp_path}/id_ed25519",
        "-o IdentitiesOnly=yes",
        "-o BatchMode=yes",
        "-o StrictHostKeyChecking=yes",
        f"-o UserKnownHostsFile={tmp_path}/known_hosts",
        "-o ConnectTimeout=15",
        "-p 2222",
        "-o ControlMaster=auto",
    ):
        assert part in joined
    assert argv[-2:] == ["root@203.0.113.10", "facts"]


def test_fresh_connection_skips_the_master(monkeypatch, tmp_path):
    seen = capture(monkeypatch, Done())
    SshTransport(State(tmp_path)).agent(Target("u", "n", "203.0.113.10"), "version", fresh=True)
    joined = " ".join(seen[0])
    assert "ControlMaster=no" in joined and "ControlPath=none" in joined


def test_agent_error_and_ssh_failures(monkeypatch, tmp_path):
    capture(monkeypatch, Done(1, b'{"error": {"code": "no_admin_key", "message": "x"}}\n'))
    with pytest.raises(NodeAgentError) as exc:
        SshTransport(State(tmp_path)).agent(Target("u", "n", "203.0.113.10"), "facts")
    assert exc.value.code == "no_admin_key"
    capture(monkeypatch, Done(255, b"", b"@@@ REMOTE HOST IDENTIFICATION HAS CHANGED! @@@"))
    with pytest.raises(TransportError) as exc:
        SshTransport(State(tmp_path)).agent(Target("u", "n", "203.0.113.10"), "facts")
    assert exc.value.kind == "hostkey_changed"


@pytest.mark.parametrize(
    "stderr, kind",
    [
        ("Host key verification failed.", "hostkey_changed"),
        ("root@203.0.113.10: Permission denied (publickey).", "auth"),
        ("ssh: connect to host 203.0.113.10 port 22: Connection refused", "refused"),
        ("ssh: connect to host 203.0.113.10 port 22: Connection timed out", "timeout"),
        ("ssh: connect to host 203.0.113.10 port 22: No route to host", "unreachable"),
        ("kex_exchange_identification: read: Connection reset by peer", "failed"),
    ],
)
def test_classify(stderr, kind):
    assert classify(stderr) == kind


def test_parse_answer_takes_the_last_json_line():
    assert parse_answer('noise\n{"a": 1}\n{"b": 2}\n') == {"b": 2}
    with pytest.raises(TransportError):
        parse_answer("no json here")

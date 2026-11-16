"""Agent protocol (tech.md §9.1, §9.2): commands, parameters, errors, update."""

import hashlib
import io
import json
import os
import stat

import pytest
from agent_helpers import ROOT, call, install_self

from kerberos import agent


def test_version(system):
    data = install_self(system)
    code, answer = call(system, ["version"])
    assert code == 0
    assert answer == {
        "protocol": 1,
        "agent": agent.AGENT_VERSION,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_command_from_ssh_original_command(tmp_path, recorder):
    system = agent.System(str(tmp_path), recorder, {"SSH_ORIGINAL_COMMAND": "version"})
    install_self(system)
    out = io.StringIO()
    assert agent.main([], system=system, stdin=b"", out=out) == 0
    assert json.loads(out.getvalue())["protocol"] == 1


@pytest.mark.parametrize(
    "words, code",
    [
        ([], "unknown_command"),
        (["rm", "-rf", "/"], "unknown_command"),
        (["version", "extra"], "bad_params"),
        (["apply", "mptcp.guard", "not-a-uuid"], "bad_params"),
        (["apply", "Bad;Fix", "0c6a8e0e-8a4b-4c39-9a51-1b2f1f6b8d10"], "bad_params"),
        (["update", "abc"], "bad_params"),
        (["confirm"], "bad_params"),
    ],
)
def test_rejects_commands_outside_the_table(system, words, code):
    rc, answer = call(system, words)
    assert rc == 1
    assert answer["error"]["code"] == code


def test_json_stdin_is_checked(system):
    rc, answer = call(system, ["site-check"], b"not json")
    assert rc == 1 and answer["error"]["code"] == "bad_params"
    rc, answer = call(system, ["site-check"], b"[1, 2]")
    assert rc == 1 and answer["error"]["code"] == "bad_params"


def test_unparsable_ssh_command(tmp_path, recorder):
    system = agent.System(str(tmp_path), recorder, {"SSH_ORIGINAL_COMMAND": "version 'open"})
    out = io.StringIO()
    assert agent.main([], system=system, stdin=b"", out=out) == 1
    assert json.loads(out.getvalue())["error"]["code"] == "bad_params"


def test_update_replaces_the_agent(system):
    install_self(system)
    new = agent_source_with_version("9.9.9")
    sha = hashlib.sha256(new).hexdigest()
    rc, answer = call(system, ["update", sha], new)
    assert rc == 0 and answer == {"agent": "9.9.9"}
    path = system.path(agent.AGENT_PATH)
    with open(path, "rb") as fh:
        assert fh.read() == new
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o755


def test_update_checks_sha256(system):
    install_self(system)
    new = agent_source_with_version("9.9.9")
    rc, answer = call(system, ["update", "0" * 64], new)
    assert rc == 1 and answer["error"]["code"] == "sha_mismatch"


def test_update_refuses_a_file_that_is_not_an_agent(system):
    data = b"#!/bin/sh\necho hi\n"
    rc, answer = call(system, ["update", hashlib.sha256(data).hexdigest()], data)
    assert rc == 1 and answer["error"]["code"] == "bad_params"


def test_error_codes_are_the_contract():
    assert {
        "bad_params",
        "unknown_command",
        "sha_mismatch",
        "no_admin_key",
        "sshd_test_failed",
        "ssh_port",
        "port_busy",
        "bridge_network",
        "docker_published",
        "mptcp_absent",
        "port80_busy",
        "certbot_failed",
        "nginx_test_failed",
        "realip_enabled",
        "apt_failed",
        "change_conflict",
        "no_backup",
        "backup_damaged",
        "not_implemented",
    } <= agent.ERROR_CODES
    with pytest.raises(ValueError):
        agent.AgentError("made_up")


def agent_source_with_version(version: str) -> bytes:
    text = (ROOT / "src" / "kerberos" / "agent.py").read_text(encoding="utf-8")
    return text.replace(
        f'AGENT_VERSION = "{agent.AGENT_VERSION}"', f'AGENT_VERSION = "{version}"'
    ).encode()

"""What the first stand run found on real Ubuntu and Debian VMs (K12)."""

import fcntl
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


def apply(system, fix_id, params=None, change=None):
    change = change or str(uuid.uuid4())
    code, answer = call(system, ["apply", fix_id, change], json.dumps(params or {}).encode())
    return change, code, answer


@pytest.fixture
def node(system, recorder):
    for prefix in (["systemctl"], ["sshd", "-t"], ["systemd-run"], ["apt-get"], ["sysctl"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(["ss"], agent.Result(0, ""))
    write(system, "/root/.ssh/authorized_keys", ADMIN + "\n", 0o600)
    write(system, "/proc/sys/net/mptcp/enabled", "1\n")
    return system


# -- the undo timer and a confirm met: the timer undid a confirmed change ---------------
def test_timer_undoes_only_a_change_waiting_for_confirmation(node):
    pending, code, answer = apply(node, "ssh.key_only")
    assert code == 0 and answer["state"] == "pending_confirm"
    code, answer = call(node, ["undo", pending])
    assert code == 0 and answer["state"] == "rolled_back"
    assert not node.exists(agent.SSHD_CONF)

    confirmed, _code, _answer = apply(node, "ssh.key_only")
    call(node, ["confirm", confirmed])
    code, answer = call(node, ["undo", confirmed])
    assert code == 0 and answer["state"] == "noop", "a confirmed change stays"
    assert node.exists(agent.SSHD_CONF)


def test_changes_wait_for_each_other(node, monkeypatch):
    monkeypatch.setattr(agent, "LOCK_WAIT", 0.3)
    path = node.path(agent.LOCK_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    holder = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        _change, code, answer = apply(node, "mptcp.guard")
        assert code == 1 and answer["error"]["code"] == "change_conflict"
        code, answer = call(node, ["facts"])
        assert code == 0, "reading does not wait"
    finally:
        os.close(holder)
    _change, code, answer = apply(node, "mptcp.guard")
    assert code == 0, answer


# -- systemd stopped ssh.socket after quick restarts (start-limit-hit) ----------------
def test_socket_restarts_reset_the_start_limit(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(0, "active\n"))
    recorder.on(["systemctl", "show", "ssh.socket"],
                agent.Result(0, "Listen=0.0.0.0:22 (Stream) [::]:22 (Stream)\n"))  # fmt: skip
    change, code, answer = apply(node, "ssh.port", {"port": 24622})
    assert code == 0, answer
    call(node, ["confirm", change])
    call(node, ["rollback", change])
    call(node, ["confirm", change])
    calls = recorder.calls
    restarts = [i for i, c in enumerate(calls) if c == ["systemctl", "restart", "ssh.socket"]]
    assert len(restarts) == 4, "apply, confirm and both phases of the rollback restart it"
    for i in restarts:
        assert calls[i - 1] == ["systemctl", "reset-failed", "ssh.socket", "ssh.service"]


# -- sshd -t failed on Ubuntu 24.04 and 26.04: no /run/sshd after the socket restart ----
def test_privsep_dir_exists_before_sshd_test(node):
    assert not node.exists(agent.PRIVSEP_DIR)
    _change, code, answer = apply(node, "ssh.key_only")
    assert code == 0, answer
    assert os.path.isdir(node.path(agent.PRIVSEP_DIR))


def test_sshd_that_cannot_answer_does_not_hide_password_login(node, recorder):
    answers = iter([agent.Result(255, "", "Missing privilege separation directory: /run/sshd"),
                    agent.Result(255, "", "still broken")])  # fmt: skip
    recorder.on(["sshd", "-T"], lambda _argv, _input: next(answers))
    ssh = agent.collect_ssh(node)
    assert ssh["passwordAuthentication"] is True and ssh["kbdInteractive"] is True
    assert sum(1 for c in recorder.calls if c == ["sshd", "-T"]) == 2, "retried after /run/sshd"
    assert os.path.isdir(node.path(agent.PRIVSEP_DIR))


def test_sshd_answers_after_the_privsep_dir_appears(node, recorder):
    answers = iter([agent.Result(255, "", "Missing privilege separation directory"),
                    agent.Result(0, "port 22\npasswordauthentication no\n")])  # fmt: skip
    recorder.on(["sshd", "-T"], lambda _argv, _input: next(answers))
    assert agent.collect_ssh(node)["passwordAuthentication"] is False


# -- Debian 12 and 13 cloud images have no nft ------------------------------------------
@pytest.mark.parametrize("fix_id, params", [
    ("mptcp.guard", {}),
    ("ports.drop", {"ports": ["8099/tcp"]}),
])  # fmt: skip
def test_nftables_comes_with_the_fix_when_missing(node, recorder, fix_id, params):
    _change, code, answer = apply(node, fix_id, params)
    assert code == 0, answer
    assert any(c[:4] == ["apt-get", "install", "-y", "-q"] and "nftables" in c
               for c in recorder.calls)  # fmt: skip


def test_no_nftables_install_when_nft_is_there(node, recorder):
    write(node, "/usr/sbin/nft", "")
    _change, code, _answer = apply(node, "mptcp.guard")
    assert code == 0 and not any(c[:1] == ["apt-get"] for c in recorder.calls)


# -- ssh-keygen -A made a DSA key on Ubuntu 22.04 that the rollback left behind --------
def test_new_host_keys_keep_the_set_of_types(node, recorder):
    for name in ("rsa", "ed25519"):
        write(node, f"/etc/ssh/ssh_host_{name}_key", f"old {name}\n", 0o600)
        write(
            node, f"/etc/ssh/ssh_host_{name}_key.pub", f"ssh-{name} AAAAold{name}AAAAAAAAAAAA x\n"
        )
    write(node, "/etc/ssh/ssh_host_dsa_key", "old dsa\n", 0o600)

    def keygen(argv, _input):
        path = argv[argv.index("-f") + 1]
        write(node, path, "new\n", 0o600)
        write(node, path + ".pub", "ssh-ed25519 AAAAnewnewnewnewnewnew x\n")
        return agent.Result(0)

    recorder.on(["ssh-keygen"], keygen)
    change, code, answer = apply(node, "hostkeys.regenerate")
    assert code == 0, answer
    made = [c for c in recorder.calls if c[0] == "ssh-keygen"]
    assert ["-A"] not in [c[1:2] for c in made], "never ssh-keygen -A"
    assert sorted(c[c.index("-t") + 1] for c in made) == ["ed25519", "rsa"]
    assert not node.exists("/etc/ssh/ssh_host_ecdsa_key"), "no new key types"
    assert open(node.path("/etc/ssh/ssh_host_dsa_key")).read() == "old dsa\n", "DSA untouched"
    call(node, ["rollback", change])
    for name in ("rsa", "ed25519"):
        assert open(node.path(f"/etc/ssh/ssh_host_{name}_key")).read() == f"old {name}\n"

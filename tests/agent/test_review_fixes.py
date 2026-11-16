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


# -- 2. the administrator key went while ssh.key_only stayed ---------------------------
def test_admin_keys_stay_while_a_later_key_only_is_in_force(node):
    write(node, "/root/.ssh/authorized_keys", "", 0o600)
    keys, code, _answer = apply(node, "access.admin_keys", {"keys": [ADMIN]})
    assert code == 0
    key_only, code, _answer = apply(node, "ssh.key_only")
    call(node, ["confirm", key_only])
    code, answer = call(node, ["rollback", keys])
    assert code == 1 and answer["error"]["code"] == "change_conflict"
    assert ADMIN in read(node, "/root/.ssh/authorized_keys"), "the person keeps the key"
    call(node, ["rollback", key_only])
    code, answer = call(node, ["rollback", keys])
    assert code == 0 and answer["state"] == "rolled_back"


def test_admin_keys_added_after_key_only_may_go(node):
    """key_only came first (the image had a key): the later admin_keys does not hold it."""
    key_only, _code, _answer = apply(node, "ssh.key_only")
    call(node, ["confirm", key_only])
    other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOther other@pc"
    later = node.now() + 10.0
    node.now = lambda: later
    keys, code, _answer = apply(node, "access.admin_keys", {"keys": [other]})
    assert code == 0
    code, answer = call(node, ["rollback", keys])
    assert code == 0 and answer["state"] == "rolled_back"


# -- 3. a confirmed ssh.port went back with no timer and no new connection -------------
SOCKET_LISTEN = "Listen=0.0.0.0:22 (Stream) [::]:22 (Stream)\n"


@pytest.fixture
def socket_node(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(0, "active\n"))
    recorder.on(["systemctl", "show", "ssh.socket"], agent.Result(0, SOCKET_LISTEN))
    recorder.on(["ss"], agent.Result(0, ss_line(22, '("systemd",pid=1,fd=101)')))
    recorder.on(["ufw", "status"], agent.Result(0, "Status: inactive\n"))
    return node


def confirmed_port(system, port=24622):
    change, code, answer = apply(system, "ssh.port", {"port": port})
    assert code == 0, answer
    code, answer = call(system, ["confirm", change])
    assert answer["state"] == "confirmed"
    return change


def listens(system):
    return sorted({int(line.rsplit(":", 1)[1]) for line in
                   (read(system, agent.SOCKET_DROPIN) or "").splitlines()
                   if line.startswith("ListenStream=") and ":" in line})  # fmt: skip


def test_rollback_of_a_confirmed_port_listens_on_both_with_the_timer(socket_node, recorder):
    change = confirmed_port(socket_node)
    assert listens(socket_node) == [24622]
    code, answer = call(socket_node, ["rollback", change])
    assert code == 0 and answer["state"] == "rollback_pending"
    assert answer["details"]["oldPorts"] == [22] and answer["details"]["newPort"] == 24622
    assert listens(socket_node) == [22, 24622], "the old port is back, the new one stays"
    timer = ["systemd-run", "--on-active=180", "--unit", f"kerberos-undo-{change}",
             agent.AGENT_PATH, "undo", change]  # fmt: skip
    assert recorder.calls.count(timer) == 2, "the same timer as at apply"
    assert read(socket_node, agent.PENDING_FILE).strip() == change
    _other, code, answer = apply(socket_node, "mptcp.guard")
    assert code == 1 and answer["error"]["code"] == "change_conflict"
    code, again = call(socket_node, ["rollback", change])
    assert again["state"] == "rollback_pending", "a repeated rollback waits too"


def test_new_connection_on_the_old_port_finishes_the_rollback(socket_node, recorder):
    change = confirmed_port(socket_node)
    call(socket_node, ["rollback", change])
    code, answer = call(socket_node, ["confirm", change])
    assert code == 0 and answer["state"] == "rolled_back"
    assert read(socket_node, agent.SOCKET_DROPIN) is None, "only the old port"
    assert ["systemctl", "stop", f"kerberos-undo-{change}.timer"] in recorder.calls
    assert read(socket_node, agent.PENDING_FILE) == ""
    code, again = call(socket_node, ["confirm", change])
    assert code == 0 and again["state"] == "rolled_back", "a lost answer can be asked again"


def test_no_new_connection_returns_to_the_confirmed_port(socket_node, recorder):
    change = confirmed_port(socket_node)
    call(socket_node, ["rollback", change])
    code, answer = call(socket_node, ["undo", change])  # KERBEROS or the timer
    assert code == 0 and answer["state"] == "confirmed"
    assert listens(socket_node) == [24622], "the new port only, as it was confirmed"
    assert read(socket_node, agent.PENDING_FILE) == ""
    code, answer = call(socket_node, ["confirm", change])
    assert answer["state"] == "noop", "too late: the change stays confirmed"
    code, answer = call(socket_node, ["rollback", change])
    assert answer["state"] == "rollback_pending", "a later rollback starts over"
    code, answer = call(socket_node, ["confirm", change])
    assert answer["state"] == "rolled_back" and read(socket_node, agent.SOCKET_DROPIN) is None


def test_first_phase_that_fails_keeps_the_confirmed_port(socket_node, recorder):
    change = confirmed_port(socket_node)
    restarts = iter([agent.Result(1, "", "start-limit-hit"), agent.Result(0)])
    recorder.on(["systemctl", "restart", "ssh.socket"], lambda _a, _i: next(restarts))
    code, answer = call(socket_node, ["rollback", change])
    assert code == 1 and answer["error"]["code"] == "command_failed"
    assert listens(socket_node) == [24622]
    assert read(socket_node, agent.PENDING_FILE) in (None, "")
    recorder.on(["systemctl", "restart", "ssh.socket"], agent.Result(0))
    code, answer = call(socket_node, ["rollback", change])
    assert answer["state"] == "rollback_pending", "still confirmed: it can go back later"


def test_config_mode_rollback_stages_both_ports(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(3, "inactive\n"))
    recorder.on(["sshd", "-T"], agent.Result(0, "port 22\npasswordauthentication no\n"))
    recorder.on(["ufw", "status"], agent.Result(0, "Status: inactive\n"))
    write(node, agent.SSHD_MAIN, "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n")
    change = confirmed_port(node)
    assert read(node, agent.SSHD_CONF) == "Port 24622\n"
    call(node, ["rollback", change])
    assert read(node, agent.SSHD_CONF) == "Port 22\nPort 24622\n"
    assert "# Port 22" in read(node, agent.SSHD_MAIN), "the old port comes from our file"
    call(node, ["undo", change])
    assert read(node, agent.SSHD_CONF) == "Port 24622\n"
    call(node, ["rollback", change])
    call(node, ["confirm", change])
    assert read(node, agent.SSHD_CONF) is None
    assert read(node, agent.SSHD_MAIN).endswith("\nPort 22\n")


def test_other_access_changes_keep_one_phase(node):
    change, _code, _answer = apply(node, "ssh.key_only")
    call(node, ["confirm", change])
    code, answer = call(node, ["rollback", change])
    assert code == 0 and answer["state"] == "rolled_back"


# -- 6. failed undo commands were swallowed -----------------------------------------------
COMPOSE = "services:\n  remnanode:\n    image: remnawave/node:latest\n    network_mode: host\n"


def test_rollback_whose_undo_command_fails_says_so(node, recorder):
    write(node, agent.COMPOSE_FILE, COMPOSE)
    change, code, answer = apply(node, "node.letsencrypt_mount")
    assert code == 0, answer
    recorder.on(["docker", "compose"], agent.Result(1, "", "no such image"))
    code, answer = call(node, ["rollback", change])
    assert code == 1 and answer["error"]["code"] == "command_failed"
    assert "docker compose" in answer["error"]["message"]
    assert read(node, agent.COMPOSE_FILE) == COMPOSE, "the files are back all the same"
    code, answer = call(node, ["rollback", change])
    assert answer["state"] == "noop"


def test_failed_apply_whose_undo_fails_says_so(node, recorder):
    recorder.on(["sshd", "-t"], agent.Result(255, "", "bad option"))
    recorder.on(["systemctl", "try-reload-or-restart"], agent.Result(1, "", "failed"))
    _change, code, answer = apply(node, "ssh.key_only")
    assert code == 1 and answer["error"]["code"] == "command_failed"
    assert "sshd_test_failed" in answer["error"]["message"]
    assert read(node, agent.SSHD_CONF) is None


def test_failed_confirm_stops_the_timer_only_after_the_restore(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(3, "inactive\n"))
    recorder.on(["sshd", "-T"], agent.Result(0, "port 22\n"))
    recorder.on(["ufw", "status"], agent.Result(0, "Status: inactive\n"))
    change, _code, _answer = apply(node, "ssh.port", {"port": 24622})
    recorder.on(["sshd", "-t"], agent.Result(255, "", "bad"))
    recorder.calls.clear()
    code, answer = call(node, ["confirm", change])
    assert code == 1 and answer["error"]["code"] == "sshd_test_failed"
    stop = recorder.calls.index(["systemctl", "stop", f"kerberos-undo-{change}.timer"])
    reload = recorder.calls.index(["systemctl", "try-reload-or-restart", "ssh.service"])
    assert reload < stop, "the old port works again before the timer goes"


def test_damaged_backup_in_a_failed_confirm_leaves_the_timer(node, recorder):
    recorder.on(["systemctl", "is-active", "ssh.socket"], agent.Result(3, "inactive\n"))
    recorder.on(["sshd", "-T"], agent.Result(0, "port 22\n"))
    recorder.on(["ufw", "status"], agent.Result(0, "Status: inactive\n"))
    write(node, agent.SSHD_CONF, "PasswordAuthentication no\n")
    change, _code, _answer = apply(node, "ssh.port", {"port": 24622})
    write(node, f"{agent.change_dir(change)}/files/0", "tampered\n")
    recorder.on(["sshd", "-t"], agent.Result(255, "", "bad"))
    code, answer = call(node, ["confirm", change])
    assert code == 1 and answer["error"]["code"] == "backup_damaged"
    assert ["systemctl", "stop", f"kerberos-undo-{change}.timer"] not in recorder.calls
    assert read(node, agent.PENDING_FILE).strip() == change, "the timer will try again"


# -- 11. a pending change outlived its timer (reboot) and blocked the node ----------------
class Clock:
    def __init__(self, start=1_800_000_000.0):
        self.value = start

    def __call__(self):
        return self.value


def test_pending_change_without_its_timer_is_settled_by_the_next_apply(node, recorder):
    clock = node.now = Clock()
    pending, _code, answer = apply(node, "ssh.key_only")
    assert answer["state"] == "pending_confirm"
    clock.value += agent.UNDO_DELAY + 10
    recorder.on(["systemctl", "show", "-p", "SubState"], agent.Result(0, "waiting\n"))
    _c, code, answer = apply(node, "mptcp.guard")
    assert code == 1 and answer["error"]["code"] == "change_conflict", "the timer still runs"
    clock.value += 3600  # a reboot: the transient timer is gone
    recorder.on(["systemctl", "show", "-p", "SubState"], agent.Result(0, "\n"))
    _c, code, answer = apply(node, "mptcp.guard")
    assert code == 0, answer
    assert read(node, agent.SSHD_CONF) is None, "rolled back as the timer would have"
    code, answer = call(node, ["confirm", pending])
    assert code == 1 and answer["error"]["code"] == "change_conflict"


def test_young_pending_change_still_blocks(node, recorder):
    node.now = Clock()
    apply(node, "ssh.key_only")
    recorder.on(["systemctl", "show", "-p", "SubState"], agent.Result(0, "\n"))
    _c, code, answer = apply(node, "mptcp.guard")
    assert code == 1 and answer["error"]["code"] == "change_conflict"


def test_stale_rollback_of_a_port_goes_back_to_the_confirmed_port(socket_node, recorder):
    clock = socket_node.now = Clock()
    change = confirmed_port(socket_node)
    call(socket_node, ["rollback", change])
    clock.value += 3600
    recorder.on(["systemctl", "show", "-p", "SubState"], agent.Result(0, "elapsed\n"))
    _c, code, answer = apply(socket_node, "mptcp.guard")
    assert code == 0, answer
    assert listens(socket_node) == [24622]
    code, answer = call(socket_node, ["rollback", change])
    assert answer["state"] == "rollback_pending"


# -- 5. node_api.panel_only cut the panel off its node -------------------------------------
REMNANODE_HOST = json.dumps([{"HostConfig": {"NetworkMode": "host"},
                              "Config": {"Env": ["NODE_PORT=2222"]}}])  # fmt: skip


def established(*peers):
    return "".join(f"0 0 [::ffff:203.0.113.10]:2222 {peer}\n" for peer in peers)


@pytest.fixture
def remnanode(node, recorder):
    recorder.on(["docker", "inspect", "remnanode"], agent.Result(0, REMNANODE_HOST))
    return node


def test_panel_peer_through_an_ipv4_mapped_socket(remnanode, recorder):
    recorder.on(["ss", "-Htn"], agent.Result(0, established("[::ffff:198.51.100.5]:41022")))
    api = agent.collect_facts(remnanode)["nodeApi"]
    assert api["panelPeer"] is True and api["otherPeers"] == 0


def test_panel_over_ipv6_ssh_is_not_the_peer_of_the_node_api(remnanode, recorder):
    """The name of the node has A and AAAA: SSH came over IPv6, the backend over IPv4."""
    remnanode.environ["SSH_CONNECTION"] = "2001:db8::5 50000 2001:db8::10 22"
    recorder.on(["ss", "-Htn"], agent.Result(0, established("198.51.100.5:41022")))
    api = agent.collect_facts(remnanode)["nodeApi"]
    assert api["panelPeer"] is False and api["otherPeers"] == 1
    _change, code, answer = apply(remnanode, "node_api.panel_only", {"port": 2222})
    assert code == 1 and answer["error"]["code"] == "panel_not_peer"
    assert read(remnanode, "/etc/kerberos/node-api.nft") is None


def test_node_api_rule_when_the_panel_is_connected(remnanode, recorder):
    recorder.on(["ss", "-Htn"], agent.Result(0, established("[::ffff:198.51.100.5]:41022",
                                                            "192.0.2.99:5000")))  # fmt: skip
    _change, code, answer = apply(remnanode, "node_api.panel_only",
                                  {"port": 2222, "panelIp": "198.51.100.5"})  # fmt: skip
    assert code == 0, answer
    assert "ip saddr 198.51.100.5 counter accept" in read(remnanode, "/etc/kerberos/node-api.nft")


# -- 7. keys that give no login counted as the administrator's ------------------------------
CLOUD_INIT = (
    "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command=\"echo 'Please login as "
    'the user \\"ubuntu\\" rather than the user \\"root\\".\';echo;sleep 10;exit 142" '
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICloudInitCloudInitCloudInit ubuntu@image"
)
BACKUP = (
    'command="/usr/bin/rrsync -ro /srv/",restrict '
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBackupBackupBackupBackupBack backup@nas"
)


def test_forced_command_and_restrict_keys_are_not_a_login():
    assert agent.count_admin_keys(CLOUD_INIT + "\n" + BACKUP + "\n") == 0
    only_from = 'from="192.0.2.10,198.51.100.0/24" ' + ADMIN
    assert agent.count_admin_keys(only_from + "\n") == 1, "from= still lets the person in"
    assert agent.count_admin_keys("no-pty " + ADMIN + "\n") == 1
    comment = ADMIN.rsplit(" ", 1)[0] + " restrict command=x"
    assert agent.count_admin_keys(comment + "\n") == 1, "the comment is not an option"


def test_key_only_refuses_when_root_has_only_such_keys(node):
    write(node, "/root/.ssh/authorized_keys", CLOUD_INIT + "\n" + BACKUP + "\n", 0o600)
    _change, code, answer = apply(node, "ssh.key_only")
    assert code == 1 and answer["error"]["code"] == "no_admin_key"
    assert agent.collect_ssh(node)["adminKeys"] == 0

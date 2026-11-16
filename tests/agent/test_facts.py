"""Agent facts and watch from recorded outputs (tech.md §9.2, §17)."""

import json

import pytest
from agent_helpers import call
from fixture_node import FIXTURES, recorded

from kerberos import agent


@pytest.mark.parametrize("name", ["ubuntu-24.04", "debian-13"])
def test_facts_match_the_reference(name):
    system, _ = recorded(name)
    facts = agent.collect_facts(system)
    assert isinstance(facts.pop("python"), str)
    expected = json.loads((FIXTURES / f"facts-{name}.json").read_text(encoding="utf-8"))
    assert facts == expected


@pytest.mark.parametrize("name", ["ubuntu-24.04", "debian-13"])
def test_watch_matches_the_reference(name):
    system, _ = recorded(name)
    watch = agent.collect_watch(system)
    assert watch.pop("at").endswith("Z")
    expected = json.loads((FIXTURES / f"watch-{name}.json").read_text(encoding="utf-8"))
    assert watch == expected


def test_facts_command_answers_json():
    system, _ = recorded("debian-13")
    code, answer = call(system, ["facts"])
    assert code == 0 and answer["protocol"] == 1 and answer["ssh"]["adminKeys"] == 1


def test_secrets_and_client_addresses_never_leave_the_agent():
    system, _ = recorded("ubuntu-24.04")
    facts = json.dumps(agent.collect_facts(system))
    assert "never-read-this-value" not in facts and "SECRET_KEY" not in facts
    watch = json.dumps(agent.collect_watch(system))
    for client in ("198.51.100.7", "198.51.100.8", "2001:db8:1::7", "198.51.100.200"):
        assert client not in watch
    assert "u1" not in watch and "u2" not in watch


def test_site_check_hashes_structure_not_text(system):
    pages = {
        "a.example.com": (200, {"alt-svc": 'h3=":443"'}, b"<html><body><h1>Hi</h1></body></html>"),
        "b.example.com": (200, {}, b"<html><body><h1>Hello there</h1></body></html>"),
    }
    system.fetch = lambda host, port, sni, path: pages[sni]
    _, a = call(system, ["site-check"], b'{"domain": "a.example.com"}')
    _, b = call(system, ["site-check"], b'{"domain": "b.example.com"}')
    assert a["status"] == 200 and a["altSvc"] == 'h3=":443"'
    assert a["template"] == b["template"]


def test_site_check_without_site(system):
    def refuse(*_args):
        raise ConnectionRefusedError()

    system.fetch = refuse
    code, answer = call(system, ["site-check"], b'{"domain": "a.example.com"}')
    assert code == 0 and answer == {"template": None, "altSvc": None, "status": None}


@pytest.mark.parametrize("domain", ["", "a b.com", "-x.example.com", "x" * 300, "a.example.com;rm"])
def test_site_check_rejects_bad_domains(system, domain):
    code, answer = call(system, ["site-check"], json.dumps({"domain": domain}).encode())
    assert code == 1 and answer["error"]["code"] == "bad_params"


def test_edge_sources_give_nets_not_addresses(system):
    import os

    tail = '+0000] "{} {} HTTP/1.1" 200 1 "-" "-"'
    log = "\n".join(
        [
            "198.51.100.10 - - [16/Nov/2026:11:00:00 " + tail.format("POST", "/api/stream/abc"),
            "198.51.100.11 - - [16/Nov/2026:11:00:01 " + tail.format("GET", "/api/stream/def"),
            "203.0.113.50 - - [16/Nov/2026:11:00:02 " + tail.format("GET", "/api/stream"),
            "192.0.2.77 - - [16/Nov/2026:11:00:03 " + tail.format("GET", "/index.html"),
            "garbage line",
        ]
    )
    path = system.path("/var/log/nginx/access.log")
    os.makedirs(os.path.dirname(path))
    with open(path, "w") as fh:
        fh.write(log)
    code, answer = call(system, ["edge-sources"], b'{"path": "/api/stream"}')
    assert code == 0
    assert answer == {
        "nets": [{"net": "198.51.100.0/24", "count": 2}, {"net": "203.0.113.0/24", "count": 1}]
    }
    assert "198.51.100.10" not in json.dumps(answer)
    code, answer = call(system, ["edge-sources"], b'{"path": "../etc"}')
    assert code == 1 and answer["error"]["code"] == "bad_params"


def test_ruleset_sets_ranges_and_sources():
    ruleset = agent.Ruleset(
        json.dumps(
            {
                "nftables": [
                    {"table": {"family": "inet", "name": "t"}},
                    {"chain": {"family": "inet", "table": "t", "name": "in", "hook": "input"}},
                    {"chain": {"family": "inet", "table": "t", "name": "other"}},
                    {
                        "rule": {
                            "family": "inet",
                            "table": "t",
                            "chain": "in",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                        "right": {"range": [9000, 9002]},
                                    }
                                },
                                {"drop": None},
                            ],
                        }
                    },
                    {
                        "rule": {
                            "family": "inet",
                            "table": "t",
                            "chain": "in",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                        "right": 2222,
                                    }
                                },
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                        "right": "198.51.100.5",
                                    }
                                },
                                {"accept": None},
                            ],
                        }
                    },
                    {
                        "rule": {
                            "family": "inet",
                            "table": "t",
                            "chain": "other",
                            "expr": [
                                {
                                    "match": {
                                        "op": "==",
                                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                        "right": 7000,
                                    }
                                },
                                {"drop": None},
                            ],
                        }
                    },
                ]
            }
        )
    )
    assert ruleset.dropped("tcp") == {9000, 9001, 9002}
    assert ruleset.accepted_from(2222) == ["198.51.100.5"]
    assert ruleset.tables == ["inet t"]
    assert agent.Ruleset("not json").dropped("tcp") == set()


def test_sshd_old_challenge_response_name():
    values = agent.parse_sshd_t("port 22\nchallengeresponseauthentication yes\n")
    assert values["challengeresponseauthentication"] == "yes" and values["port"] == [22]


def test_ufw_profiles_limits_and_v6():
    status = agent.parse_ufw(
        "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
        "To                         Action      From\n--                         ------      ----\n"
        "OpenSSH                    LIMIT IN    Anywhere\n"
        "8000:8002/tcp              ALLOW IN    Anywhere\n"
        "3000                       ALLOW IN    198.51.100.5\n"
        "OpenSSH (v6)               LIMIT IN    Anywhere (v6)\n"
    )
    assert status["state"] == "active" and status["deny"]
    assert (22, "tcp") in status["allowed"] and (8001, "tcp") in status["allowed"]
    assert (3000, "tcp") not in status["allowed"]
    assert agent.parse_ufw("")["state"] == "absent"


def test_fail2ban_local_overrides_conf():
    configs = [
        ("jail.conf", "[sshd]\nport = ssh\nenabled = false\n"),
        ("jail.d/defaults-debian.conf", "[sshd]\nenabled = true\n"),
        ("jail.local", "[sshd]\nport = 0:65535 ; everything\n"),
    ]
    assert agent.parse_fail2ban(configs, [22, 24622]) == {"enabled": True, "jailPorts": [22, 24622]}


def test_admin_keys_skip_the_kerberos_key():
    text = (
        "ssh-ed25519 AAAA admin@laptop\n# comment\n"
        'from="198.51.100.5",command="/usr/local/sbin/kerberos-agent",restrict ssh-ed25519 AAAB k\n'
        "no-pty ssh-rsa AAAC deploy\n"
    )
    assert agent.count_admin_keys(text) == 2


def test_listen_addresses():
    sockets = agent.parse_ss_listen(
        'tcp LISTEN 0 4096 [fe80::1%eth0]:8080 [::]:* users:(("x",pid=1,fd=3))\n'
        "udp UNCONN 0 0 *:51820 *:*\n"
        "garbage\n"
    )
    assert sockets == [
        {"proto": "tcp", "address": "fe80::1", "port": 8080, "process": "x"},
        {"proto": "udp", "address": "0.0.0.0", "port": 51820, "process": ""},
    ]

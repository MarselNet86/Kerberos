"""Renewals that need port 80 move to the webroot of self-steal (tech.md §10.4, K16).

acme.sh and certbot in standalone mode open :80 for each renewal and give up when it is
taken; after self_steal.site nginx holds it for good. The 3x-ui installer issues the
panel's IP certificate that way, for 6 days.
"""

import base64
import json
import os
import re
import shutil
import uuid
from pathlib import Path

import pytest
from agent_helpers import call

from kerberos import agent

DOMAIN = "vpn.example.com"
IP = "203.0.113.50"
CERTS = Path(__file__).resolve().parent.parent / "fixtures" / "agent" / "certs"
ACME_DIR = f"{agent.ACME_HOME}/{IP}_ecc"
ACME_CONF = f"{ACME_DIR}/{IP}.conf"
CERTBOT_CONF = f"{agent.CERTBOT_RENEWAL}/old.example.com.conf"
CERTBOT_CERT = "/etc/letsencrypt/live/old.example.com/cert.pem"


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


def acme_text(webroot="no", port="80", pre_hook="", alt="no", domain=IP, renew="1763899999"):
    """A domain conf as the 3x-ui installer leaves it (acme.sh --standalone --httpport 80)."""
    hook = ""
    if pre_hook:  # acme.sh keeps hooks in base64 between markers
        encoded = base64.b64encode(pre_hook.encode()).decode()
        hook = f"__ACME_BASE64__START_{encoded}__ACME_BASE64__END_"
    return (
        f"Le_Domain='{domain}'\nLe_Alt='{alt}'\nLe_Webroot='{webroot}'\nLe_PreHook='{hook}'\n"
        "Le_PostHook=''\nLe_RenewHook=''\nLe_API='https://acme-v02.api.letsencrypt.org/directory'\n"
        f"Le_Keylength='ec-256'\nLe_HTTPPort='{port}'\nLe_CertificateProfile='shortlived'\n"
        f"Le_NextRenewTime='{renew}'\n"
        "Le_ReloadCmd='__ACME_BASE64__START_c3lzdGVtY3RsIHJlc3RhcnQgeC11aQ==__ACME_BASE64__END_'\n"
    )


def certbot_text(method="standalone", extra="", version="2.9.0"):
    return (
        f"# renew_before_expiry = 30 days\nversion = {version}\n"
        "archive_dir = /etc/letsencrypt/archive/old.example.com\n"
        f"cert = {CERTBOT_CERT}\n"
        "privkey = /etc/letsencrypt/live/old.example.com/privkey.pem\n"
        "chain = /etc/letsencrypt/live/old.example.com/chain.pem\n"
        "fullchain = /etc/letsencrypt/live/old.example.com/fullchain.pem\n\n"
        "# Options used in the renewal process\n[renewalparams]\n"
        "account = 0123456789abcdef0123456789abcdef\n"
        f"authenticator = {method}\n{extra}"
        "server = https://acme-v02.api.letsencrypt.org/directory\nkey_type = ecdsa\n"
    )


class Nginx:
    """nginx on :80 as KERBEROS configures it: the self-steal block answers the names of
    its server_name with the webroot; any other Host lands on the default site."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.asked: list = []
        self.addresses: list = []
        self.down = False

    def __call__(self, address, host, path):
        self.asked.append(host)
        self.addresses.append(address)
        conf = Path(self.root, agent.SITE_CONF.lstrip("/"))
        block = conf.read_text().split("server {")[1] if conf.exists() else ""
        names = re.search(r"server_name ([^;]+);", block)
        served = names.group(1).split() if names else []
        header = f"[{host}]" if ":" in host else host
        if self.down or header not in served or not path.startswith("/.well-known/acme-challenge/"):
            return 404, "<html><body>404 Not Found</body></html>"
        file = Path(self.root, agent.ACME_ROOT.lstrip("/"), path.lstrip("/"))
        return (200, file.read_text()) if file.exists() else (404, "")


@pytest.fixture
def nginx(tmp_path):
    return Nginx(str(tmp_path))


@pytest.fixture
def node(tmp_path, recorder, nginx):
    system = agent.System(root=str(tmp_path), run=recorder, environ={}, http=nginx)
    for prefix in (["nginx"], ["systemctl"], ["certbot"], ["apt-get"], ["docker"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(
        ["ss"], agent.Result(0, 'tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=7))\n')
    )
    return system


def with_acme(system, **kwargs):
    write(system, ACME_CONF, acme_text(**kwargs))
    shutil.copy(CERTS / "ip.pem", system.path(f"{ACME_DIR}/{IP}.cer"))


def with_certbot(system, **kwargs):
    write(system, CERTBOT_CONF, certbot_text(**kwargs))
    os.makedirs(os.path.dirname(system.path(CERTBOT_CERT)), exist_ok=True)
    shutil.copy(CERTS / "old-example.pem", system.path(CERTBOT_CERT))


def apply(system, domain=DOMAIN, seed=1):
    change = str(uuid.uuid4())
    params = json.dumps({"domain": domain, "siteSeed": seed}).encode()
    code, answer = call(system, ["apply", "self_steal.site", change], params)
    return change, code, answer


def probe_left(system) -> list:
    folder = system.path(agent.CHALLENGES)
    return os.listdir(folder) if os.path.isdir(folder) else []


def test_facts_name_the_renewals_that_need_port_80(node):
    with_acme(node)
    with_certbot(node)
    not_after = agent.cert_not_after(str(CERTS / "ip.pem"))
    assert agent.collect_facts(node)["acme"] == [
        {"tool": "acme.sh", "name": IP, "names": [IP], "notAfter": not_after},
        {"tool": "certbot", "name": "old.example.com",
         "names": ["old.example.com", "www.old.example.com"],
         "notAfter": agent.cert_not_after(str(CERTS / "old-example.pem"))},
    ]  # fmt: skip


def test_the_3xui_ip_certificate_renews_through_nginx(node, nginx):
    with_acme(node)
    change, code, answer = apply(node)
    assert code == 0, answer
    assert f"server_name {DOMAIN} {IP};" in read(node, agent.SITE_CONF)
    # Only the method changed: acme.sh keeps its own lines.
    assert read(node, ACME_CONF) == acme_text(webroot=agent.ACME_ROOT)
    assert answer["details"]["renewals"] == [{"tool": "acme.sh", "name": IP, "names": [IP]}]
    assert nginx.asked == [IP]  # the probe, asked the way the CA asks for an IP
    assert probe_left(node) == []
    assert agent.collect_facts(node)["acme"] == []


def test_certbot_standalone_renews_through_the_webroot(node):
    with_certbot(node)
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert (f"server_name {DOMAIN} old.example.com www.old.example.com;"
            in read(node, agent.SITE_CONF))  # fmt: skip
    assert read(node, CERTBOT_CONF) == certbot_text(
        method="webroot", extra=f"webroot_path = {agent.ACME_ROOT},\n"
    )


def test_nothing_moves_when_nginx_does_not_answer(node, nginx):
    with_acme(node)
    with_certbot(node)
    nginx.down = True
    before = {path: read(node, path) for path in (ACME_CONF, CERTBOT_CONF)}
    _change, code, answer = apply(node)
    assert code != 0 and answer["error"]["code"] == "acme_check_failed"
    assert {path: read(node, path) for path in before} == before
    assert read(node, agent.SITE_CONF) is None  # the change went back as a whole
    assert probe_left(node) == []


def test_a_failed_certificate_leaves_the_renewals(node, recorder):
    with_acme(node)
    recorder.on(["certbot"], agent.Result(1, "", "challenge failed"))
    _change, code, answer = apply(node)
    assert answer["error"]["code"] == "certbot_failed"
    assert read(node, ACME_CONF) == acme_text()


def test_rollback_after_renewals_returns_only_the_method(node):
    with_acme(node)
    with_certbot(node)
    change, code, _answer = apply(node)
    assert code == 0
    # Both tools renewed meanwhile and rewrote their files.
    write(node, ACME_CONF, acme_text(webroot=agent.ACME_ROOT, renew="1764400000"))
    write(node, CERTBOT_CONF, certbot_text(
        method="webroot", extra=f"webroot_path = {agent.ACME_ROOT},\n", version="2.11.0",
    ) + f"[[webroot_map]]\nold.example.com = {agent.ACME_ROOT}\n"
        f"www.old.example.com = {agent.ACME_ROOT}\n")  # fmt: skip
    code, answer = call(node, ["rollback", change])
    assert code == 0, answer
    assert read(node, ACME_CONF) == acme_text(renew="1764400000")
    assert read(node, CERTBOT_CONF) == certbot_text(version="2.11.0")


def test_rollback_keeps_a_method_changed_after_kerberos(node):
    with_acme(node)
    change, code, _answer = apply(node)
    assert code == 0
    write(node, ACME_CONF, acme_text(webroot="/var/www/html"))
    code, answer = call(node, ["rollback", change])
    assert code == 0, answer
    assert agent.acme_conf(read(node, ACME_CONF))["Le_Webroot"] == "/var/www/html"
    record = json.loads(read(node, f"{agent.change_dir(change)}/rollback.json"))
    assert record["details"]["renewalsLeft"] == [ACME_CONF]


def test_another_self_steal_keeps_the_moved_names(node):
    with_acme(node)
    _first, code, _answer = apply(node)
    assert code == 0
    _second, code, answer = apply(node, domain="vpn2.example.com", seed=3)
    assert code == 0, answer
    assert f"server_name vpn2.example.com {IP};" in read(node, agent.SITE_CONF)
    assert answer["details"]["renewals"] == []
    assert agent.acme_conf(read(node, ACME_CONF))["Le_Webroot"] == agent.ACME_ROOT


def test_renewals_that_stop_nginx_themselves_stay(node):
    with_acme(node, pre_hook="systemctl stop nginx")
    with_certbot(node, extra="pre_hook = systemctl stop nginx\npost_hook = systemctl start nginx\n")
    assert agent.collect_facts(node)["acme"] == []
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert agent.acme_conf(read(node, ACME_CONF))["Le_Webroot"] == "no"
    assert "authenticator = standalone" in read(node, CERTBOT_CONF)
    assert f"server_name {DOMAIN};" in read(node, agent.SITE_CONF)


def test_standalone_on_another_port_is_not_ours(node):
    with_acme(node, port="8080")
    with_certbot(node, extra="http01_port = 8080\n")
    assert agent.collect_facts(node)["acme"] == []


@pytest.mark.parametrize("alt", ["*.example.net", "fe80::1%eth0", "fe80::1%x;}server{"])
def test_a_name_nginx_cannot_answer_stops_before_any_change(node, recorder, alt):
    with_acme(node, alt=alt)
    [fact] = agent.collect_facts(node)["acme"]
    assert fact["blocked"] == "name"
    _change, code, answer = apply(node)
    assert answer["error"]["code"] == "acme_standalone"
    assert not [c for c in recorder.calls if c[0] in ("nginx", "certbot", "apt-get")]
    assert read(node, agent.SITE_CONF) is None


def test_an_ipv6_name_is_served_in_brackets(node, nginx):
    with_acme(node, alt="2001:DB8::50")
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert f"server_name {DOMAIN} {IP} [2001:db8::50];" in read(node, agent.SITE_CONF)
    assert nginx.asked == [IP, "2001:db8::50"]


def test_only_standalone_domains_of_a_conf_move(node):
    conf = f"{agent.ACME_HOME}/old.example.com_ecc/old.example.com.conf"
    write(node, conf, acme_text(domain="old.example.com", alt="www.old.example.com",
                                webroot="/var/www/html,no"))  # fmt: skip
    [found] = agent.renewals(node)
    assert (found["names"], found["state"]) == (["www.old.example.com"], "move")
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert agent.acme_conf(read(node, conf))["Le_Webroot"] == f"/var/www/html,{agent.ACME_ROOT}"


def test_plan_names_the_renewal_files_without_their_text(node):
    with_acme(node)
    params = json.dumps({"domain": DOMAIN, "siteSeed": 1}).encode()
    code, answer = call(node, ["plan", "self_steal.site"], params)
    assert code == 0, answer
    assert {"path": ACME_CONF, "content": None} in answer["files"]


def test_a_move_in_the_record_but_not_in_the_file_is_not_left(node):
    with_acme(node)
    record = {"changeId": str(uuid.uuid4()), "details": {},
              "renewals": [{"path": ACME_CONF, "tool": "acme.sh", "before": "no",
                            "after": agent.ACME_ROOT}]}  # fmt: skip
    agent.revert_renewals(node, record)
    assert "renewalsLeft" not in record["details"]
    assert read(node, ACME_CONF) == acme_text()


GLOBAL_STOP = "/etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh"


def test_a_global_certbot_hook_that_stops_nginx_keeps_its_renewal(node, recorder):
    with_certbot(node)
    write(node, GLOBAL_STOP, "#!/bin/sh\nsystemctl stop nginx\n", 0o755)
    assert agent.collect_facts(node)["acme"] == []  # it frees :80 itself, as before
    # ...but the domain's own certificate would renew through the nginx it stops (K17)
    _change, code, answer = apply(node)
    assert answer["error"]["code"] == "certbot_hook"
    assert read(node, CERTBOT_CONF) == certbot_text()
    assert not [c for c in recorder.calls if c[0] in ("nginx", "certbot", "apt-get")]


@pytest.mark.parametrize("hook", ["systemctl reload nginx", "nginx -t && echo ok"])
def test_a_hook_that_does_not_stop_nginx_does_not_free_the_port(node, hook):
    with_certbot(node, extra=f"pre_hook = {hook}\n")
    assert [r["name"] for r in agent.collect_facts(node)["acme"]] == ["old.example.com"]
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert "authenticator = webroot" in read(node, CERTBOT_CONF)


@pytest.mark.parametrize("cli", ["authenticator = standalone\n", "standalone = true\n",
                                 "webroot-path = /var/www/html\n"])  # fmt: skip
def test_cli_ini_that_picks_the_method_stops_self_steal(node, recorder, cli):
    with_certbot(node)
    write(node, agent.CERTBOT_CLI, "rsa-key-size = 4096\n" + cli)
    [fact] = agent.collect_facts(node)["acme"]
    assert fact["blocked"] == "cli.ini"
    _change, code, answer = apply(node)
    assert answer["error"]["code"] == "acme_standalone"
    assert read(node, CERTBOT_CONF) == certbot_text()
    assert not [c for c in recorder.calls if c[0] in ("nginx", "certbot", "apt-get")]


def test_an_old_webroot_map_follows_the_move_and_comes_back(node):
    old = "webroot_path = /var/www/html,\n"
    text = certbot_text(extra=old) + "[[webroot_map]]\nold.example.com = /var/www/html\n"
    with_certbot(node)
    write(node, CERTBOT_CONF, text)
    change, code, answer = apply(node)
    assert code == 0, answer
    moved = read(node, CERTBOT_CONF)
    # certbot's webroot plugin takes the map before webroot_path: both point at nginx now
    assert f"old.example.com = {agent.ACME_ROOT}" in moved
    assert f"webroot_path = {agent.ACME_ROOT}," in moved and "/var/www/html" not in moved
    code, answer = call(node, ["rollback", change])
    assert code == 0, answer
    assert read(node, CERTBOT_CONF) == text


def test_an_idn_name_is_served_in_punycode(node, nginx):
    name = "пример.рф"
    conf = f"{agent.ACME_HOME}/{name}_ecc/{name}.conf"
    write(node, conf, acme_text(domain=name))
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert f"server_name {DOMAIN} xn--e1afmkfd.xn--p1ai;" in read(node, agent.SITE_CONF)
    assert nginx.asked == ["xn--e1afmkfd.xn--p1ai"]


def test_the_probe_goes_to_a_public_address_of_the_server(node, nginx, recorder):
    addresses = [{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1",
                                                  "scope": "host"}]},
                 {"ifname": "eth0", "addr_info": [{"family": "inet", "local": IP,
                                                    "scope": "global"}]}]  # fmt: skip
    recorder.on(["ip", "-j", "addr", "show"], agent.Result(0, json.dumps(addresses)))
    with_acme(node)
    _change, code, answer = apply(node)
    assert code == 0, answer
    assert nginx.addresses == [IP]  # nginx picks servers by that address first, as for the CA


def test_the_probe_is_part_of_the_change(node):
    with_acme(node)
    change, code, _answer = apply(node)
    assert code == 0
    record = json.loads(read(node, f"{agent.change_dir(change)}/rollback.json"))
    entry = next(e for e in record["files"] if e["path"] == agent.PROBE)
    assert entry["existed"] is False  # an interrupted apply or its rollback removes it
    assert not os.path.exists(node.path(agent.PROBE))

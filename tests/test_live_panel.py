"""K19: what the run on a real Remnawave 2.8.1 with two remnanode 2.8.0 nodes found.

Each test replays one finding of that run and failed before its fix.
"""

from types import SimpleNamespace

from demo_input import demo_input
from test_review_logic import (
    APPLY,
    DONE,
    NL1,
    ROLLBACK,
    Hooked,
    changes_of,
    domain_keys,
    fix,
    fix_run,
    fleet,
    profile_of,
    raw_node,
)
from test_ssh_port_flow import all_and_ports, run_fix

from kerberos.checks import spec
from kerberos.copy import TEXT, t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK
from kerberos.report.view import action, problems
from kerberos.screens.rollback import label


# -- 1: client sockets of DHCP and NTP are not open ports ---------------------------------
def node_ports(data, name, *sockets):
    item = next(i for i in data.nodes if i.node.name == name)
    item.facts["listening"] = item.facts["listening"] + [
        {"proto": proto, "address": address, "port": port, "process": process,
         "docker": False, "firewalled": False}
        for proto, address, port, process in sockets
    ]  # fmt: skip
    found = [f for f in spec("ports.public").rule(data) if f["target"] == f"node:{item.node.uuid}"]
    return found[0]["evidence"]["ports"]


def test_dhcp_and_ntp_clients_are_no_open_ports():
    _env, data = demo_input()
    ip = next(i for i in data.nodes if i.node.name == "nl-2").ipv4
    ports = node_ports(
        data, "nl-2",
        ("udp", ip, 68, "systemd-network"),  # systemd-networkd: «203.0.113.x%eth0:68»
        ("udp", "0.0.0.0", 68, "dhclient"),
        ("udp", "::", 546, "dhclient"),
        ("udp", "0.0.0.0", 47710, "systemd-timesyn"),
    )  # fmt: skip
    # Before K19: ['68/udp', '546/udp', '47710/udp'], and ports.drop put `udp dport 68 drop`
    # on the node: the answers to the renewal of its own address never came in.
    assert ports == []


def test_a_udp_service_is_still_an_open_port():
    _env, data = demo_input()
    ports = node_ports(data, "nl-2", ("udp", "0.0.0.0", 51820, "wireguard"),
                       ("udp", "0.0.0.0", 123, "ntpd"))  # fmt: skip
    assert ports == ["123/udp", "51820/udp"]


# -- 2: a fix that does not apply says what to do by hand, in its own words ------------------
def finding(check_id, **evidence):
    return {"checkId": check_id, "ok": False, "fixId": None, "evidence": evidence}


def test_panel_without_the_caddy_of_the_portal_is_fixed_by_hand():
    text, _style = action(finding("panel.public", status=200, proxy="arch"))
    # Before K19 it read «Вручную: паддинг настроен частично, его правят руками».
    assert "паддинг" not in text
    assert text == t("action.manual", how=TEXT["check.panel.public.manual"])


def test_partial_padding_and_a_pinned_3xui_port_keep_their_own_words():
    padding, _style = action(finding("xhttp.padding", server=True, hosts=0, of=1))
    assert padding == "Вручную: паддинг настроен частично, его правят руками"
    xui, _style = action(finding("xui.panel_exposed", port=2053, secretPath=True))
    assert xui == t("action.manual", how=TEXT["check.xui.panel_exposed.manual"])
    assert "KERBEROS переносит" not in xui


# -- 3: self-steal waits until the panel has the node back -----------------------------------
def test_self_steal_waits_for_the_node_the_panel_restarts():
    """node.letsencrypt_mount recreates remnanode right before the profile: the panel found the
    container again about 8 s later, when Xray already answered with the site."""
    base, nodes = fleet()
    nl1 = profile_of(base, "nl-1")["uuid"]
    state = {"patched": False, "reads": 0}

    def hook(method, path, n, body):
        node = raw_node(base, "nl-1")
        if (method, path) == ("PATCH", "/config-profiles") and body["uuid"] == nl1:
            if not state["patched"]:
                state["patched"] = True
                node["isConnected"] = False  # the panel has not found the container yet
        elif (method, path) == ("GET", "/nodes") and state["patched"] and not node["isConnected"]:
            state["reads"] += 1
            node["isConnected"] = state["reads"] >= 3  # its health check brings the node back
        return None

    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE,
                           Hooked(base, hook), nodes)  # fmt: skip
    run = fix_run(app)
    profile = changes_of(run, "self_steal.profile")[0]
    assert (profile["state"], profile["error"]) == ("applied", None)  # was node_offline
    assert code == EXIT_OK
    assert state["reads"] == 3


# -- 4, 5: report.md of «Исправление» -------------------------------------------------------
def test_fix_report_lists_what_is_left_and_the_new_ssh_port():
    nodes = {n.name: n for n in build_nodes()}
    app, _term, code = run_fix(all_and_ports("nl-1") + ["enter"], nodes)
    assert code == EXIT_OK
    store = RunStore(app.env.state, app.env.clock)
    run = store.runs()[0]
    report = store.report_text(run["runId"])
    left = problems(run["findingsAfter"])
    # Before K19 the findings before the fix: «Исправит KERBEROS» for what it had just fixed.
    assert report.count("\n- ● ") == len(left) < len(problems(run["findings"]))
    port = next(c for c in run["changes"] if c["fixId"] == "ssh.port")["details"]["newPort"]
    assert f"| nl-1 | 203.0.113.10 | {port} |" in report  # was 22, the port of the start


def test_rollback_report_has_the_old_ssh_port_again():
    nodes = {n.name: n for n in build_nodes()}
    app, _term, code = run_fix(all_and_ports("nl-1") + ["enter"], nodes)
    assert code == EXIT_OK
    app.env.terminal.feed(*ROLLBACK, "x")  # the run, all changes, consent, the notice
    assert app.run("rollback") == EXIT_OK
    store = RunStore(app.env.state, app.env.clock)
    rolled = next(r for r in store.runs() if r["mode"] == "rollback")
    # The fix run says 29xxx now; the rollback has the node on its old port again.
    assert "| nl-1 | 203.0.113.10 | 22 |" in store.report_text(rolled["runId"])


# -- 7: the rollback list names hosts and templates ------------------------------------------
def test_rollback_list_names_the_host_of_a_change():
    app = SimpleNamespace(mask=lambda value: value)
    run = {"nodes": [{"uuid": "n1", "name": "lab-nl-1"}]}
    nl = {"fixId": "host.fingerprint", "target": "host:h1", "params": {"remark": "NL Reality"}}
    de = {"fixId": "host.fingerprint", "target": "host:h2", "params": {"remark": "DE Reality"}}
    # Before K19 both read «панель: Fingerprint firefox у хоста».
    assert label(app, run, nl) == "хост NL Reality: " + t("fix.host.fingerprint.label")
    assert label(app, run, nl) != label(app, run, de)


# -- 9: S2 names the menu items the way the Russian panel shows them -------------------------
def test_token_hint_follows_the_panel_menu():
    assert "Настройки Remnawave → API токены" in TEXT["panel.token_hint"]
    assert "Создать API токен" in TEXT["panel.token_hint"]

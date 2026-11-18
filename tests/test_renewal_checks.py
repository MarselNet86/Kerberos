"""Renewals that already run into port 80 (tech.md §10.2, §10.4, K17).

`acme.port80`: a certificate renews by its own listener on :80 while another program holds
the port. `acme.stop_hook`: a pre-hook of every certbot renewal stops nginx on a node with
the site of KERBEROS. Both give findings only where such renewals or the site exist.
"""

import pytest
from demo_input import demo_input
from helpers import seen
from test_xui_flow import STEAL_ROW, TO_PLAN, local_node, xui_app

from kerberos.agent import SITE_CONF
from kerberos.checks import spec
from kerberos.copy import t
from kerberos.fixes.plan import self_steal_blocker

RENEWAL = {"tool": "acme.sh", "name": "203.0.113.10", "names": ["203.0.113.10"],
           "notAfter": "2026-11-24T00:00:00Z"}  # fmt: skip


@pytest.fixture
def data():
    return demo_input()[1]


def results(data, check_id):
    return [f for f in spec(check_id).rule(data) if f["checkId"] == check_id]


def with_facts(data):
    return [n for n in data.nodes if n.facts is not None]


def listening80(process):
    return {"proto": "tcp", "address": "0.0.0.0", "port": 80, "process": process,
            "docker": False, "firewalled": False}  # fmt: skip


def site(name):
    return {"file": SITE_CONF, "serverNames": [name], "listen": ["80", "[::]:80"]}


def test_the_demo_fleet_gives_no_renewal_findings(data):
    # the demo has neither renewals on :80 nor the site of KERBEROS: its score stays (§12.4)
    assert results(data, "acme.port80") == [] and results(data, "acme.stop_hook") == []


@pytest.mark.parametrize("holder", ["nginx", "caddy"])
def test_a_renewal_behind_a_busy_port_is_found(data, holder):
    node = with_facts(data)[0]
    node.facts["acme"] = [RENEWAL]
    node.facts["listening"].append(listening80(holder))
    [found] = results(data, "acme.port80")
    assert found["ok"] is False and found["target"] == f"node:{node.node.uuid}"
    assert found["evidence"] == {"names": ["203.0.113.10"], "holders": [holder]}
    assert found["fixId"] is None  # manual: self-steal moves it only where it runs anyway


def test_a_renewal_with_a_free_port_passes(data):
    node = with_facts(data)[0]
    node.facts["acme"] = [RENEWAL]
    node.facts["listening"] = [s for s in node.facts["listening"] if s["port"] != 80]
    [found] = results(data, "acme.port80")
    assert found["ok"] is True


def test_a_moved_renewal_leaves_no_finding(data):
    node = with_facts(data)[0]
    node.facts["listening"].append(listening80("nginx"))
    node.facts["acme"] = []  # self-steal moved it to nginx
    assert results(data, "acme.port80") == []


def test_a_hook_that_stops_nginx_is_found_on_a_node_with_the_site(data):
    node = with_facts(data)[0]
    node.facts["nginx"]["sites"].append(site("nl-1.example.com"))
    node.facts["certbot"]["stopsNginx"] = True
    [found] = results(data, "acme.stop_hook")
    assert found["ok"] is False and found["evidence"] == {"names": ["nl-1.example.com"]}
    node.facts["certbot"]["stopsNginx"] = False
    [found] = results(data, "acme.stop_hook")
    assert found["ok"] is True


def test_a_hook_on_a_node_without_the_site_is_not_this_check(data):
    node = with_facts(data)[0]
    node.facts["certbot"]["stopsNginx"] = True
    assert results(data, "acme.stop_hook") == []


def test_the_hook_blocks_self_steal(data):
    node = next(n for n in with_facts(data) if self_steal_blocker(data, n) is None)
    node.facts["certbot"]["stopsNginx"] = True
    assert self_steal_blocker(data, node) == "certbot_hook"


def test_plan_shows_why_self_steal_is_off():
    keys = TO_PLAN + ["down"] * STEAL_ROW + ["esc", "q", "enter"]  # the row, its details, out
    app, term = xui_app(keys)
    local_node(app).state["facts"]["certbot"]["stopsNginx"] = True
    app.run("fix")
    assert seen(term, t("plan.blocked.certbot_hook"))
    assert [cmd for _a, cmd in app.env.transport.log if cmd.startswith("apply")] == []

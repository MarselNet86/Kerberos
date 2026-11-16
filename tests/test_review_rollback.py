"""What the review of the node side found (K13), on the KERBEROS side: the rollback of
a run, the SSH transport and S4 picking the node address."""

import pytest
from helpers import login_keys, make_app, seen, typed

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_ROLLBACK_FAILED
from kerberos.nodes.transport import NodeAgentError

# Same keys as tests/test_fix_flow.py and tests/test_ssh_port_flow.py.
TO_PLAN = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]
DEFAULT_APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept, S9
EVERYTHING = ["a", "enter", "enter", "enter"]  # ssh.port too
ROLLBACK = ["enter", "enter", "enter"] + list("admin") + ["enter"] + list("pw") + ["enter"]
NL1 = "203.0.113.10"


def fixed(keys, nodes):
    app, term = make_app(TO_PLAN + keys, nodes=list(nodes.values()), height=44)
    app.run("fix")
    return app, term


def demo_nodes():
    return {n.name: n for n in build_nodes()}


def run_of(app, run_id):
    return RunStore(app.env.state, app.env.clock).load(run_id)


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


def changes_of(run, uuid):
    return [c for c in run["changes"] if c["target"] == f"node:{uuid}"]


def uuid_of(app, name):
    return next(u for u, r in app.env.state.nodes().items() if r.name == name)


class Spy:
    """Agent calls with the port they went to."""

    def __init__(self, transport):
        self.calls = []
        self.inner = transport.agent

        def agent(target, command, payload=None, **kwargs):
            self.calls.append((target.address, target.port, command, kwargs.get("fresh", False)))
            return self.inner(target, command, payload, **kwargs)

        transport.agent = agent


# -- 2. a change that does not go back stops the earlier changes of its node ---------------
def test_failed_rollback_keeps_the_earlier_changes_of_the_node():
    nodes = demo_nodes()
    app, _term = fixed(DEFAULT_APPLY, nodes)
    first = last_run(app)
    nl1 = changes_of(first, uuid_of(app, "nl-1"))
    fixes = [c["fixId"] for c in nl1]
    assert fixes.index("access.admin_keys") < fixes.index("ssh.key_only")
    key_only = next(c for c in nl1 if c["fixId"] == "ssh.key_only")
    original = nodes["nl-1"].handlers["rollback"]

    def rollback(node, args, data):
        # A later run changed 10-kerberos.conf (ssh.port in sshd_config mode).
        if args[0] == key_only["changeId"]:
            raise NodeAgentError("change_conflict", "10-kerberos.conf changed after KERBEROS")
        return original(node, args, data)

    nodes["nl-1"].handlers["rollback"] = rollback
    admin_keys = list(nodes["nl-1"].authorized_keys)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    after = {c["changeId"]: c for c in run_of(app, first["runId"])["changes"]}
    assert after[key_only["changeId"]]["error"] == "change_conflict"
    earlier = [after[c["changeId"]] for c in nl1 if c["fixId"] != "ssh.key_only"]
    assert earlier and all(c["error"] == "rollback_skipped" for c in earlier)
    assert all(c["state"] != "rolled_back" for c in earlier)
    assert nodes["nl-1"].authorized_keys == admin_keys, "the administrator key stays"
    assert nodes["nl-1"].state["facts"]["ssh"]["passwordAuthentication"] is False
    others = [c for c in after.values() if c["target"] == f"node:{uuid_of(app, 'nl-2')}"]
    assert others and all(c["state"] == "rolled_back" for c in others), "other nodes go back"


def test_the_fake_agent_keeps_the_admin_key_for_a_later_key_only():
    nodes = demo_nodes()
    app, _term = fixed(DEFAULT_APPLY, nodes)
    nl1 = changes_of(last_run(app), uuid_of(app, "nl-1"))
    keys = next(c for c in nl1 if c["fixId"] == "access.admin_keys")
    with pytest.raises(NodeAgentError) as refused:
        nodes["nl-1"].handlers["rollback"](nodes["nl-1"], [keys["changeId"]], None)
    assert refused.value.code == "change_conflict"


# -- 3. a confirmed ssh.port goes back in two phases ---------------------------------------
def port_change(app, name="nl-1"):
    uuid = uuid_of(app, name)
    return next(c for c in last_run(app)["changes"]
                if c["fixId"] == "ssh.port" and c["target"] == f"node:{uuid}")  # fmt: skip


def test_rollback_of_the_port_is_proved_on_the_old_port():
    nodes = demo_nodes()
    app, _term = fixed(EVERYTHING, nodes)
    change = port_change(app)
    new = change["details"]["newPort"]
    assert change["state"] == "confirmed" and nodes["nl-1"].ssh_port == new
    spy = Spy(app.env.transport)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    mine = [(port, cmd, fresh) for addr, port, cmd, fresh in spy.calls
            if addr == NL1 and change["changeId"] in cmd]  # fmt: skip
    assert mine == [
        (new, f"rollback {change['changeId']}", False),
        (22, f"confirm {change['changeId']}", True),
    ]
    assert nodes["nl-1"].ssh_port == 22 and nodes["nl-1"].state["facts"]["ssh"]["ports"] == [22]
    assert app.env.state.find_node("nl-1").ssh_port == 22


def test_old_port_closed_at_the_hoster_keeps_the_new_port():
    """The person opened the new port at the hoster and closed 22 there."""
    nodes = demo_nodes()
    app, _term = fixed(EVERYTHING, nodes)
    change = port_change(app)
    run_id = last_run(app)["runId"]
    new = change["details"]["newPort"]
    nodes["nl-1"].state["closed_ports"] = [22]
    spy = Spy(app.env.transport)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    after = {c["changeId"]: c for c in run_of(app, run_id)["changes"]}
    port = after[change["changeId"]]
    assert port["state"] == "confirmed" and port["error"] == "port_closed"
    assert nodes["nl-1"].state["facts"]["ssh"]["ports"] == [new], "back to the new port only"
    assert app.env.state.find_node("nl-1").ssh_port == new
    commands = [cmd for addr, _p, cmd, _f in spy.calls if addr == NL1]
    assert f"undo {change['changeId']}" in commands
    hostkeys = next(c for c in changes_of(run_of(app, run_id), uuid_of(app, "nl-1"))
                    if c["fixId"] == "hostkeys.regenerate")  # fmt: skip
    assert hostkeys["error"] == "rollback_skipped", "an earlier change of nl-1 waits"
    assert sum(app.env.clock.slept) >= 55, "the old port had its minute"


# 3x-ui (§7.6): KERBEROS reaches this server on 127.0.0.1 and cannot see the hoster's firewall.
XUI_LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
XUI_PLAN = ["down", "enter"] + XUI_LOGIN + ["enter", "enter", "enter"]
XUI_PORT_ROW = 4


def xui_with_new_port():
    keys = XUI_PLAN + ["down"] * XUI_PORT_ROW + ["space", "enter", "enter", "enter", "enter"]
    app, term = make_app(keys, panel_kind=None, height=44)
    app.run("fix")
    change = next(c for c in last_run(app)["changes"] if c["fixId"] == "ssh.port")
    assert change["state"] == "confirmed"
    return app, term, change


@pytest.mark.parametrize("answer, code", [("enter", EXIT_OK), ("esc", EXIT_ROLLBACK_FAILED)])
def test_xui_rollback_of_the_port_is_tried_from_outside(answer, code):
    from kerberos.demo.xui import XUI_IP

    app, term, change = xui_with_new_port()
    run_id = last_run(app)["runId"]
    new = change["details"]["newPort"]
    app.env.terminal.feed("enter", "enter", "enter", answer, "x")
    assert app.run("rollback") == code
    assert seen(term, t("rb.outside", port=22, command=f"ssh -p 22 root@{XUI_IP}"))
    ssh = app.env.transport.nodes["127.0.0.1"].state["facts"]["ssh"]
    port = next(c for c in run_of(app, run_id)["changes"] if c["changeId"] == change["changeId"])
    if answer == "enter":
        assert port["state"] == "rolled_back" and ssh["ports"] == [22]
        assert app.env.state.node("local").ssh_port == 22
    else:
        assert port["state"] == "confirmed" and port["error"] == "port_closed"
        assert ssh["ports"] == [new] and app.env.state.node("local").ssh_port == new

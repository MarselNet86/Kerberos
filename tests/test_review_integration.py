"""Where the review fixes of K13 meet: a change whose automatic rollback failed and
`kerberos rollback`, the rollback of a port in rollback words, the exit code of a
direct `kerberos fix` left with q."""

from helpers import make_app, seen
from test_review_logic import (
    APPLY,
    DONE,
    ROLLBACK,
    TO_PLAN,
    changes_of,
    fix,
    fix_run,
    fleet,
    raw_node,
)
from test_review_rollback import EVERYTHING, demo_nodes, fixed, port_change

from kerberos.copy import t
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.nodes.transport import NodeAgentError


class Died(Exception):
    """The process is killed in the middle of an apply."""


def stuck_mptcp(panel, nodes):
    """nl-2's mptcp.guard fails its recheck, and its automatic rollback fails too."""
    node = nodes["nl-2"]
    real = dict(node.handlers)

    def facts(n, args, data):
        answer = real["facts"](n, args, data)
        answer["mptcp"]["enabled"] = True
        return answer

    def rollback(n, args, data):
        raise NodeAgentError("backup_damaged", "files/0")

    node.handlers.update(facts=facts, rollback=rollback)
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_ROLLBACK_FAILED
    node.handlers.update(facts=real["facts"], rollback=real["rollback"])
    return app, node


def mptcp_change(app, panel):
    return changes_of(fix_run(app), "mptcp.guard", raw_node(panel, "nl-2")["uuid"])[0]


def test_rollback_settles_a_change_whose_automatic_rollback_failed():
    panel, nodes = fleet()
    app, node = stuck_mptcp(panel, nodes)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    change = mptcp_change(app, panel)
    assert (change["state"], change["error"]) == ("rolled_back", "recheck_failed")
    assert "rollbackError" not in change["details"]
    assert "inet kerberos_mptcp" not in node.state["facts"]["nftTables"]


def test_rollback_that_fails_again_keeps_the_mark_and_says_why():
    panel, nodes = fleet()
    app, node = stuck_mptcp(panel, nodes)
    mptcp = mptcp_change(app, panel)["changeId"]
    real = node.handlers["rollback"]

    def rollback(n, args, data):
        if args[0] == mptcp:
            raise NodeAgentError("change_conflict", "a later change")
        return real(n, args, data)

    node.handlers["rollback"] = rollback
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    change = mptcp_change(app, panel)
    assert change["error"] == "rollback_failed", "still possibly in place"
    assert change["details"]["rollbackError"] == "change_conflict"
    assert change["details"]["failure"] == "recheck_failed"
    assert seen(app.env.terminal, t("error.change_conflict"))


def test_change_cut_short_before_the_agent_acted_counts_as_back():
    panel, nodes = fleet()
    node = nodes["nl-2"]
    real_apply = node.handlers["apply"]

    def apply(n, args, params):
        if args[0] == "mptcp.guard":
            raise Died()  # killed before the agent got the change
        return real_apply(n, args, params)

    node.handlers["apply"] = apply
    app, _term = make_app(TO_PLAN + APPLY, panel=panel, nodes=list(nodes.values()), height=46)
    try:
        app.run("fix")
    except Died:
        pass
    change = mptcp_change(app, panel)
    assert change["state"] == "applying"
    node.handlers["apply"] = real_apply
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    assert mptcp_change(app, panel)["state"] == "rolled_back"


def test_old_port_closed_on_rollback_is_said_in_rollback_words():
    nodes = demo_nodes()
    app, _term = fixed(EVERYTHING, nodes)
    assert port_change(app)["state"] == "confirmed"
    nodes["nl-1"].state["closed_ports"] = [22]
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    assert seen(app.env.terminal, t("rb.port_closed"))
    assert not seen(app.env.terminal, t("error.port_closed"))


def test_quit_on_s9_keeps_the_exit_code_of_a_direct_fix():
    panel, nodes = fleet()
    node = nodes["nl-2"]
    real_facts = node.handlers["facts"]

    def facts(n, args, data):
        answer = real_facts(n, args, data)
        answer["mptcp"]["enabled"] = True  # the recheck fails; the rollback works
        return answer

    node.handlers["facts"] = facts
    app, _term, code = fix(APPLY + ["q", "enter"], panel, nodes)
    assert code == EXIT_PARTIAL

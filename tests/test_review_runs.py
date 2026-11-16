"""Review K13, finalization, the lock and exit codes: each test replays a review scenario."""

from helpers import make_app
from test_review_logic import (
    APPLY,
    DONE,
    NL1,
    ROLLBACK,
    TO_PLAN,
    domain_keys,
    fix,
    fix_run,
    fleet,
)

from kerberos.demo.fleet import build_host
from kerberos.fixes.finalize import unattended
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK
from kerberos.host import CommandResult


def store_of(app):
    return RunStore(app.env.state, app.env.clock)


# -- app 16: a finalization token no timer will use does not stay behind ----------------------
def test_failed_timer_leaves_no_finalize_token():
    panel, nodes = fleet()
    app, _term, _code = fix(domain_keys(NL1, "nl-1.example.com") + ["f"] + APPLY + DONE,
                            panel, nodes)  # fmt: skip
    run = fix_run(app)
    assert any(c[:1] == ("systemd-run",) for c in app.env.host.calls)  # the demo host has none
    assert run["finalizeTimer"] is None
    assert not (store_of(app).path(run["runId"]) / "finalize.token").exists()
    assert panel.api_tokens == {}


def test_timer_of_a_rolled_back_run_drops_its_token():
    panel, nodes = fleet()
    host = build_host()
    host.on(["systemd-run"], CommandResult(0))
    keys = TO_PLAN + domain_keys(NL1, "nl-1.example.com") + ["f"] + APPLY + DONE
    app, _term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46, host=host)
    app.run("fix")
    run = fix_run(app)
    token = store_of(app).path(run["runId"]) / "finalize.token"
    assert token.exists() and run["finalizeTimer"]
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    app.env.clock.advance(24 * 3600 + 1)  # the timer fires: nothing is due any more
    assert unattended(store_of(app), panel, app.env.clock, run["runId"]) == 0
    assert not token.exists() and panel.api_tokens == {}

"""Texts and screens S1–S4, rollback and finalize: findings of the K12 review.

Each test follows the failure scenario of a finding of the UX review (numbers in
the names of the sections below) through the fake terminal.
"""

from datetime import datetime

from helpers import flat, login_keys, make_app, row_of, typed

from kerberos.copy import plural
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK
from kerberos.nodes.keys import demo_blob, fingerprint

TO_S4 = login_keys() + ["enter", "enter"]  # S2 summary, S3
INTRO = ["enter"]  # «Проверка»: what S4 installs, before the first node
# nl-1, nl-2, de-1 (and its python3), fi-1 confirm the host key; kz-1 is unreachable.
ALL_NODES = ["enter", "enter", "enter", "enter", "enter", "esc"]
QUIT = ["q", "enter"]
# «Исправление»: S4 with «Мои ключи» and the checklist, its summary, whois, S6 → S7.
TO_PLAN = TO_S4 + ALL_NODES + ["enter", "enter"] + ["enter", "enter", "enter"]
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter
ROLLBACK = ["enter", "enter", "enter"] + login_keys() + ["x"]  # run, changes, consent, panel
CHOOSE_XUI = ["down", "enter"]  # S2: 3x-ui is the second panel of the demo server
XUI_LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
SHARED = fingerprint(demo_blob("hoster-image"))  # nl-1 and nl-2: one image of the hoster


def strict_panel():
    panel = build_panel()
    panel.accept_any_login = False
    return panel


def first(term, text):
    """Index of the first frame that shows `text`, wrapped or not; None if none does."""
    return next((i for i, f in enumerate(term.frames) if text in flat(f)), None)


def footer(frame):
    return frame.splitlines()[-1]


def title(frame):
    return frame.splitlines()[0]


def words(text):
    """A text as `flat` shows it: line breaks and runs of spaces become one space."""
    return " ".join(text.split())


def solid(frame):
    """Frame text without any spaces: a long path folded over lines reads as one."""
    return "".join(flat(frame).split())


def run_check(nodes=None, state=None, extra=INTRO + ALL_NODES, panel=None):
    keys = TO_S4 + list(extra) + ["enter", "x"] + QUIT
    app, term = make_app(keys, nodes=nodes, state=state, panel=panel or strict_panel())
    app.run("check")
    return app, term


def fix_with_self_steal(nodes=None):
    keys = TO_PLAN + ["down"] * row_of("nl-1", "self_steal") + ["d"]
    keys += list("nl-1.example.com") + ["enter"] + APPLY
    app, term = make_app(keys, nodes=nodes, height=46)
    assert app.run("fix") == EXIT_OK
    return app, term


def store_of(app):
    return RunStore(app.env.state, app.env.clock)


def when(run):
    moment = datetime.strptime(run["startedAt"], "%Y-%m-%dT%H:%M:%SZ")
    return moment.strftime("%d.%m.%Y %H:%M") + " UTC"


# -- 12: the result of a rollback, its scores and how runs are named -------------------
def fix_then(extra_nodes=None):
    nodes = {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + ["enter", "enter", "enter"], nodes=list(nodes.values()),
                         height=40)  # fmt: skip
    assert app.run("fix") == EXIT_OK
    return app, term, nodes, store_of(app).runs()[0]


# -- 24: numbers agree with words, small slips -----------------------------------------
def test_plural_forms():
    forms = ("нода", "ноды", "нод")
    expected = {1: "нода", 2: "ноды", 4: "ноды", 5: "нод", 11: "нод", 12: "нод", 14: "нод",
                21: "нода", 22: "ноды", 25: "нод", 101: "нода", 111: "нод", 0: "нод"}  # fmt: skip
    assert {n: plural(n, *forms) for n in expected} == expected

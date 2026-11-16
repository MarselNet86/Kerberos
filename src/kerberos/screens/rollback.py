"""Rollback of a past run, whole or change by change (tech.md §11.4, §5.3).

Changes go back in reverse order. A change on a node is rolled back by its
agent; the agent refuses when a file was changed after KERBEROS (a later
change touches it): then that later change has to go back first.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Optional

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos.copy import t
from kerberos.fixes.engine import ROLLBACKABLE
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.panel_changes import PANEL_FIXES, undo
from kerberos.flow import EXIT_OK, EXIT_PANEL, EXIT_ROLLBACK_FAILED
from kerberos.nodes.transport import NodeAgentError, Target, TransportError
from kerberos.screens.check import write_report
from kerberos.screens.fix import agree, error_text
from kerberos.ui.widgets import Checklist, Consent, Menu, Notice

if TYPE_CHECKING:
    from kerberos.app import App


def node_of(run: dict, target: str) -> Optional[dict]:
    ref = target.partition(":")[2]
    return next((n for n in run["nodes"] if n["uuid"] == ref), None)


def label(app: App, run: dict, change: dict) -> str:
    target = (
        f"node:{change['params']['node']}" if change["params"].get("node") else change["target"]
    )
    node = node_of(run, target)
    name = node["name"] if node else t("target.panel")
    ports = ", ".join(change["params"].get("ports", []))
    text = t(
        "fix." + change["fixId"] + ".label",
        ports=ports,
        port=change["params"].get("port", ""),
        domain=change["params"].get("domain", ""),
        reserve=(node_of(run, f"node:{change['params'].get('reserve')}") or {}).get("name", ""),
    )
    return f"{app.mask(name)}: {app.mask(text)}"


def choose_run(app: App, runs: list) -> Optional[dict]:
    items = [
        (run["runId"], t("rb.item", run=run["runId"],
                         n=sum(1 for c in run["changes"] if c["state"] in ROLLBACKABLE)), "")
        for run in runs
    ]  # fmt: skip
    menu = Menu(items)

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else menu.handle(key)

    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    body = Group(Text(t("rb.choose"), style="bold"), Text(""), menu)
    choice = app.interact(t("rb.title"), body, keys, handle)
    return next((r for r in runs if r["runId"] == choice), None)


def target_of(app: App, run: dict, change: dict) -> Target:
    target = (
        f"node:{change['params']['node']}" if change["params"].get("node") else change["target"]
    )
    node = node_of(run, target) or {}
    record = app.env.state.node(node.get("uuid", ""))
    if record is not None:
        return record.target(record.address)
    return Target(node.get("uuid", ""), node.get("name", ""), node.get("address", ""),
                  node.get("sshPort", 22))  # fmt: skip


def ask_diff(app: App, diff: str) -> bool:
    """§11.4: the panel object changed after KERBEROS: show how, ask before undoing."""
    from kerberos.screens.check import show_pager

    show_pager(app, t("rb.diff.intro") + "\n\n" + app.mask(diff), t("rb.title"))
    body = Group(Notice("warning", t("rb.diff.question")),
                 Text(f"{t('quit.yes')}    {t('quit.no')}", style="muted"))  # fmt: skip
    app.draw(t("rb.title"), body)
    return app.term.read_key() == "enter"


def roll_back(app: App, run: dict, changes: list, client=None) -> list:
    """Reverse order; returns the changes that did not go back."""
    failed = []
    store = RunStore(app.env.state, app.env.clock)
    # Reverse journal order: changes of one second share a timestamp.
    position = {id(c): i for i, c in enumerate(run["changes"])}
    for change in sorted(changes, key=lambda c: position.get(id(c), -1), reverse=True):
        if change["fixId"] in PANEL_FIXES:
            reason = (
                undo(client, change, ask=lambda diff: ask_diff(app, diff))
                if client
                else ("no_panel")
            )
            if reason:
                change["error"] = reason
                failed.append(change)
                store.save(run)
                continue
            run["pending"] = [p for p in run.get("pending", [])
                              if p.get("changeId") != change["changeId"]]  # fmt: skip
            change["state"] = "rolled_back"
            change["finishedAt"] = iso(app.env.clock)
            store.save(run)
            continue
        target = target_of(app, run, change)
        try:
            app.env.transport.agent(target, f"rollback {change['changeId']}")
        except (NodeAgentError, TransportError) as exc:
            change["error"] = getattr(exc, "code", None) or getattr(exc, "kind", "failed")
            failed.append(change)
            store.save(run)
            continue
        previous = change["details"].get("previousKey")
        if change["fixId"] == "hostkeys.regenerate" and previous:
            app.env.state.pin(target.address, target.port, "ssh-ed25519", previous)
        if change["fixId"] == "ssh.port" and change["details"].get("oldPorts"):
            record = app.env.state.node(target.uuid)
            if record is not None:
                record.ssh_port = change["details"]["oldPorts"][0]
                app.env.state.save_node(record)
        change["state"] = "rolled_back"
        change["finishedAt"] = iso(app.env.clock)
        store.save(run)
    return failed


def rollback_flow(app: App, run_id: Optional[str] = None) -> int:
    store = RunStore(app.env.state, app.env.clock)
    runs = [r for r in store.runs() if any(c["state"] in ROLLBACKABLE for c in r["changes"])]
    if run_id is not None:
        runs = [r for r in runs if r["runId"] == run_id]
    if not runs:
        app.notice("info", t("rb.empty"), t("rb.title"))
        return EXIT_OK
    run = runs[0] if run_id is not None else choose_run(app, runs)
    if run is None:
        return EXIT_OK
    changes = [c for c in run["changes"] if c["state"] in ROLLBACKABLE]
    rows = [[label(app, run, c), t(f"state.{c['state']}")] for c in changes]
    checklist = Checklist(rows, [t("rb.col.change"), t("rb.col.state")],
                          selected=set(range(len(changes))))  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        result = checklist.handle(key)
        return "done" if result == "done" and checklist.selected else None

    keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    while True:
        body = Group(Text(t("rb.changes"), style="bold"), checklist)
        if app.interact(t("rb.title"), body, keys, handle) == "back":
            return EXIT_OK
        chosen = [changes[i] for i in sorted(checklist.selected)]
        summary = Group(Text(t("rb.consent", n=len(chosen))),
                        *[Text("  " + label(app, run, c)) for c in chosen])  # fmt: skip
        if agree(app, t("rb.title"), Consent(summary, t("rb.accept"), t("rb.keys"))):
            break
    client = None
    if any(c["fixId"] in PANEL_FIXES for c in chosen):
        from kerberos.screens.panel import open_panel

        opened = open_panel(app, kind=run["panel"].get("kind", "remnawave"))
        if not isinstance(opened, tuple):
            return EXIT_PANEL if opened == EXIT_PANEL else EXIT_OK
        client = opened[1]
    failed = roll_back(app, run, chosen, client)
    record = store.new_run("rollback", run["panel"], run["nodes"])
    record["changes"] = copy.deepcopy(chosen)
    record["findings"] = run.get("findings", [])
    record["scoreBefore"] = run.get("scoreAfter") or run.get("scoreBefore", 0)
    record["rolledBackRun"] = run["runId"]
    record["finishedAt"] = iso(app.env.clock)
    store.save(record)
    write_report(app, record)
    lines: list[RenderableType] = [
        Text(t("rb.done", ok=len(chosen) - len(failed), total=len(chosen)), style="bold")
    ]
    for change in failed:
        lines.append(Text(f"✗ {label(app, run, change)}: {error_text(change.get('error'))}",
                          style="risk.high"))  # fmt: skip
    if failed:
        lines.append(Notice("error", t("rb.failed")))
    app.notice("info" if not failed else "error", "\n".join(
        str(line.plain) if isinstance(line, Text) else "" for line in lines).strip(),
        t("rb.title"))  # fmt: skip
    return EXIT_ROLLBACK_FAILED if failed else EXIT_OK

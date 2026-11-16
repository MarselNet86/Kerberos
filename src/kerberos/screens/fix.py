"""S7 plan and consent, S8 applying, S9 green report (tech.md §6, §11, §12)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos.checks import run_checks
from kerberos.checks.score import score
from kerberos.copy import TEXT, t
from kerberos.fixes.engine import Engine
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.plan import PlanItem, build_plan, follow_admin_key
from kerberos.flow import BACK, EXIT_INTERRUPTED, EXIT_OK, EXIT_PARTIAL, NEXT
from kerberos.screens.check import report_header, show_pager, write_report
from kerberos.ui.keys import hotkey
from kerberos.ui.widgets import Checklist, Consent, Notice, ProgressBoard

if TYPE_CHECKING:
    from kerberos.app import App, Session

WARNINGS = {
    "ssh.key_only": "fix.key_only.warning",
}
STEP_KEYS = ("backup", "apply", "check", "confirm")


def launcher() -> str:
    return str(Path(__file__).resolve().parent.parent.parent.parent / "kerberos")


def rollback_command(run_id: str) -> str:
    return f"sudo {launcher()} rollback {run_id}"


def fix_label(app: App, item: Any) -> str:
    fix_id = item.fix_id if isinstance(item, PlanItem) else item["fixId"]
    params = item.params if isinstance(item, PlanItem) else item["params"]
    ports = ", ".join(params.get("ports", []))
    return app.mask(t(f"fix.{fix_id}.label", ports=ports))


def node_name(session: Session, target: str) -> str:
    kind, _, ref = target.partition(":")
    node = session.snapshot.node(ref) if kind == "node" else None
    return node.name if node else target


def error_text(code: Optional[str]) -> str:
    if not code:
        return ""
    return TEXT.get(f"error.{code}", code)


# -- S7 -------------------------------------------------------------------------
def step_plan(app: App, session: Session) -> Any:
    data = session.data["input"]
    if "plan" not in session.data:
        records = app.env.state.nodes()
        panel_ips = {uuid: r.panel_ip for uuid, r in records.items()}
        session.data["plan"] = build_plan(
            session.data["findings"], data, session.data.get("admin"), panel_ips
        )
    items: list[PlanItem] = session.data["plan"]
    if not items:
        app.notice("info", t("plan.empty"), t("plan.title"))
        return NEXT
    disabled = {i for i, item in enumerate(items) if item.blocked}
    checklist = Checklist([], [t("plan.col.node"), t("plan.col.fix"), t("plan.col.risk"),
                               t("plan.col.note")],  # fmt: skip
                          selected={i for i, item in enumerate(items) if item.selected},
                          disabled=disabled)  # fmt: skip

    def rows() -> list[list[Any]]:
        result = []
        for item in items:
            note = t(f"plan.blocked.{item.blocked}") if item.blocked else ""
            if not note and item.fix_id in WARNINGS:
                note = t("plan.has_warning")
            risk = Text(f"● {t('risk.' + item.risk)}", style=f"risk.{item.risk}"
                        if item.risk != "info" else "muted")  # fmt: skip
            result.append([app.mask(node_name(session, item.target)), fix_label(app, item), risk,
                           note])  # fmt: skip
        return result

    def body(_w: int, height: int) -> RenderableType:
        checklist.rows = rows()
        for i, item in enumerate(items):
            item.selected = i in checklist.selected
        follow_admin_key(items)
        checklist.selected = {i for i, item in enumerate(items) if item.selected}
        tail: list[RenderableType] = [
            Text(t("plan.selected", n=len(checklist.selected), total=len(items)), style="muted")
        ]
        checklist.viewport = max(4, height - 4)
        return Group(Text(t("plan.title"), style="bold"), checklist, *tail)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return BACK
        result = checklist.handle(key)
        if result == "done":
            return "consent" if checklist.selected else None
        return None

    keys = (
        ("↑↓", t("keys.select")),
        (t("keys.space"), t("keys.toggle")),
        ("a", t("keys.all")),
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
    )
    while True:
        if app.interact(t("plan.title"), body, keys, handle) == BACK:
            return BACK
        for i, item in enumerate(items):
            item.selected = i in checklist.selected
        follow_admin_key(items)
        if consent(app, session, items):
            return NEXT


def consent(app: App, session: Session, items: list[PlanItem]) -> bool:
    """§6 S7: what changes on every node, the warnings of §15 word for word."""
    chosen = [i for i in items if i.selected and not i.blocked]
    lines: list[RenderableType] = [Text(t("consent.intro"), style="bold")]
    by_node: dict = {}
    for item in chosen:
        by_node.setdefault(node_name(session, item.target), []).append(fix_label(app, item))
    for name, labels in by_node.items():
        lines.append(Text(f"  {app.mask(name)}: " + "; ".join(labels)))
    warnings = []
    for item in chosen:
        key = WARNINGS.get(item.fix_id)
        if key and t(key) not in warnings:
            warnings.append(t(key))
    for text in warnings:
        lines.append(Notice("warning", text))
    widget = Consent(Group(*lines), t("consent.accept"), t("consent.keys"))
    app.term.draw(app.frame(t("consent.title"), widget, ()))
    key = app.term.read_key()
    return Consent.handle(key or "")


# -- S8 -------------------------------------------------------------------------
def step_apply(app: App, session: Session) -> Any:
    items: list[PlanItem] = session.data["plan"]
    chosen = [i for i in items if i.selected and not i.blocked]
    names = []
    for item in chosen:
        name = node_name(session, item.target)
        if name not in names:
            names.append(name)
    board = ProgressBoard([app.mask(n) for n in names], [t(f"step.{s}") for s in STEP_KEYS])
    board.node_title, board.fix_title = t("board.node"), t("board.fix")
    board.result_title, board.legend = t("board.result"), t("board.legend")

    def on_event(step: str, item: PlanItem, state: str, note: str) -> None:
        name = app.mask(node_name(session, item.target))
        if step == "backup" and state == "running":
            board.start(name, fix_label(app, item))
        board.set(name, t(f"step.{step}"), state)
        if state in ("failed", "rolled_back"):
            board.finish(name, Text(t("apply.rolled_back", reason=error_text(note) or note),
                                    style="risk.high"))  # fmt: skip

    engine = Engine(app, session, chosen, on_event)
    session.data["engine"] = engine
    app.busy = True

    def tick() -> Optional[str]:
        if engine.done:
            return NEXT
        engine.step()
        return None

    def interrupt() -> Optional[str]:
        body = Group(Notice("warning", t("apply.interrupt")),
                     Text(f"{t('quit.yes')}    {t('quit.no')}", style="muted"))  # fmt: skip
        app.draw(t("s8.title"), body)
        if app.term.read_key() == "enter":
            engine.cancel()
        return None

    keys = (("Ctrl+C", t("keys.interrupt")),)
    try:
        app.interact(t("s8.title"), board, keys, lambda _key: None, timeout=0, tick=tick,
                     interrupt=interrupt, typing=True)  # fmt: skip
    finally:
        app.busy = False
    finish_run(app, session, engine)
    return NEXT


def finish_run(app: App, session: Session, engine: Engine) -> None:
    run = session.data["run"]
    data = session.data["input"]
    after = run_checks(data)
    session.data["findings_after"] = after
    run["scoreAfter"] = score(after)
    run["findingsAfter"] = after
    run["interrupted"] = engine.cancelled
    run["finishedAt"] = iso(app.env.clock)
    store = RunStore(app.env.state, app.env.clock)
    store.save(run)
    applied = sum(1 for c in run["changes"] if c["state"] in ("applied", "confirmed"))
    store.log(run, f"fix: {applied} applied, {engine.failed} failed, score {run['scoreAfter']}")
    write_report(app, run)


# -- S9 -------------------------------------------------------------------------
def change_lines(app: App, session: Session, run: dict) -> list[RenderableType]:
    lines: list[RenderableType] = []
    for change in run["changes"]:
        name = app.mask(node_name(session, change["target"]))
        label = fix_label(app, change)
        if change["state"] in ("applied", "confirmed"):
            lines.append(Text(f"✓ {name}: {label}", style="ok"))
        else:
            reason = error_text(change.get("error"))
            lines.append(Text(f"↺ {name}: {label}. " + t("apply.rolled_back", reason=reason),
                              style="risk.high"))  # fmt: skip
        for key in change["details"].get("hostKeys", []) if change["state"] in (
            "applied", "confirmed") else []:  # fmt: skip
            if key.get("type") == "ED25519":
                node = session.snapshot.node(change["target"].partition(":")[2])
                lines.append(Text("  " + t("s9.hostkey", fingerprint=key["fingerprint"],
                                             address=app.mask(node.address if node else "")),
                                  style="muted"))  # fmt: skip
    return lines


def step_done(app: App, session: Session) -> Any:
    run = session.data["run"]
    engine: Engine = session.data.get("engine")
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    without = [n["name"] for n in run["nodes"] if n["access"] != "ok"]
    after = session.data.get("findings_after", session.data["findings"])

    def body(_w: int, _h: int) -> RenderableType:
        parts: list[RenderableType] = [
            report_header(app, after, run.get("scoreAfter") or run["scoreBefore"],
                          run["scoreBefore"], without, path),
            Text(""),
        ]  # fmt: skip
        if engine is not None and engine.cancelled:
            parts.append(Notice("warning", t("apply.interrupted")))
        lines = change_lines(app, session, run)
        parts += lines or [Text(t("s9.none"), style="muted")]
        if run["changes"]:
            parts += [Text(""), Text(t("done.rollback", command=rollback_command(run["runId"])),
                                     style="bold")]  # fmt: skip
        return Group(*parts)

    def handle(key: str) -> Optional[str]:
        if key in ("enter", "esc"):
            return "done"
        if hotkey(key) == "s":
            text = RunStore(app.env.state, app.env.clock).report_text(run["runId"]) or ""
            show_pager(app, text, t("done.title"))
        return None

    keys = (("s", t("keys.full_report")), ("Enter", t("keys.menu")), ("q", t("keys.quit")))
    app.interact(t("done.title"), body, keys, handle)
    if engine is not None and engine.cancelled:
        return EXIT_INTERRUPTED
    if engine is not None and engine.failed:
        return EXIT_PARTIAL
    return EXIT_OK

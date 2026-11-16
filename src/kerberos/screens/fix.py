"""S7 plan and consent, S8 applying, S9 green report (tech.md §6, §11, §12)."""

from __future__ import annotations

import re
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
from kerberos.ui.widgets import Checklist, Consent, Notice, ProgressBoard, TextInput

if TYPE_CHECKING:
    from kerberos.app import App, Session

STEP_KEYS = ("backup", "apply", "check", "confirm")


def warning_of(item: PlanItem) -> Optional[str]:
    """Warnings of §15 shown before consent, word for word."""
    if item.fix_id == "ssh.key_only":
        return t("fix.key_only.warning")
    if item.fix_id == "ssh.port":
        return t("fix.ssh_port.warning", port=item.params.get("port"))
    if item.fix_id == "self_steal":
        return t("fix.self_steal.warning")
    return None


def extra_warnings(app: App, session: Session, item: PlanItem) -> list[str]:
    """Self-steal also replaces the profile and may restart the node container."""
    if item.fix_id != "self_steal":
        return []
    texts = [t("fix.profile.warning")]
    node = session.data["input"].node_data(item.node_uuid or "")
    facts = node.facts if node else {}
    if not (facts.get("remnanode") or {}).get("letsencryptMounted", True):
        texts.append(t("fix.mount.warning", node=app.mask(node.node.name)))
    return texts


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)


def dns_state(app: App, session: Session, item: PlanItem) -> None:
    """§10.4: A must point to the node's IPv4, AAAA (if any) to its IPv6."""
    domain = item.params.get("domain")
    if not domain:
        item.params["dns"] = "none"
        return
    node = session.data["input"].node_data(item.node_uuid or "")
    addresses = app.env.prober.resolve(domain)
    v4 = [a for a in addresses if ":" not in a]
    v6 = [a for a in addresses if ":" in a]
    want4 = node.ipv4
    want6 = (node.facts or {}).get("ipv6", []) if node else []
    ok = bool(want4) and v4 == [want4] and (not v6 or bool(set(v6) & set(want6)))
    item.params["dns"] = "ok" if ok else "wait"
    item.params["record"] = f"A {domain} → {want4}"
    if ok and item.blocked is None:
        item.selected = True


def ask_domain(app: App, session: Session, item: PlanItem) -> None:
    node = session.snapshot.node(item.node_uuid or "")
    field = TextInput(
        t("plan.domain.label", node=app.mask(node.name if node else "")),
        hint=t("plan.domain.hint"),
        validate=lambda v: None if DOMAIN_RE.match(v.strip().lower()) else t("plan.domain.invalid"),
        value=item.params.get("domain") or "",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    keys = (("Enter", t("keys.next")), ("Esc", t("keys.back")))
    value = app.interact(t("plan.title"), field, keys, handle, typing=True).strip().lower()
    if value:
        app.env.masker.register(value)
        item.params["domain"] = value
        dns_state(app, session, item)


def launcher() -> str:
    return str(Path(__file__).resolve().parent.parent.parent.parent / "kerberos")


def rollback_command(run_id: str) -> str:
    return f"sudo {launcher()} rollback {run_id}"


def fix_label(app: App, item: Any) -> str:
    fix_id = item.fix_id if isinstance(item, PlanItem) else item["fixId"]
    params = item.params if isinstance(item, PlanItem) else item["params"]
    ports = ", ".join(params.get("ports", []))
    label = t(f"fix.{fix_id}.label", ports=ports, port=params.get("port", ""),
              domain=params.get("domain") or "…")  # fmt: skip
    return app.mask(label)


def node_name(session: Session, target: str, params: Optional[dict] = None) -> str:
    """The node a change belongs to; panel changes of self-steal carry it in params."""
    kind, _, ref = target.partition(":")
    if kind != "node" and params and params.get("node"):
        kind, ref = "node", params["node"]
    node = session.snapshot.node(ref) if kind == "node" else None
    return node.name if node else t("target.panel")


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
            if not note and item.fix_id == "self_steal":
                state = item.params.get("dns")
                if state == "ok":
                    note = t("plan.domain.ok", domain=app.mask(item.params["domain"]))
                elif state == "wait":
                    note = t("plan.domain.wait", record=app.mask(item.params.get("record", "")))
                else:
                    note = t("plan.domain.none")
            elif not note and warning_of(item):
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
        if any(i.fix_id == "self_steal" for i in items):
            auto = session.data.get("auto_finalize", False)
            tail.append(Text(t("plan.finalize.auto" if auto else "plan.finalize.manual"),
                             style="muted"))  # fmt: skip
        if state["error"]:
            tail.append(Notice("warning", state["error"]))
        checklist.viewport = max(4, height - 4 - len(tail))
        return Group(Text(t("plan.title"), style="bold"), checklist, *tail)

    state: dict = {"error": None, "next_dns": app.env.clock.monotonic() + 10}

    def tick() -> Optional[str]:
        # Waiting domains are resolved again every 10 seconds (§10.4).
        if app.env.clock.monotonic() >= state["next_dns"]:
            state["next_dns"] = app.env.clock.monotonic() + 10
            for item in items:
                if item.fix_id == "self_steal" and item.params.get("dns") == "wait":
                    dns_state(app, session, item)
                    if item.selected:
                        checklist.selected.add(items.index(item))
        return None

    def handle(key: str) -> Optional[str]:
        state["error"] = None
        if key == "esc":
            return BACK
        if hotkey(key) == "d" and items[checklist.cursor].fix_id == "self_steal":
            item = items[checklist.cursor]
            ask_domain(app, session, item)
            if item.selected:
                checklist.selected.add(checklist.cursor)
            return None
        if hotkey(key) == "f":
            session.data["auto_finalize"] = not session.data.get("auto_finalize", False)
            return None
        result = checklist.handle(key)
        if hotkey(key) == "a":
            # «Все» marks what can run now: self-steal waits for its domain and DNS.
            checklist.selected -= {
                i
                for i, item in enumerate(items)
                if item.fix_id == "self_steal" and item.params.get("dns") != "ok"
            }
        if result == "done":
            for i, item in enumerate(items):
                if (
                    i in checklist.selected
                    and item.fix_id == "self_steal"
                    and (item.params.get("dns") != "ok")
                ):
                    state["error"] = t("plan.need_domain")
                    return None
            return "consent" if checklist.selected else None
        return None

    keys = (
        ("↑↓", t("keys.select")),
        (t("keys.space"), t("keys.toggle")),
        ("a", t("keys.all")),
        ("d", t("keys.domain")),
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
    )
    while True:
        if app.interact(t("plan.title"), body, keys, handle, timeout=1, tick=tick) == BACK:
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
        for text in [warning_of(item), *extra_warnings(app, session, item)]:
            if text and text not in warnings:
                warnings.append(text)
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
    if session.data.get("auto_finalize") and session.data["run"]["pending"]:
        from kerberos.fixes.finalize import schedule

        schedule(app, session.panel, session.data["run"], launcher())
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
        name = app.mask(node_name(session, change["target"], change["params"]))
        label = fix_label(app, change)
        if change["state"] in ("applied", "confirmed"):
            lines.append(Text(f"✓ {name}: {label}", style="ok"))
        else:
            reason = error_text(change.get("error"))
            lines.append(Text(f"↺ {name}: {label}. " + t("apply.rolled_back", reason=reason),
                              style="risk.high"))  # fmt: skip
        node = session.snapshot.node(change["params"].get("node")
                                     or change["target"].partition(":")[2])  # fmt: skip
        if change["fixId"] == "self_steal.hosts" and change["state"] == "applied":
            lines.append(Text("  " + t("s9.hosts", created=len(change["details"]["created"]),
                                         disabled=len(change["details"]["disabled"])),
                              style="muted"))  # fmt: skip
        if change["fixId"] == "ssh.port" and change["state"] == "confirmed" and node:
            port = change["details"].get("newPort")
            command = f"ssh -p {port} root@{app.mask(node.address)}"
            lines.append(Text("  " + t("s9.ssh_port", port=port), style="accent"))
            lines.append(Text("  " + t("s9.login", command=command, node=app.mask(node.name)),
                              style="muted"))  # fmt: skip
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
        if run.get("pending"):
            key = "s9.finalize.auto" if session.data.get("auto_finalize") else "s9.finalize"
            parts += [Text(""), Text(t(key, n=len(run["pending"]),
                                       command=f"sudo {launcher()} finalize {run['runId']}"),
                                     style="accent")]  # fmt: skip
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

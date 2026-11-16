"""S5 collection and S6 red report (tech.md §6, §10, §12).

S5 reads the fleet without changing anything: agent facts, observation,
sites, outside probes, whois only after consent. S6 shows the score and the
findings by topic and saves the report; in «Проверка» this is the end.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from kerberos.checks import run_checks
from kerberos.checks.collect import STEPS, collect_in_background
from kerberos.checks.score import score
from kerberos.copy import t
from kerberos.fixes.journal import RunStore
from kerberos.fixes.model import Run
from kerberos.flow import BACK, NEXT
from kerberos.report import markdown
from kerberos.report.view import counts, finding_items
from kerberos.ui.keys import hotkey
from kerberos.ui.widgets import STEP_VIEW, FindingList, Menu, Notice, Pager, ScoreBadge

if TYPE_CHECKING:
    from kerberos.app import App, Session


def node_entries(session: Session) -> list[dict]:
    records = session.data.get("records", {})
    access = session.data.get("access", {})
    entries = []
    for node in session.snapshot.nodes:
        if node.uuid not in session.selected:
            continue
        record = records.get(node.uuid)
        entries.append({
            "uuid": node.uuid,
            "name": node.name,
            "address": node.address,
            "sshPort": record.ssh_port if record else 22,
            "access": access.get(node.uuid, "none"),
        })  # fmt: skip
    return entries


def ask_whois(app: App, session: Session) -> Optional[bool]:
    menu = Menu([("yes", t("s5.whois.yes"), ""), ("no", t("s5.whois.no"), "")])

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        return menu.handle(key)

    body = Group(Text(t("s5.whois.question")), Text(""), menu)
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    answer = app.interact(t("s5.title"), body, keys, handle)
    return None if answer == "back" else answer == "yes"


def progress_table(app: App, session: Session, progress: Any) -> Table:
    table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
    table.add_column(t("s5.col.node"), no_wrap=True, header_style="muted")
    for step in STEPS:
        table.add_column(t(f"s5.step.{step}"), justify="center", header_style="muted")
    for node in session.snapshot.nodes:
        if node.uuid not in session.selected:
            continue
        cells = []
        for step in STEPS:
            symbol, style = STEP_VIEW[progress.cells.get((node.uuid, step), "pending")]
            cells.append(Text(symbol, style=style))
        table.add_row(app.mask(node.name), *cells)
    return table


def step_collect(app: App, session: Session) -> Any:
    whois = False
    candidates = [n for n in session.snapshot.nodes if n.uuid in session.selected]
    if len(candidates) >= 2:
        answer = ask_whois(app, session)
        if answer is None:
            return BACK
        whois = answer
    session.data["records"] = app.env.state.nodes() if app.env.state else {}
    progress, box_ = collect_in_background(
        app.env, session.snapshot, session.selected, session.data.get("access", {}), whois
    )

    def body(_w: int, _h: int) -> RenderableType:
        return Group(Text(t("s5.collecting"), style="bold"), Text(""),
                     progress_table(app, session, progress))  # fmt: skip

    def tick() -> Optional[str]:
        box_["thread"].join(0.2)  # wait for the collection, keys stay in the queue
        return NEXT if progress.done else None

    keys = (("q", t("keys.quit")),)
    app.interact(t("s5.title"), body, keys, lambda _key: None, timeout=0, tick=tick)
    box_["thread"].join()
    if progress.error is not None:
        app.notice("error", t("s5.failed", error=type(progress.error).__name__), t("s5.title"))
        return BACK
    data = box_["input"]
    for item in data.nodes:
        if item.access != session.data.get("access", {}).get(item.node.uuid):
            session.data.setdefault("access", {})[item.node.uuid] = item.access
    findings = run_checks(data)
    session.data["input"] = data
    session.data["findings"] = findings
    session.data["score"] = score(findings)
    save_check_run(app, session)
    return NEXT


def save_check_run(app: App, session: Session) -> Run:
    store = RunStore(app.env.state, app.env.clock)
    snapshot = session.snapshot
    run = session.data.get("run")
    if run is None:
        panel = {"version": snapshot.version, "nodes": len(snapshot.nodes),
                 "hosts": len(snapshot.hosts),
                 "api": session.location.api if session.location else ""}  # fmt: skip
        run = store.new_run(session.mode, panel, node_entries(session))
        session.data["run"] = run
    run["nodes"] = node_entries(session)
    run["findings"] = session.data["findings"]
    run["scoreBefore"] = session.data["score"]
    if session.mode == "check":
        from kerberos.fixes.journal import iso

        run["finishedAt"] = iso(app.env.clock)
    store.save(run)
    store.log(run, f"{session.mode}: {len(run['findings'])} findings, score {run['scoreBefore']}")
    write_report(app, run)
    return run


def write_report(app: App, run: Run) -> str:
    store = RunStore(app.env.state, app.env.clock)
    masker = app.env.masker
    text = markdown.render(run, masker.text if masker.enabled else None)
    masked = masker.data(run) if masker.enabled else None
    path = store.write_report(run, text, masked)
    return str(path)


def show_pager(app: App, text: str, title: str) -> None:
    pager = Pager(text)

    def body(_w: int, height: int) -> RenderableType:
        pager.viewport = height
        return pager

    def handle(key: str) -> Optional[str]:
        if key in ("esc", "enter") or hotkey(key) in ("s", "q"):
            return "close"
        pager.handle(key)
        return None

    keys = (("↑↓", t("keys.scroll")), ("Esc", t("keys.back")))
    app.interact(title, body, keys, handle, typing=True)


def sized(listing: FindingList, height: int) -> FindingList:
    listing.viewport = max(3, height)
    return listing


def report_header(app: App, findings: list, value: int, before: Optional[int],
                  without: list, path: str) -> RenderableType:  # fmt: skip
    """Score on the left; what was found, nodes without access and the file on the right."""
    numbers = counts(findings)
    lines: list[RenderableType] = []
    if numbers["problems"]:
        lines.append(Text(t("s6.summary", **numbers), style="bold"))
    else:
        lines.append(Text(f"✓ {t('s6.none')}", style="ok"))
    if without:
        lines.append(Text(t("s6.no_access", nodes=app.mask(", ".join(without))), style="muted"))
    lines += [Text(""), Text(t("report.saved", path=app.mask(path)), style="muted")]
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(ratio=1)
    grid.add_row(ScoreBadge(value, before), Group(*lines))
    return grid


def step_report(app: App, session: Session) -> Any:
    findings = session.data["findings"]
    run = session.data["run"]
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    items = finding_items(findings, names, app.mask)
    listing = FindingList(items)
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    without = [n["name"] for n in run["nodes"] if n["access"] != "ok"]

    def body(_w: int, height: int) -> RenderableType:
        listing.items = finding_items(findings, names, app.mask)
        return Group(report_header(app, findings, session.data["score"], None, without, path),
                     Text(""), sized(listing, height - 9))  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "enter":
            return NEXT
        if key == "esc":
            return BACK
        if hotkey(key) == "s":
            text = RunStore(app.env.state, app.env.clock).report_text(run["runId"]) or ""
            show_pager(app, text, t("s6.title"))
            return None
        listing.handle(key)
        return None

    keys = (
        ("↑↓", t("keys.select")),
        (t("keys.space"), t("keys.details")),
        ("s", t("keys.full_report")),
        ("Enter", t("keys.menu") if session.mode == "check" else t("keys.next")),
        ("q", t("keys.quit")),
    )
    return app.interact(t("s6.title"), body, keys, handle)


def reports_menu(app: App) -> None:
    """S1 «Отчёты»: past runs, newest first; Enter opens report.md."""
    store = RunStore(app.env.state, app.env.clock)
    runs = store.runs()
    if not runs:
        app.notice("info", t("report.empty"), t("reports.title"))
        return
    items = [
        (run["runId"], t("reports.item", run=run["runId"], mode=t(f"report.mode.{run['mode']}"),
                         score=run.get("scoreAfter") or run.get("scoreBefore")), "")
        for run in runs
    ]  # fmt: skip
    menu = Menu(items)
    while True:

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return "back"
            return menu.handle(key)

        keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
        choice = app.interact(t("reports.title"), menu, keys, handle)
        if choice == "back":
            return
        text = store.report_text(choice) or ""
        show_pager(app, app.mask(text), t("reports.title"))


def no_report_notice() -> Notice:
    return Notice("info", t("report.empty"))

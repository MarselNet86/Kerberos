"""S7 plan and consent, S8 applying, S9 green report (tech.md §6, §11, §12)."""

from __future__ import annotations

import random
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from kerberos.checks import run_checks
from kerberos.checks.score import score
from kerberos.copy import TEXT, t
from kerberos.fixes.engine import Engine
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.model import is_applied
from kerberos.fixes.plan import (
    NEEDS_INPUT,
    PERSON_MARKS,
    PlanItem,
    build_plan,
    follow_admin_key,
)
from kerberos.flow import BACK, EXIT_OK, NEXT
from kerberos.report.view import change_target, counts
from kerberos.screens.check import (
    COMPACT_BELOW,
    report_header,
    show_full_report,
    show_pager,
    without_access,
    write_report,
)
from kerberos.ui.keys import hotkey
from kerberos.ui.palette import risk_style
from kerberos.ui.widgets import (
    Checklist,
    Clamp,
    Consent,
    Hanging,
    Notice,
    Pager,
    ProgressBoard,
    Stack,
    TextInput,
)

if TYPE_CHECKING:
    from kerberos.app import App, Session

STEP_KEYS = ("backup", "apply", "check", "confirm")


def warning_of(item: PlanItem, kind: str = "remnawave") -> Optional[str]:
    """Warnings of §15 shown before consent, word for word."""
    if item.fix_id == "ssh.key_only":
        return t("fix.key_only.warning")
    if item.fix_id == "ssh.port":
        return t("fix.ssh_port.warning", port=item.params.get("port"))
    if item.fix_id == "self_steal":
        # 3x-ui changes only target and serverNames of its Reality inbounds (§7.6).
        return t("fix.xui_steal.warning") if kind == "3x-ui" else t("fix.self_steal.warning")
    if item.fix_id == "cdn.edge_only":
        return t("fix.edge_only.warning")
    if item.fix_id == "xhttp.padding":
        return t("fix.padding.warning")
    if item.fix_id == "panel.portal":
        return t("fix.portal.warning")
    if item.fix_id == "xui.panel_hide":
        port = item.params.get("port")
        return t("fix.xui_hide.warning", port=port) if port else t("fix.xui_hide.warning.path")
    return None


def extra_warnings(app: App, session: Session, item: PlanItem) -> list[str]:
    """Self-steal also replaces the profile and may restart the node container.

    On 3x-ui there is neither: the inbounds keep their config, the server its Xray.
    """
    if item.fix_id != "self_steal" or session.snapshot.kind == "3x-ui":
        return []
    texts = [t("fix.profile.warning")]
    node = session.data["input"].node_data(item.node_uuid or "")
    facts = node.facts if node else {}
    if not (facts.get("remnanode") or {}).get("letsencryptMounted", True):
        texts.append(t("fix.mount.warning", node=app.mask(node.node.name)))
    return texts


def consent_warnings(app: App, session: Session, chosen: list[PlanItem]) -> list[str]:
    """The warnings of the chosen fixes, each once; one text for several new SSH ports."""
    kind = session.snapshot.kind
    ports = [i for i in chosen if i.fix_id == "ssh.port"]
    warnings: list[str] = []
    for item in chosen:
        if item.fix_id == "ssh.port" and len(ports) > 1:
            texts = [t("fix.ssh_port.warning.many", ports=", ".join(
                f"{app.mask(app.session_name(p.node_uuid))}: {p.params.get('port')}"
                for p in ports))]  # fmt: skip
        else:
            texts = [warning_of(item, kind), *extra_warnings(app, session, item)]
        for text in texts:
            if text and text not in warnings:
                warnings.append(text)
    return warnings


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


def pair_ready(items: list[PlanItem], pair: PlanItem) -> bool:
    """A reserve pair runs only when both nodes move to their domains in this run."""
    wanted = {pair.node_uuid, pair.params["reserve"]}
    ready = {i.node_uuid for i in items if i.fix_id == "self_steal" and i.selected
             and i.params.get("dns") == "ok"}  # fmt: skip
    return wanted <= ready


def choose_reserve(app: App, session: Session, items: list[PlanItem], main: PlanItem) -> None:
    """§6 S7: «Резервная нода» of a main node: another node of this run, or none."""
    from kerberos.fixes.plan import reserve_item
    from kerberos.ui.widgets import Menu

    name = app.session_name(main.node_uuid)
    if main.params.get("reserveOf"):
        # A reserve with its own reserve would be hidden and visible at once (§10.9).
        app.notice("warning", t("plan.reserve.is_reserve", node=app.mask(name),
                                main=app.mask(app.session_name(main.params["reserveOf"]))),
                   t("plan.title"))  # fmt: skip
        return
    others = [i for i in items if i.fix_id == "self_steal" and i is not main
              and not i.params.get("reserve")
              and i.params.get("reserveOf") in (None, main.node_uuid)]  # fmt: skip
    options = [("none", t("plan.reserve.none"), "")]
    options += [(i.node_uuid, app.mask(app.session_name(i.node_uuid)), "") for i in others]
    menu = Menu(options)

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else menu.handle(key)

    body = Group(Text(t("plan.reserve", node=app.mask(name)), style="bold"),
                 Text(t("plan.reserve.hint", node=app.mask(name)), style="muted"), Text(""),
                 menu)  # fmt: skip
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    choice = app.interact(t("plan.title"), body, keys, handle)
    if choice == "":
        return
    for item in items:
        if item.params.get("reserveOf") == main.node_uuid:
            item.params.pop("reserveOf", None)
    main.params.pop("reserve", None)
    items[:] = [i for i in items if not (i.fix_id == "reserve" and i.node_uuid == main.node_uuid)]
    if choice == "none":
        return
    spare = next(i for i in items if i.node_uuid == choice and i.fix_id == "self_steal")
    main.params["reserve"] = spare.node_uuid
    spare.params["reserveOf"] = main.node_uuid
    items.append(reserve_item(main, spare))


def confirm_edges(app: App, session: Session, item: PlanItem) -> None:
    """§10.6: the /24 nets the tunnel path was reached from; the person confirms the list."""
    from kerberos.nodes.transport import NodeAgentError, Target, TransportError

    node = session.snapshot.node(item.node_uuid or "")
    record = app.env.state.node(node.uuid)
    target = record.target(node.address) if record else Target(node.uuid, node.name,
                                                                   node.address, 22)  # fmt: skip
    counts: dict = {}
    for path in item.params["paths"]:
        try:
            answer = app.env.transport.agent(target, "edge-sources", {"path": path})
        except (NodeAgentError, TransportError) as exc:
            code = getattr(exc, "code", None) or getattr(exc, "kind", "")
            app.notice("error", t("plan.edges.failed", reason=error_text(code)), t("plan.title"))
            return
        for row in answer.get("nets") or []:
            if isinstance(row, dict) and isinstance(row.get("net"), str):
                counts[row["net"]] = counts.get(row["net"], 0) + int(row.get("count") or 0)
    if not counts:
        app.notice("warning", t("plan.edges.empty"), t("plan.title"))
        return
    nets = sorted(counts, key=lambda net: (-counts[net], net))
    chosen = set(item.params.get("nets") or nets)
    table = Checklist([[app.mask(net), str(counts[net])] for net in nets],
                      [t("plan.edges.col.net"), t("plan.edges.col.count")],
                      selected={i for i, net in enumerate(nets) if net in chosen})  # fmt: skip

    def body(_w: int, height: int) -> RenderableType:
        table.viewport = max(4, height - 5)
        return Group(Text(t("plan.edges.title", node=app.mask(node.name)), style="bold"),
                     Text(t("plan.edges.hint"), style="muted"), table)  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        result = table.handle(key)
        return "done" if result == "done" and table.selected else None

    keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("plan.edges.confirm")),
            ("Esc", t("keys.back")))  # fmt: skip
    if app.interact(t("plan.title"), body, keys, handle) == "done":
        item.params["nets"] = [net for i, net in enumerate(nets) if i in table.selected]
        if item.blocked is None:
            item.selected = True


def ask_domain(app: App, session: Session, item: PlanItem) -> None:
    node = session.snapshot.node(item.node_uuid or "")
    data = session.data["input"].node_data(item.node_uuid or "")
    ipv4 = data.ipv4 if data else None
    field = TextInput(
        t("plan.domain.label", node=app.mask(node.name if node else "")),
        hint=t("plan.domain.hint", ip=app.mask(ipv4)) if ipv4 else t("plan.domain.hint.no_ip"),
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
    spare = params.get("reserve")
    label = t(f"fix.{fix_id}.label", ports=ports, port=params.get("port", ""),
              domain=params.get("domain") or "…", nets=len(params.get("nets") or []),
              reserve=app.session_name(spare) if spare else "")  # fmt: skip
    return app.mask(label)


def node_name(session: Session, target: str, params: Optional[dict] = None) -> str:
    """Who a change belongs to: a node, a host, a template or the panel."""
    names = {n.uuid: n.name for n in session.snapshot.nodes}
    return change_target(target, params or {}, names)


def node_renewals(session: Session, target: str) -> list:
    """Certificates of the node that renew on :80 themselves: self-steal moves them
    to the webroot of its nginx (§10.4, K16)."""
    uuid = target.partition(":")[2]
    for data in session.data["input"].nodes:
        if data.node.uuid == uuid:
            return [r for r in (data.facts or {}).get("acme") or [] if not r.get("blocked")]
    return []


def renewals_text(app: App, renewals: list) -> str:
    return ", ".join(f"{app.mask(str(r.get('name', '')))} ({r.get('tool', '')})"
                     for r in renewals)  # fmt: skip


def error_text(code: Optional[str]) -> str:
    if not code:
        return ""
    return TEXT.get(f"error.{code}", code)


def site_preview(app: App, session: Session, item: PlanItem) -> Text:
    """§10.4: what the stub site of the node will be, with its colours (g draws another).

    Without colour the samples would be three equal blocks: they are left out.
    """
    from kerberos.agent import site_spec

    spec = site_spec(item.params.get("siteSeed", 0))
    theme = spec["theme"]
    line = Text(t("plan.site", node=app.mask(app.session_name(item.node_uuid)),
                  title=spec["title"], kind=t(f"site.kind.{spec['kind']}")))  # fmt: skip
    if app.term.color:
        for key in ("background", "text", "accent"):
            line.append(" ")
            line.append("██", style=theme[key])
    line.append("  " + t("plan.site.again"), style="muted")
    return line


def new_site(session: Session, item: PlanItem) -> None:
    """Another random stub site for the node, still unlike the other nodes' sites."""
    from kerberos.agent import site_html, template_hash
    from kerberos.fixes.plan import free_site_seed, site_layouts_in_use

    data = session.data["input"]
    used = site_layouts_in_use(data)
    for other in session.data["plan"]:
        if other.fix_id == "self_steal":
            used.add(template_hash(site_html(other.params.get("siteSeed", 0), "example.com")))
    rng = session.data.setdefault("rng", random.SystemRandom())
    item.params["siteSeed"] = free_site_seed(used, rng)


def waits_for_input(item: PlanItem) -> bool:
    if item.fix_id == "self_steal":
        return item.params.get("dns") != "ok"
    if item.fix_id == "cdn.edge_only":
        return not item.params.get("nets")
    if item.fix_id == "panel.portal":
        return not item.params.get("login")
    return False


def ask_portal_login(app: App, session: Session, item: PlanItem) -> None:
    """§10.10: the login and password of the portal, typed twice; they stay in memory
    (the password never reaches the plan or the journal) until the env file is written."""
    from kerberos.fixes.portal import LOGIN_RE, PASSWORD_RE

    fields = [TextInput(t("plan.portal.login"), value=item.params.get("login") or ""),
              TextInput(t("plan.portal.password"), secret=True),
              TextInput(t("plan.portal.repeat"), secret=True)]  # fmt: skip
    state: dict[str, Any] = {"focus": 0, "error": None}

    def body(_w: int, _h: int) -> RenderableType:
        for i, field in enumerate(fields):
            field.focused = i == state["focus"]
        parts: list[RenderableType] = [
            Text(t("plan.portal.title"), style="bold"),
            Text(t("plan.portal.hint"), style="muted"),
            Text(""),
        ]
        for field in fields:
            parts += [field, Text("")]
        if state["error"]:
            parts.append(Notice("error", state["error"]))
        return Group(*parts)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key in ("tab", "down"):
            state["focus"] = (state["focus"] + 1) % len(fields)
            return None
        if key == "up":
            state["focus"] = (state["focus"] - 1) % len(fields)
            return None
        if key == "enter":
            if state["focus"] < len(fields) - 1:
                state["focus"] += 1
                return None
            return "submit"
        fields[state["focus"]].handle(key)
        state["error"] = None
        return None

    keys = (("Tab", t("keys.field")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    try:
        while app.interact(t("plan.title"), body, keys, handle, typing=True) == "submit":
            login = fields[0].value.strip()
            password = fields[1].value
            if not LOGIN_RE.fullmatch(login):
                state["error"], state["focus"] = t("plan.portal.bad_login"), 0
            elif not PASSWORD_RE.fullmatch(password):
                state["error"], state["focus"] = t("plan.portal.bad_password"), 1
            elif password != fields[2].value:
                state["error"], state["focus"] = t("plan.portal.mismatch"), 2
            else:
                session.data["portal"] = {"login": login, "password": password}
                item.params["login"] = login
                item.selected = True
                return
            fields[1].clear()
            fields[2].clear()
    finally:
        for field in fields[1:]:
            field.clear()


# -- S7 -------------------------------------------------------------------------
FIX_COLUMN = 1  # «Исправление»: the column that keeps its width in a narrow terminal
FIX_COLUMN_MIN = 30
DETAILS_LINES = 3


def note_of(app: App, item: PlanItem) -> str:
    """The «Заметка» of a row: why it is off, what it waits for, its reserve."""
    if item.blocked:
        return t(f"plan.blocked.{item.blocked}")
    note = ""
    if item.fix_id == "self_steal":
        state = item.params.get("dns")
        if state == "ok":
            note = t("plan.domain.ok")
        elif state == "wait":
            note = t("plan.domain.waiting")
        else:
            note = t("plan.domain.none")
        if item.params.get("reserve"):
            note += " · " + t("plan.reserve.with", node=app.session_name(item.params["reserve"]))
        if item.params.get("reserveOf"):
            note += " · " + t("plan.reserve.of", node=app.session_name(item.params["reserveOf"]))
    elif item.fix_id == "cdn.edge_only":
        nets = item.params.get("nets")
        note = t("plan.edges.ok", n=len(nets)) if nets else t("plan.edges.none")
    elif item.fix_id == "panel.portal":
        login = item.params.get("login")
        note = t("plan.portal.ok", login=login) if login else t("plan.portal.none")
    elif warning_of(item):
        note = t("plan.has_warning")
    return app.mask(note)


def plan_details(app: App, session: Session, item: PlanItem) -> RenderableType:
    """Under the table: the current row in full, why it is off and its warning."""
    name = app.mask(node_name(session, item.target, item.params))
    head = Text(f"{name}: {fix_label(app, item)}", style="bold")
    note = note_of(app, item)
    if note and item.fix_id in NEEDS_INPUT and not item.blocked:
        head.append(" · " + note, style="")  # the domain, its DNS, the reserve, the nets
    lines: list[RenderableType] = [head]
    if item.blocked:
        lines.append(Text(t("plan.details.blocked", reason=note), style="risk.medium"))
    else:
        if item.fix_id == "self_steal" and item.params.get("dns") == "wait":
            # The record to make, in full: the table column is too narrow for it.
            lines.append(Text(t("plan.domain.wait", record=app.mask(item.params["record"])),
                              style="risk.medium"))  # fmt: skip
        if item.fix_id == "self_steal":
            lines.append(site_preview(app, session, item))
            renewals = node_renewals(session, item.target)
            if renewals:
                lines.append(Text(t("plan.renewals", names=renewals_text(app, renewals)),
                                  style="muted"))  # fmt: skip
        warning = warning_of(item, session.snapshot.kind)
        if warning:
            lines.append(Text(t("plan.details.warning", text=warning), style="muted"))
    return Clamp(Group(*lines), DETAILS_LINES, pad=True)


def step_plan(app: App, session: Session) -> Any:
    data = session.data["input"]
    if "plan" not in session.data:
        records = app.env.state.nodes()
        panel_ips = {uuid: r.panel_ip for uuid, r in records.items()}
        # The demo draws the same ports and stub sites every time: snapshots stay stable.
        session.data["rng"] = random.Random(20261116) if app.env.demo else random.SystemRandom()
        session.data["plan"] = build_plan(
            session.data["findings"], data, session.data.get("admin"), panel_ips,
            session.data["rng"],
        )  # fmt: skip
    items: list[PlanItem] = session.data["plan"]
    if not items:
        app.notice("info", t("plan.empty"), t("plan.title"))
        return NEXT
    xui = session.snapshot.kind == "3x-ui"
    disabled = {i for i, item in enumerate(items) if item.blocked}
    checklist = Checklist([], [t("plan.col.node"), t("plan.col.fix"), t("plan.col.risk"),
                               t("plan.col.note")],  # fmt: skip
                          selected={i for i, item in enumerate(items) if item.selected},
                          disabled=disabled, flexible=FIX_COLUMN, min_width=FIX_COLUMN_MIN,
                          reach_disabled=True)  # fmt: skip

    def rows() -> list[list[Any]]:
        result = []
        for item in items:
            importance = Text(t("importance." + item.risk), style=risk_style(item.risk))
            result.append([app.mask(node_name(session, item.target, item.params)),
                           fix_label(app, item), importance, note_of(app, item)])  # fmt: skip
        return result

    def current() -> Optional[PlanItem]:
        return items[checklist.cursor] if items else None

    def body(_w: int, _height: int) -> RenderableType:
        checklist.rows = rows()
        checklist.disabled = {i for i, item in enumerate(items) if item.blocked}
        for i, item in enumerate(items):
            item.selected = i in checklist.selected
        follow_admin_key(items)
        checklist.selected = {i for i, item in enumerate(items) if item.selected}
        tail: list[RenderableType] = [
            Text(t("plan.selected", n=len(checklist.selected), total=len(items)), style="muted")
        ]
        row = current()
        if row is not None:
            # One row at a time: records of several waiting domains would push the
            # table off a low screen; the column «Заметка» says which rows wait.
            tail.append(plan_details(app, session, row))
        if any(i.fix_id == "self_steal" and i.selected for i in items):
            auto = session.data.get("auto_finalize", False)
            key = "plan.finalize.auto" if auto else "plan.finalize.manual"
            if xui:
                key = "plan.finalize.xui"  # no timer: 3x-ui gives KERBEROS no token for it
            tail.append(Text(t(key), style="muted"))
        if state["error"]:
            tail.append(Notice("warning", state["error"]))
        return Stack(Text(t("plan.title"), style="bold"), checklist, *tail, flex=1)

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

    def mark_all() -> None:
        """`a`: everything that can run now, except the SSH port (§6: the person marks it);
        pressed again, it takes back what it marked."""
        waiting = {i for i, item in enumerate(items) if waits_for_input(item)}
        marked = {i for i, item in enumerate(items)
                  if not (item.blocked or i in waiting or item.fix_id in PERSON_MARKS)}  # fmt: skip
        if marked <= checklist.selected:
            checklist.selected -= marked
        else:
            checklist.selected |= marked
        checklist.selected -= waiting

    def handle(key: str) -> Optional[str]:
        state["error"] = None
        if key == "esc":
            return BACK
        item = current()
        free = item is not None and not item.blocked
        if hotkey(key) == "d" and free and item.fix_id == "self_steal":
            ask_domain(app, session, item)
            if item.selected:
                checklist.selected.add(checklist.cursor)
            return None
        if hotkey(key) == "e" and free and item.fix_id == "cdn.edge_only":
            confirm_edges(app, session, item)
            if item.selected:
                checklist.selected.add(checklist.cursor)
            return None
        if hotkey(key) == "p" and free and item.fix_id == "panel.portal":
            ask_portal_login(app, session, item)
            if item.selected:
                checklist.selected.add(checklist.cursor)
            return None
        if hotkey(key) == "g" and free and item.fix_id == "self_steal":
            new_site(session, item)
            return None
        if hotkey(key) == "f" and not xui:
            session.data["auto_finalize"] = not session.data.get("auto_finalize", False)
            return None
        if hotkey(key) == "r" and free and item.fix_id == "self_steal" and not xui:
            choose_reserve(app, session, items, item)
            checklist.rows = rows()
            checklist.selected = {i for i, item in enumerate(items) if item.selected}
            return None
        if hotkey(key) == "a":
            mark_all()
            return None
        result = checklist.handle(key)
        if result == "done":
            needs = {"self_steal": "plan.need_domain", "cdn.edge_only": "plan.need_edges",
                     "panel.portal": "plan.need_portal"}  # fmt: skip
            for i, item in enumerate(items):
                if i in checklist.selected and waits_for_input(item):
                    state["error"] = t(needs[item.fix_id])
                    return None
            for item in items:
                if item.fix_id == "reserve" and item.selected and not pair_ready(items, item):
                    state["error"] = t("plan.need_reserve")
                    return None
            return "consent" if checklist.selected else None
        return None

    def keys() -> list[tuple[str, str]]:
        """The footer follows the current row: its own keys first, the rest in `?`."""
        item = current()
        hints: list[tuple[str, str]] = []
        if item is not None and not item.blocked and item.fix_id == "self_steal":
            hints.append(("d", t("keys.domain")))
            if not xui:
                hints.append(("r", t("keys.reserve")))
            hints.append(("g", t("keys.site")))
        elif item is not None and not item.blocked and item.fix_id == "cdn.edge_only":
            hints.append(("e", t("keys.edges")))
        elif item is not None and not item.blocked and item.fix_id == "panel.portal":
            hints.append(("p", t("keys.portal")))
        hints.append((t("keys.space"), t("keys.toggle")))
        if len(hints) == 1:
            hints.append(("a", t("keys.all_but_port")))
        return hints + [("Enter", t("keys.next")), ("Esc", t("keys.back")),
                        ("?", t("keys.help"))]  # fmt: skip

    app.screen_help = t("help.s7.xui" if xui else "help.s7")
    try:
        while True:
            if app.interact(t("plan.title"), body, keys, handle, timeout=1, tick=tick) == BACK:
                return BACK
            for i, item in enumerate(items):
                item.selected = i in checklist.selected
            follow_admin_key(items)
            if consent(app, session, items):
                return NEXT
    finally:
        app.screen_help = ""


def agree(app: App, title: str, widget: Consent) -> bool:
    """A consent screen (S7, rollback, finalization): Enter agrees, ↑ ↓ PgUp PgDn Home
    End scroll, any other key goes back."""
    return bool(app.interact(title, widget, (), widget.handle, typing=True))


def consent(app: App, session: Session, items: list[PlanItem]) -> bool:
    """§6 S7: what changes on every node, the warnings of §15 word for word."""
    chosen = [i for i in items if i.selected and not i.blocked]
    lines: list[RenderableType] = [Text(t("consent.intro"), style="bold")]
    by_node: dict = {}
    for item in chosen:
        by_node.setdefault(node_name(session, item.target, item.params), []).append(
            fix_label(app, item)
        )
    for name, labels in by_node.items():
        lines.append(Hanging(f"  {app.mask(name)}: " + "; ".join(labels), indent=4))
    for item in chosen:
        renewals = node_renewals(session, item.target) if item.fix_id == "self_steal" else []
        if renewals:
            name = app.mask(node_name(session, item.target, item.params))
            lines.append(
                Hanging(
                    "  " + t("consent.renewals", node=name, names=renewals_text(app, renewals)),
                    indent=4,
                )
            )
    for text in consent_warnings(app, session, chosen):
        lines.append(Notice("warning", text))
    return agree(app, t("consent.title"), Consent(Group(*lines), t("consent.accept")))


# -- S8 -------------------------------------------------------------------------
def step_apply(app: App, session: Session) -> Any:
    items: list[PlanItem] = session.data["plan"]
    chosen = [i for i in items if i.selected and not i.blocked]
    names = []
    for item in chosen:
        name = node_name(session, item.target, item.params)
        if name not in names:
            names.append(name)
    board = ProgressBoard([app.mask(n) for n in names], [t(f"step.{s}") for s in STEP_KEYS])
    board.node_title, board.fix_title = t("board.node"), t("board.fix")
    board.legend = t("board.legend")

    def on_event(step: str, item: PlanItem, state: str, note: str) -> None:
        name = app.mask(node_name(session, item.target, item.params))
        if step == "backup" and state == "running":
            board.start(name, fix_label(app, item))
        board.set(name, t(f"step.{step}"), state)
        if state in ("failed", "rolled_back"):
            # A change that could not be undone either says so, never «откатил».
            text = (error_text(note) if note == "rollback_failed"
                    else t("apply.rolled_back", reason=error_text(note) or note))  # fmt: skip
            board.finish(name, Text(text, style="risk.high"))

    engine = Engine(app, session, chosen, on_event)
    engine.ask_diff = lambda diff: ask_overwrite(app, diff)
    engine.ask_outside = lambda port, command: ask_outside(app, port, command)
    from kerberos.screens.rollback import ask_old_port

    engine.ask_old_port = lambda port, command: ask_old_port(app, port, command)
    engine.ask_portal = lambda link, login, where: ask_portal(
        app, link, login, where, cancel=engine.cancel
    )
    session.data["engine"] = engine
    app.busy = True

    def tick() -> Optional[str]:
        if engine.done:
            return NEXT
        engine.step()
        return None

    def interrupt() -> Optional[str]:
        body = Group(Notice("warning", t("apply.interrupt")),
                     Text(t("apply.interrupt.keys"), style="muted"))  # fmt: skip
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
    from kerberos.screens.panel import settle_token

    settle_token(app, session.panel)
    if session.data.get("auto_finalize") and session.data["run"]["pending"]:
        from kerberos.fixes.finalize import schedule

        schedule(app, session.data["run"], launcher())
    return NEXT


def ask_outside(app: App, port: int, command: str) -> bool:
    """§7.6: the new SSH port of this server, tried by the person from their computer."""
    body = Group(Notice("warning", t("apply.outside", port=port, command=app.mask(command))),
                 Text(t("apply.outside.keys"), style="muted"))  # fmt: skip
    app.draw(t("s8.title"), body)
    return app.term.read_key() == "enter"


def masked_link(app: App, link: str) -> str:
    """The secret path of a panel link is hidden with the addresses when masking."""
    if not app.env.masker.enabled:
        return link
    head, _, _secret = link.partition("://")[2].partition("/")
    return app.mask(f"{link.partition('://')[0]}://{head}/") + "…"


def ask_portal(app: App, link: str, login: Optional[str], where: str = "",
               cancel: Optional[Any] = None) -> bool:  # fmt: skip
    """§10.10: the person logs in at the new link from their browser; Enter: in, Esc: no.

    Three minutes without an answer count as no: everything goes back. Ctrl+C means no
    too and stops the run after it; `q` is no way out here, it would leave the change
    half confirmed. With masking on, the full link is in the 0600 file `where`.
    """
    from kerberos.fixes.portal import LOGIN_WAIT

    def body(_w: int, _h: int) -> RenderableType:
        text = (t("apply.portal", link=masked_link(app, link), login=login) if login
                else t("apply.xui_panel", link=masked_link(app, link)))  # fmt: skip
        parts: list[RenderableType] = [Notice("warning", text)]
        if app.env.masker.enabled and where:
            parts.append(Text(t("apply.portal.masked", path=where), style="muted"))
        parts.append(Text(t("apply.portal.keys"), style="muted"))
        return Group(*parts)

    deadline = app.env.clock.monotonic() + LOGIN_WAIT

    def handle(key: str) -> Optional[str]:
        return {"enter": "yes", "esc": "no"}.get(key)

    def tick() -> Optional[str]:
        return "no" if app.env.clock.monotonic() >= deadline else None

    def interrupt() -> Optional[str]:
        if cancel is not None:
            cancel()
        return "no"

    keys = (("Enter", t("keys.logged_in")), ("Esc", t("keys.not_logged_in")),
            ("Ctrl+C", t("keys.interrupt")))  # fmt: skip
    return app.interact(t("s8.title"), body, keys, handle, typing=True, timeout=1,
                        tick=tick, interrupt=interrupt) == "yes"  # fmt: skip


def ask_overwrite(app: App, diff: str) -> bool:
    """§10.9: a KERBEROS template was edited in the panel: show how, ask before writing."""
    show_pager(app, t("tpl.diff.intro") + "\n\n" + app.mask(diff), t("s8.title"))
    body = Group(Notice("warning", t("tpl.diff.question")),
                 Text(f"{t('quit.yes')}    {t('quit.no')}", style="muted"))  # fmt: skip
    app.draw(t("s8.title"), body)
    return app.term.read_key() == "enter"


def refresh_snapshot(app: App, session: Session) -> None:
    """Panel changes land in the score after: read the panel again."""
    if session.panel is None or session.location is None or session.snapshot is None:
        return
    try:
        if session.snapshot.kind == "3x-ui":
            node = session.snapshot.nodes[0]  # §7.6: the one node is this server
            snapshot = session.panel.snapshot(session.location, node.address, node.name)
        else:
            snapshot = session.panel.snapshot(session.location.version,
                                              session.location.panel_domain)  # fmt: skip
    except Exception:  # noqa: BLE001 - the score after then uses what KERBEROS knows
        return
    session.snapshot = snapshot
    session.data["input"].snapshot = snapshot


def finish_run(app: App, session: Session, engine: Engine) -> None:
    run = session.data["run"]
    refresh_snapshot(app, session)
    data = session.data["input"]
    after = run_checks(data)
    session.data["findings_after"] = after
    run["scoreAfter"] = score(after)
    run["findingsAfter"] = after
    run["interrupted"] = engine.cancelled
    run["finishedAt"] = iso(app.env.clock)
    store = RunStore(app.env.state, app.env.clock)
    store.save(run)
    applied = sum(1 for c in run["changes"] if is_applied(c))
    store.log(run, f"fix: {applied} applied, {engine.failed} failed, {engine.rollback_failed} "
                   f"not rolled back, score {run['scoreAfter']}")  # fmt: skip
    session.data["exit"] = engine.exit_code  # kept if the person quits on S9
    write_report(app, run)


# -- S9 -------------------------------------------------------------------------
def rollback_failed(change: dict) -> bool:
    """The change did not apply and its undo failed too: it may still be on the node."""
    return change.get("error") == "rollback_failed"


def applied(change: dict) -> bool:
    return change["state"] in ("applied", "confirmed") and not rollback_failed(change)


def change_lines(app: App, session: Session, run: dict) -> list[RenderableType]:
    lines: list[RenderableType] = []
    for change in run["changes"]:
        name = app.mask(node_name(session, change["target"], change["params"]))
        label = fix_label(app, change)
        if rollback_failed(change):
            reason = error_text(change["details"].get("failure"))
            lines.append(Hanging(f"✗ {name}: {label}. " + t("apply.rollback_failed", reason=reason),
                                 style="risk.high"))  # fmt: skip
        elif applied(change):
            lines.append(Hanging(f"✓ {name}: {label}", style="ok"))
        else:
            reason = error_text(change.get("error"))
            lines.append(Hanging(f"↺ {name}: {label}. " + t("apply.rolled_back", reason=reason),
                                 style="risk.high"))  # fmt: skip
        site = change["details"].get("site")
        if change["fixId"] == "self_steal.site" and applied(change) and site:
            lines.append(Hanging("  " + t("s9.site", title=site["title"],
                                          kind=t(f"site.kind.{site['kind']}"),
                                          background=site["background"],
                                          accent=site["accent"]), indent=4,
                                 style="muted"))  # fmt: skip
        renewals = change["details"].get("renewals")
        if change["fixId"] == "self_steal.site" and applied(change) and renewals:
            lines.append(Hanging("  " + t("s9.renewals", names=renewals_text(app, renewals)),
                                 indent=4, style="muted"))  # fmt: skip
        if change["fixId"] == "self_steal.hosts" and applied(change):
            lines.append(Hanging("  " + t("s9.hosts", created=len(change["details"]["created"]),
                                          disabled=len(change["details"]["disabled"])),
                                 indent=4, style="muted"))  # fmt: skip
        for key in change["details"].get("hostKeys", []) if applied(change) else []:
            if key.get("type") == "ED25519":
                node = session.snapshot.node(change["target"].partition(":")[2])
                lines.append(Hanging("  " + t("s9.hostkey", fingerprint=key["fingerprint"],
                                              address=app.mask(node.address if node else "")),
                                     indent=4, style="muted"))  # fmt: skip
    return lines


def apply_summary(run: dict, findings: list) -> list[RenderableType]:
    """How the run went, then what is left: «Исправит KERBEROS» would read as a promise."""
    changes = run["changes"]
    ok = sum(1 for c in changes if applied(c))
    stuck = sum(1 for c in changes if rollback_failed(c))
    failed = len(changes) - ok - stuck
    line = Text(t("s9.applied", ok=ok, total=len(changes)), style="ok" if ok == len(changes)
                else "bold")  # fmt: skip
    if failed:
        line.append(" " + t("s9.failed", n=failed), style="risk.high")
    if stuck:
        line.append(" " + t("s9.rollback_failed", n=stuck), style="risk.high")
    numbers = counts(findings, {n["uuid"]: n["name"] for n in run["nodes"]})
    if numbers["problems"]:
        left = Text(t("s9.left", **numbers), style="bold")
    else:
        left = Text(f"✓ {t('s6.none')}", style="ok")
    return [line, left]


def new_ports(
    app: App, session: Session, run: dict, compact: bool = False
) -> Optional[RenderableType]:
    """§10.3: the new SSH port stands out, with how to log in now; in a low terminal
    without the frame, which would take two lines from the list."""
    admin = app.env.state is not None and app.env.state.admin_key.exists()
    lines: list[RenderableType] = []
    for change in run["changes"]:
        if change["fixId"] != "ssh.port" or change["state"] != "confirmed":
            continue
        if rollback_failed(change):
            continue
        node = session.snapshot.node(change["target"].partition(":")[2])
        if node is None:
            continue
        port = change["details"].get("newPort")
        name = app.mask(node.name)
        command = f"ssh -p {port} root@{app.mask(node.address)}"
        lines.append(Text(t("s9.ssh_port", node=name, port=port), style="accent"))
        # `kerberos ssh` works only with the administrator key on this server (§8.5).
        key = "s9.login.admin" if admin else "s9.login"
        lines.append(Text(t(key, command=command, node=name), style="bold"))
    lines += panel_links(app, run)
    if not lines:
        return None
    if compact:
        return Group(*lines)
    return Panel(Group(*lines), box=box.HEAVY, border_style="accent", expand=False)


def panel_links(app: App, run: dict) -> list[RenderableType]:
    """§10.10: the new way into the panel stands out like a new SSH port."""
    from kerberos.fixes.panel_changes import load_snapshot

    lines: list[RenderableType] = []
    for change in run["changes"]:
        if change["fixId"] not in ("panel.portal", "xui.panel_hide"):
            continue
        if change["state"] != "confirmed" or rollback_failed(change):
            continue
        saved = load_snapshot(change["details"].get("linkPath")) or {}
        if not saved.get("link"):
            continue
        link = masked_link(app, saved["link"])
        if change["fixId"] == "panel.portal":
            lines.append(Text(t("s9.portal", link=link), style="accent"))
            lines.append(Text(t("s9.portal.login", login=saved.get("login", "")), style="bold"))
        else:
            lines.append(Text(t("s9.xui_panel", link=link), style="accent"))
    return lines


def command_lines(label: str, command: str) -> list[RenderableType]:
    """A command to copy: on a line of its own, so the label never pushes it to a
    break (it folds only when longer than the whole screen)."""
    return [Text(label, style="bold"), Text(command, overflow="fold")]


# S9 pins more than S6 (the new SSH ports, two commands): its score shrinks to a line
# sooner, so the list of changes keeps room on a 30-line terminal too.
S9_COMPACT_BELOW = COMPACT_BELOW + 8


def step_done(app: App, session: Session) -> Any:
    run = session.data["run"]
    engine: Engine = session.data.get("engine")
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    without = without_access(run)
    after = session.data.get("findings_after", session.data["findings"])
    cancelled = engine is not None and engine.cancelled
    title = t("apply.interrupted.title") if cancelled else t("done.title")
    listing = Pager("")

    def body(_w: int, height: int) -> RenderableType:
        compact = height < S9_COMPACT_BELOW
        top: list[RenderableType] = [
            report_header(app, after, run.get("scoreAfter") or run["scoreBefore"],
                          run["scoreBefore"], without, path,
                          summary=apply_summary(run, after), compact=compact),
        ]  # fmt: skip
        if cancelled:
            top.append(Notice("warning", t("apply.interrupted")))
        ports = new_ports(app, session, run, compact)
        if ports is not None:
            top.append(ports)
        if not compact:
            top.append(Text(""))
        lines = change_lines(app, session, run)
        listing.text = Group(*(lines or [Text(t("s9.none"), style="muted")]))
        bottom: list[RenderableType] = []
        if run.get("pending"):
            # «Automatically» only when the timer is really set (§10.4 step 6).
            if run.get("finalizeTimer"):
                bottom += [Text(t("s9.finalize.auto"), style="accent")]
            else:
                command = f"sudo {launcher()} finalize {run['runId']}"
                bottom += command_lines(t("s9.finalize"), command)
        if run["changes"]:
            bottom += command_lines(t("done.rollback"), rollback_command(run["runId"]))
        if bottom and not compact:
            bottom.insert(0, Text(""))
        return Stack(*top, listing, *bottom, flex=len(top))

    def handle(key: str) -> Optional[str]:
        if key in ("enter", "esc"):
            return "done"
        if hotkey(key) == "s":
            show_full_report(app, run["runId"], title)
            return None
        listing.handle(key)
        return None

    keys = (("↑↓ PgDn", t("keys.scroll")), ("s", t("keys.full_report")),
            ("Enter", t("keys.menu")), ("?", t("keys.help")))  # fmt: skip
    app.screen_help = t("help.s9")
    try:
        app.interact(title, body, keys, handle)
    finally:
        app.screen_help = ""
    return engine.exit_code if engine is not None else EXIT_OK

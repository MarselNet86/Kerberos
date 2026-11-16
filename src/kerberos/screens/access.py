"""S4. Access to the nodes (tech.md §6, §8).

For every chosen node without KERBEROS access: show the host key fingerprint
and pin it after the person confirms; log in with the panel server's root
keys or hand the terminal to `ssh` for the node password; install the agent
and the restricted KERBEROS key; prove the access with a new connection.
Nodes that already have access get their agent version checked (§8.3).
In «Исправление» the person also chooses the administrator key once (§8.5);
the keys reach the nodes only after consent, as a planned change.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from kerberos.copy import t
from kerberos.flow import BACK, NEXT
from kerberos.nodes import bootstrap
from kerberos.nodes.keys import parse_authorized_keys
from kerberos.nodes.transport import NodeAgentError, Target, TransportError
from kerberos.panel.model import Node
from kerberos.state import NodeRecord
from kerberos.ui.widgets import Checklist, Menu, Notice, TextInput

if TYPE_CHECKING:
    from kerberos.app import App, Session

OK, NONE, DENIED = "ok", "none", "denied"


class AccessFailed(Exception):
    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def target_of(node: Node, record: Optional[NodeRecord]) -> Target:
    port = record.ssh_port if record else 22
    return Target(node.uuid, node.name, node.address, port)


def ensure_key(app: App) -> str:
    """The KERBEROS key pair on the panel server, created on first use."""
    state = app.env.state
    public = state.public_key()
    if public:
        return public
    state.ensure()
    host = app.env.host
    result = host.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"kerberos@{host.hostname()}",
            "-f",
            str(state.key),
        ]  # fmt: skip
    )
    if not result.ok or state.public_key() is None:
        raise AccessFailed(NONE, t("access.reason.keygen"))
    os.chmod(state.key, 0o600)
    return state.public_key() or ""


class AccessScreen:
    def __init__(self, app: App, session: Session) -> None:
        self.app = app
        self.session = session
        self.nodes = [n for n in session.snapshot.nodes if n.uuid in session.selected]
        self.status: dict[str, str] = session.data.setdefault("access", {})
        self.reasons: dict[str, str] = session.data.setdefault("access_reason", {})
        self.action = ""

    # -- drawing -------------------------------------------------------------
    def table(self) -> Table:
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
        for title in ("access.col.node", "access.col.address", "access.col.status"):
            table.add_column(t(title), no_wrap=True, overflow="ellipsis", header_style="muted")
        for node in self.nodes:
            state = self.status.get(node.uuid)
            if state == OK:
                cell = Text(f"✓ {t('access.status.ok')}", style="ok")
            elif state in (NONE, DENIED):
                reason = self.reasons.get(node.uuid, "")
                cell = Text(f"✗ {t('access.status.' + state)}: {reason}", style="risk.high")
            else:
                cell = Text("…", style="muted")
            table.add_row(self.app.mask(node.name), self.app.mask(node.address), cell)
        return table

    def frame(self, *extra: RenderableType) -> RenderableType:
        parts: list[RenderableType] = [self.table()]
        if self.action:
            parts += [Text(""), Text(self.action, style="accent")]
        if extra:
            parts += [Text(""), *extra]
        return Group(*parts)

    def show(self, action: str) -> None:
        self.action = action
        self.app.draw(t("access.title"), self.frame())

    def ask_menu(self, prompt: RenderableType, items: list[tuple[str, str, str]]) -> str:
        menu = Menu(items)

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return items[-1][0]
            return menu.handle(key)

        keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("q", t("keys.quit")))
        return self.app.interact(
            t("access.title"), lambda _w, _h: self.frame(prompt, Text(""), menu), keys, handle
        )

    def ask_port(self, node: Node, port: int) -> Optional[int]:
        def check(value: str) -> Optional[str]:
            ok = value.isdigit() and 1 <= int(value) <= 65535
            return None if ok else t("access.port_invalid")

        field = TextInput(
            t("access.port_label", node=self.app.mask(node.name)),
            hint=t("access.port_hint", port=port),
            validate=check,
            value=str(port),
        )

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return ""
            return field.handle(key)

        keys = (("Enter", t("keys.next")), ("Esc", t("access.skip")))
        value = self.app.interact(
            t("access.title"), lambda _w, _h: self.frame(field), keys, handle, typing=True
        )
        return int(value) if value else None

    # -- one node --------------------------------------------------------------
    def pin_host_key(self, node: Node, target: Target, record: Optional[NodeRecord]) -> Target:
        transport, state = self.app.env.transport, self.app.env.state
        while True:
            self.show(t("access.checking_key", node=self.app.mask(node.name)))
            key = transport.keyscan(target.address, target.port)
            if key is not None:
                break
            port = self.ask_port(node, target.port)
            if port is None:
                raise AccessFailed(NONE, t("access.reason.unreachable"))
            target = Target(target.uuid, target.name, target.address, port)
        pinned = state.pinned(target.address, target.port)
        fingerprint = key.fingerprint
        if pinned is not None and pinned != key.blob:
            prompt: RenderableType = Group(
                Notice("error", t("access.hostkey_changed", node=self.app.mask(node.name))),
                Text(t("access.hostkey_new", fingerprint=fingerprint)),
            )
            items = [("yes", t("access.accept_new"), ""), ("no", t("access.skip"), "")]
        elif pinned is None:
            prompt = Text(
                t("access.hostkey", node=self.app.mask(node.name), fingerprint=fingerprint)
            )
            items = [("yes", t("access.yes"), ""), ("no", t("access.no"), "")]
        else:
            return target
        if self.ask_menu(prompt, items) != "yes":
            raise AccessFailed(DENIED, t("access.reason.declined"))
        state.pin(target.address, target.port, key.type, key.blob)
        return target

    def login(self, node: Node, target: Target) -> None:
        transport = self.app.env.transport
        self.show(t("access.trying_keys"))
        try:
            if transport.open_root(target, interactive=False):
                return
            message = t("access.password", node=self.app.mask(node.name))
            with self.app.term.suspend(message):
                ok = transport.open_root(target, interactive=True)
        except TransportError as exc:
            raise AccessFailed(NONE, reason_of(exc)) from exc
        if not ok:
            raise AccessFailed(NONE, t("access.reason.login"))

    def install(self, node: Node, target: Target, public_key: str) -> dict:
        transport = self.app.env.transport
        self.show(t("access.installing", node=self.app.mask(node.name)))
        script = bootstrap.install_script(public_key)
        result = transport.root_run(target, bootstrap.REMOTE_COMMAND, script, timeout=120)
        if result.code == bootstrap.NO_PYTHON:
            prompt = Text(t("access.no_python", node=self.app.mask(node.name)))
            items = [("yes", t("access.install_python"), ""), ("no", t("access.skip"), "")]
            if self.ask_menu(prompt, items) != "yes":
                raise AccessFailed(NONE, t("access.reason.python"))
            self.show(t("access.installing_python", node=self.app.mask(node.name)))
            installed = transport.root_run(target, bootstrap.INSTALL_PYTHON, timeout=600)
            if not installed.ok:
                raise AccessFailed(NONE, t("access.reason.python"))
            self.show(t("access.installing", node=self.app.mask(node.name)))
            result = transport.root_run(target, bootstrap.REMOTE_COMMAND, script, timeout=120)
        answer = bootstrap.parse_result(result.stdout)
        if not result.ok or "error" in answer:
            detail = str(answer.get("error") or result.stderr.strip()[:80] or result.code)
            raise AccessFailed(NONE, t("access.reason.failed", detail=detail))
        return answer

    def verify(self, node: Node, target: Target, public_key: str) -> dict:
        """A new connection with the KERBEROS key; on failure the key line goes away."""
        transport = self.app.env.transport
        self.show(t("access.verify"))
        try:
            return transport.agent(target, "version", fresh=True)
        except (TransportError, NodeAgentError) as exc:
            transport.root_run(
                target, bootstrap.REMOTE_COMMAND, bootstrap.remove_script(public_key)
            )
            raise AccessFailed(NONE, t("access.reason.verify")) from exc

    def setup(self, node: Node, record: Optional[NodeRecord], public_key: str) -> None:
        transport, state = self.app.env.transport, self.app.env.state
        target = self.pin_host_key(node, target_of(node, record), record)
        self.login(node, target)
        try:
            answer = self.install(node, target, public_key)
            version = self.verify(node, target, public_key)
        finally:
            transport.close_root(target)
        key_blob = state.pinned(target.address, target.port) or ""
        from kerberos.nodes.keys import fingerprint

        state.save_node(
            NodeRecord(
                uuid=node.uuid,
                name=node.name,
                address=node.address,
                ssh_port=target.port,
                fingerprint=fingerprint(key_blob) if key_blob else "",
                agent=str(version.get("agent", "")),
                panel_ip=str(answer.get("panelIp", "")),
                access=OK,
            )
        )

    def refresh(self, node: Node, record: NodeRecord) -> bool:
        """Known node: check the agent and update it (§8.3). False: set up again."""
        transport = self.app.env.transport
        target = target_of(node, record)
        self.show(t("access.checking_agent", node=self.app.mask(node.name)))
        try:
            answer = transport.agent(target, "version")
            local = bootstrap.agent_sha256()
            if answer.get("sha256") != local:
                self.show(t("access.updating", node=self.app.mask(node.name)))
                answer = transport.agent(target, f"update {local}", data=bootstrap.agent_source())
            record.agent = str(answer.get("agent", record.agent))
            record.access = OK
            self.app.env.state.save_node(record)
            return True
        except TransportError as exc:
            if exc.kind == "hostkey_changed":
                return False
            if exc.kind in ("auth", "failed"):
                return False  # the panel address may have changed (§8.4): set up again
            raise AccessFailed(NONE, reason_of(exc)) from exc
        except NodeAgentError as exc:
            raise AccessFailed(NONE, t("access.reason.failed", detail=exc.code)) from exc

    # -- the screen ------------------------------------------------------------
    def run(self) -> Any:
        try:
            public_key = ensure_key(self.app)
        except AccessFailed as exc:
            self.app.notice("error", exc.reason, t("access.title"))
            return BACK
        state = self.app.env.state
        for node in self.nodes:
            if self.status.get(node.uuid) == OK:
                continue
            record = state.node(node.uuid)
            try:
                if record and record.access == OK and self.refresh(node, record):
                    self.status[node.uuid] = OK
                    continue
                self.setup(node, record, public_key)
                self.status[node.uuid] = OK
            except AccessFailed as exc:
                self.status[node.uuid] = exc.status
                self.reasons[node.uuid] = exc.reason
        self.action = ""
        if self.session.mode == "fix" and "admin" not in self.session.data:
            self.session.data["admin"] = self.ask_admin()
        return self.summary()

    def summary(self) -> Any:
        ok = sum(1 for n in self.nodes if self.status.get(n.uuid) == OK)
        lines: list[RenderableType] = [Text(t("access.summary", ok=ok, total=len(self.nodes)))]
        if ok < len(self.nodes):
            lines.append(Text(t("access.panel_only"), style="muted"))
        admin = self.session.data.get("admin")
        if admin:
            lines.append(Text(t("access.admin.chosen." + admin["mode"]), style="muted"))

        def handle(key: str) -> Optional[str]:
            if key == "enter":
                return NEXT
            if key == "esc":
                return BACK
            return None

        keys = (("Enter", t("keys.next")), ("Esc", t("keys.back")), ("q", t("keys.quit")))
        self.action = ""
        return self.app.interact(t("access.title"), lambda _w, _h: self.frame(*lines), keys, handle)

    def ask_admin(self) -> dict:
        """§8.5: once per run, which key keeps the person's own access."""
        text = self.app.env.host.read_text("/root/.ssh/authorized_keys") or ""
        own = [k for k in parse_authorized_keys(text) if not k.is_kerberos]
        items = []
        if own:
            items.append(("mine", t("access.admin.mine", n=len(own)), ""))
        items.append(("create", t("access.admin.create"), ""))
        items.append(("skip", t("access.admin.skip"), ""))
        intro = t("access.admin_keys") if own else t("access.no_admin_key")
        prompt = Group(Text(intro), Text(t("access.admin.later"), style="muted"))
        choice = self.ask_menu(prompt, items)
        if choice != "mine":
            return {"mode": choice, "keys": []}
        rows = [[k.type, k.comment or "—", k.fingerprint] for k in own]
        checklist = Checklist(
            rows,
            [t("access.col.type"), t("access.col.comment"), t("access.col.fingerprint")],
            selected=set(range(len(own))),
        )

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return "skip"
            if checklist.handle(key) == "done":
                return "done" if checklist.selected else None
            return None

        keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("keys.next")))
        body = Group(Text(t("access.admin.choose")), checklist)
        result = self.app.interact(t("access.admin.title"), body, keys, handle)
        if result == "skip":
            return {"mode": "skip", "keys": []}
        return {"mode": "mine", "keys": [own[i].line for i in sorted(checklist.selected)]}


def reason_of(exc: TransportError) -> str:
    if exc.kind == "hostkey_changed":
        return t("access.reason.hostkey")
    if exc.kind in ("refused", "timeout", "unreachable"):
        return t("access.reason.unreachable")
    if exc.kind == "auth":
        return t("access.reason.login")
    return t("access.reason.failed", detail=exc.kind)


def step(app: App, session: Session) -> Any:
    return AccessScreen(app, session).run()

"""S2. Panel (tech.md §6, §7): find Remnawave, sign in from the window, read it.

The password and the token are typed into secret fields and live only in
memory: the password until the login request, the token inside PanelClient.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos.copy import t
from kerberos.flow import BACK, EXIT_PANEL, NEXT
from kerberos.panel.client import PanelClient
from kerberos.panel.discover import PanelLocation, discover
from kerberos.panel.errors import PanelError
from kerberos.panel.model import PanelSnapshot
from kerberos.ui.widgets import Notice, TextInput

if TYPE_CHECKING:
    from kerberos.app import App, Session

API_RE = re.compile(r"^https?://[\w.\-\[\]:]+(:\d{1,5})?(/[\w.\-/]*)?$")


def keys_form() -> tuple:
    return (
        ("Tab", t("keys.field")),
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
    )


def keys_next() -> tuple:
    return (
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
        ("m", t("keys.mask")),
        ("q", t("keys.quit")),
    )


def error_text(exc: PanelError, api: str = "") -> str:
    if exc.code == "unauthorized":
        return t("panel.err.token")
    if exc.code == "forbidden":
        return t("panel.err.forbidden", operation=exc.operation)
    if exc.code == "server_error":
        return t("panel.err.server", status=exc.status, operation=exc.operation)
    if exc.code == "timeout":
        return t("panel.err.timeout", operation=exc.operation)
    if exc.code == "unreachable":
        return t("panel.err.unreachable", api=api)
    if exc.code == "no_response":
        return t("panel.err.no_response", operation=exc.operation)
    if exc.code == "bad_request":
        return t("panel.err.bad_request", operation=exc.operation, detail=exc.detail)
    return t("panel.err.bad_response", detail=exc.detail or exc.operation)


def found_lines(app: App, location: PanelLocation) -> list[RenderableType]:
    lines: list[RenderableType] = [Text(t("panel.found", version=location.version), style="bold")]
    lines.append(Text(t("panel.api", api=app.mask(location.api)), style="muted"))
    if location.panel_domain:
        lines.append(Text(t("panel.domain", domain=app.mask(location.panel_domain)), style="muted"))
    return lines


def ask_api(app: App) -> Optional[str]:
    field = TextInput(
        t("panel.api_label"),
        hint=t("panel.api_hint"),
        validate=lambda v: None if API_RE.match(v.strip()) else t("panel.api_invalid"),
        value="http://127.0.0.1:3000/api",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    body = Group(Notice("warning", t("panel.not_found")), Text(""), field)
    value = app.interact(t("s2.title"), body, keys_form(), handle, typing=True)
    return value.strip() or None


def connect(app: App, client: PanelClient, location: PanelLocation) -> Optional[bool]:
    """Ask how the panel lets in. None: the person gave up."""
    while True:
        try:
            return client.password_enabled()
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return None


def login_form(app: App, client: PanelClient, location: PanelLocation) -> bool:
    login = TextInput(t("panel.login"))
    password = TextInput(t("panel.password"), secret=True)
    fields = [login, password]
    state: dict[str, Any] = {"focus": 0, "error": None}

    def body(_w: int, _h: int) -> RenderableType:
        for i, item in enumerate(fields):
            item.focused = i == state["focus"]
        parts = found_lines(app, location) + [Text(""), Text(t("panel.login_hint")), Text("")]
        parts += [login, Text(""), password]
        if state["error"]:
            parts += [Text(""), Notice("error", state["error"])]
        return Group(*parts)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key in ("tab", "down", "up"):
            state["focus"] = 1 - state["focus"]
            return None
        if key == "enter":
            if state["focus"] == 0:
                if login.value.strip():
                    state["focus"] = 1
                return None
            if login.value.strip() and password.value:
                return "submit"
            return None
        fields[state["focus"]].handle(key)
        state["error"] = None
        return None

    while True:
        if app.interact(t("s2.title"), body, keys_form(), handle, typing=True) == "back":
            password.clear()
            return False
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        try:
            client.login(login.value.strip(), password.value)
            password.clear()
            return True
        except PanelError as exc:
            password.clear()
            if exc.code == "unauthorized":
                state["error"] = t("panel.err.login")
            elif exc.code == "forbidden":
                state["error"] = t("panel.err.password_off")
            elif not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return False
            state["focus"] = 1


def token_form(app: App, client: PanelClient, location: PanelLocation) -> bool:
    token = TextInput(t("panel.token"), secret=True)
    state: dict[str, Any] = {"error": None}

    def body(_w: int, _h: int) -> RenderableType:
        parts = found_lines(app, location) + [Text(""), Text(t("panel.token_hint")), Text("")]
        parts.append(token)
        if state["error"]:
            parts += [Text(""), Notice("error", state["error"])]
        return Group(*parts)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key == "enter":
            return "submit" if token.value.strip() else None
        token.handle(key)
        state["error"] = None
        return None

    while True:
        if app.interact(t("s2.title"), body, keys_form(), handle, typing=True) == "back":
            token.clear()
            return False
        client.set_token(token.value)
        token.clear()
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        try:
            client.nodes()
            return True
        except PanelError as exc:
            client.forget_token()
            if exc.code == "unauthorized":
                state["error"] = t("panel.err.token")
            elif not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return False


def load(app: App, client: PanelClient, location: PanelLocation) -> Optional[PanelSnapshot]:
    while True:
        app.draw(t("s2.title"), Text(t("panel.loading")))
        try:
            return client.snapshot(location.version, location.panel_domain)
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return None


def register_sensitive(app: App, snapshot: PanelSnapshot) -> None:
    """Domains of the fleet are masked on every screen and in the report."""
    masker = app.env.masker
    masker.register(snapshot.panel_domain)
    for node in snapshot.nodes:
        masker.register(node.address)
    for host in snapshot.hosts:
        masker.register(host.address, host.sni)
    for profile in snapshot.profiles:
        for inbound in profile.config.get("inbounds") or []:
            stream = (inbound or {}).get("streamSettings") or {}
            reality = stream.get("realitySettings") or {}
            for name in reality.get("serverNames") or []:
                if isinstance(name, str):
                    masker.register(name)
            dest = reality.get("dest")
            if isinstance(dest, str):
                masker.register(dest.rsplit(":", 1)[0])


def step(app: App, session: Session) -> Any:
    if session.snapshot is None:
        app.draw(t("s2.title"), Text(t("panel.searching")))
        location = discover(app.env.host) if app.env.host is not None else None
        if location is None:
            api = ask_api(app)
            if api is None:
                return BACK
            location = PanelLocation(api=api, version="?")
        app.env.masker.register(location.panel_domain)
        client = PanelClient(location.api, app.env.panel_transport, app.env.clock)
        password_enabled = connect(app, client, location)
        if password_enabled is None:
            return EXIT_PANEL
        form = login_form if password_enabled else token_form
        if not form(app, client, location):
            return BACK
        snapshot = load(app, client, location)
        if snapshot is None:
            return EXIT_PANEL
        register_sensitive(app, snapshot)
        session.location, session.panel, session.snapshot = location, client, snapshot

    location, snapshot = session.location, session.snapshot

    def body(_w: int, _h: int) -> RenderableType:
        ok = Text(
            f"✓ {t('panel.ok', nodes=len(snapshot.nodes), hosts=len(snapshot.hosts))}", style="ok"
        )
        return Group(*found_lines(app, location), Text(""), ok)

    def handle(key: str) -> Optional[str]:
        if key == "enter":
            return NEXT
        if key == "esc":
            return BACK
        return None

    return app.interact(t("s2.title"), body, keys_next(), handle)

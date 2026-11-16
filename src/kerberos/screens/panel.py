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
from kerberos.panel.discover import PanelLocation, discover, discover_xui
from kerberos.panel.errors import PanelError
from kerberos.panel.model import PanelSnapshot
from kerberos.ui.widgets import Menu, Notice, TextInput

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


UNREACHABLE = {"remnawave": "panel.err.unreachable", "3x-ui": "panel.xui.err.unreachable"}


def error_text(exc: PanelError, api: str = "", kind: str = "") -> str:
    """What went wrong and what to do; `kind` names the panel to check (§7.5, §7.6)."""
    if exc.code == "unauthorized":
        return t("panel.err.token")
    if exc.code == "forbidden":
        return t("panel.err.forbidden", operation=exc.operation)
    if exc.code == "server_error":
        return t("panel.err.server", status=exc.status, operation=exc.operation)
    if exc.code == "timeout":
        return t("panel.err.timeout", operation=exc.operation)
    if exc.code == "unreachable":
        return t(UNREACHABLE.get(kind, "panel.err.unreachable.any"), api=api)
    if exc.code == "no_response":
        return t("panel.err.no_response", operation=exc.operation)
    if exc.code == "bad_request":
        return t("panel.err.bad_request", operation=exc.operation, detail=exc.detail)
    return t("panel.err.bad_response", detail=exc.detail or exc.operation)


def found_lines(app: App, location: PanelLocation) -> list[RenderableType]:
    if location.version == "?":
        # Typed by hand (or found without a version): no «Нашёл Remnawave ?».
        lines = [Text(t("panel.manual", api=app.mask(location.api)), style="bold")]
    else:
        lines = [Text(t("panel.found", version=location.version), style="bold"),
                 Text(t("panel.api", api=app.mask(location.api)), style="muted")]  # fmt: skip
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
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
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
            elif not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
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
            elif not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return False


def load(app: App, client: PanelClient, location: PanelLocation) -> Optional[PanelSnapshot]:
    while True:
        app.draw(t("s2.title"), Text(t("panel.loading")))
        try:
            return client.snapshot(location.version, location.panel_domain)
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
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
            dest = reality.get("target") or reality.get("dest")
            if isinstance(dest, str):
                masker.register(dest.rsplit(":", 1)[0])


PANELS = ("remnawave", "3x-ui")


def choose_panel(app: App) -> Any:
    """§6 S2, §7.6: which panel runs here, Remnawave or 3x-ui; the one found is first.

    (kind, location or None) or BACK. `--panel` answers without asking.
    """
    app.draw(t("s2.title"), Text(t("panel.searching")))
    host = app.env.host
    found = {
        "remnawave": discover(host) if host is not None else None,
        "3x-ui": discover_xui(host) if host is not None else None,
    }
    wanted = getattr(app.env, "panel_kind", None)
    if wanted in PANELS:
        return wanted, found[wanted]
    items = []
    for kind in PANELS:
        location = found[kind]
        hint = (t("panel.choose.found", version=location.version) if location
                else t("panel.choose.none"))  # fmt: skip
        items.append((kind, t(f"panel.kind.{kind}"), hint))
    first = 1 if found["3x-ui"] and not found["remnawave"] else 0
    menu = Menu(items, selected=first)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        return menu.handle(key)

    body = Group(Text(t("panel.choose"), style="bold"), Text(""), menu, Text(""),
                 Text(t("panel.choose.hint"), style="muted"))  # fmt: skip
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    choice = app.interact(t("s2.title"), body, keys, handle)
    if choice == "back":
        return BACK
    return choice, found[choice]


def open_panel(app: App, kind: Optional[str] = None) -> Any:
    """Find the panel and sign in. A (location, client) pair, BACK or EXIT_PANEL.

    `kind` skips the question (rollback and finalize know the panel of the run).
    """
    if kind is None:
        chosen = choose_panel(app)
        if chosen == BACK:
            return BACK
        kind, location = chosen
    else:
        host = app.env.host
        finder = discover_xui if kind == "3x-ui" else discover
        location = finder(host) if host is not None else None
    if kind == "3x-ui":
        return open_xui(app, location)
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
    return location, client


# -- 3x-ui (§7.6) ------------------------------------------------------------------
XUI_URL_RE = re.compile(r"^https?://[\w.\-\[\]:]+(:\d{1,5})?(/[\w.\-/]*)?$")


def ask_xui_url(app: App) -> Optional[str]:
    field = TextInput(
        t("panel.xui.url_label"),
        hint=t("panel.xui.url_hint"),
        validate=lambda v: None if XUI_URL_RE.match(v.strip()) else t("panel.xui.url_invalid"),
        value="http://127.0.0.1:2053/",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    body = Group(Notice("warning", t("panel.xui.not_found")), Text(""), field)
    value = app.interact(t("s2.title"), body, keys_form(), handle, typing=True)
    return value.strip() or None


def xui_lines(app: App, location: PanelLocation) -> list[RenderableType]:
    """Where the panel is, without its secret path: that path is a password of sorts."""
    if location.version != "?":
        head = t("panel.xui.found", version=location.version)
    else:
        # Found here without a version, or typed by hand (no settings were read).
        head = t("panel.xui.found.unknown") if location.info else t("panel.xui.manual")
    lines: list[RenderableType] = [Text(head, style="bold")]
    if location.info.get("port"):
        lines.append(Text(t("panel.xui.port", port=location.info["port"]), style="muted"))
    if location.panel_domain:
        lines.append(Text(t("panel.domain", domain=app.mask(location.panel_domain)), style="muted"))
    return lines


def xui_login_form(app: App, client: Any, location: PanelLocation) -> bool:
    fields = [TextInput(t("panel.xui.login")), TextInput(t("panel.password"), secret=True)]
    if location.info.get("twoFactor"):
        fields.append(TextInput(t("panel.xui.code"), secret=True))
    state: dict[str, Any] = {"focus": 0, "error": None}

    def body(_w: int, _h: int) -> RenderableType:
        for i, item in enumerate(fields):
            item.focused = i == state["focus"]
        parts = xui_lines(app, location) + [Text(""), Text(t("panel.xui.login_hint")), Text("")]
        for item in fields:
            parts += [item, Text("")]
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
            if all(item.value.strip() for item in fields):
                return "submit"
            state["focus"] = next(i for i, item in enumerate(fields) if not item.value.strip())
            return None
        fields[state["focus"]].handle(key)
        state["error"] = None
        return None

    def forget() -> None:
        for item in fields[1:]:
            item.clear()

    while True:
        if app.interact(t("s2.title"), body, keys_form(), handle, typing=True) == "back":
            forget()
            return False
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        values = [item.value for item in fields]
        try:
            client.login(values[0].strip(), values[1], values[2].strip() if len(values) > 2 else "")
            forget()
            return True
        except PanelError as exc:
            forget()
            if exc.code == "unauthorized":
                state["error"] = t("panel.xui.err.login")
            elif exc.code == "forbidden":
                state["error"] = t("panel.xui.err.forbidden")
            elif not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return False
            state["focus"] = 1


def open_xui(app: App, location: Optional[PanelLocation]) -> Any:
    from kerberos.panel.xui import XuiClient

    if location is None:
        url = ask_xui_url(app)
        if url is None:
            return BACK
        location = PanelLocation(api=url, version="?", kind="3x-ui")
    app.env.masker.register(location.panel_domain)
    client = XuiClient(location.api, app.env.xui_transport, app.env.clock, location.panel_domain)
    if not xui_login_form(app, client, location):
        return BACK
    return location, client


def public_ipv4(app: App, location: PanelLocation) -> Optional[str]:
    """The address the world reaches this server at: an interface, the panel domain, or asked."""
    from kerberos.agent import parse_ip_addr

    result = app.env.host.run(["ip", "-j", "addr", "show"], timeout=10)
    v4, _v6 = parse_ip_addr(result.stdout) if result.ok else ([], [])
    if v4:
        return v4[0]
    if location.panel_domain and app.env.prober is not None:
        found = [a for a in app.env.prober.resolve(location.panel_domain) if ":" not in a]
        if found:
            return found[0]
    field = TextInput(t("panel.xui.ip_label"), hint=t("panel.xui.ip_hint"),
                      validate=lambda v: None if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", v.strip())
                      else t("panel.xui.ip_invalid"))  # fmt: skip

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else field.handle(key)

    value = app.interact(t("s2.title"), field, keys_form(), handle, typing=True).strip()
    return value or None


def load_xui(app: App, client: Any, location: PanelLocation) -> Optional[PanelSnapshot]:
    address = public_ipv4(app, location)
    if address is None:
        return None
    while True:
        app.draw(t("s2.title"), Text(t("panel.xui.loading")))
        try:
            return client.snapshot(location, address, app.env.host.hostname())
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api)):
                return None


def step(app: App, session: Session) -> Any:
    if session.snapshot is None:
        opened = open_panel(app)
        if not isinstance(opened, tuple):
            return opened
        location, client = opened
        loader = load_xui if location.kind == "3x-ui" else load
        snapshot = loader(app, client, location)
        if snapshot is None:
            return EXIT_PANEL
        register_sensitive(app, snapshot)
        session.location, session.panel, session.snapshot = location, client, snapshot

    location, snapshot = session.location, session.snapshot

    def body(_w: int, _h: int) -> RenderableType:
        if location.kind == "3x-ui":
            inbounds = len(snapshot.hosts)
            ok = Text(f"✓ {t('panel.xui.ok', inbounds=inbounds)}", style="ok")
            return Group(*xui_lines(app, location), Text(""), ok)
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

"""3x-ui panel client (tech.md §7.6) over a pluggable HTTP session.

Checked against 3x-ui sources from v2.4 to v3.11. 3x-ui keeps a cookie
session: `GET <base>csrf-token` (v3.0+) gives a token for the
`X-CSRF-Token` header of every POST, `POST <base>login` opens the session.
The live session is a urllib opener with a cookie jar in memory: the cookie
never reaches disk or a log. Answers come in an envelope {success, msg,
obj}; a false `success` is an error even with HTTP 200. The panel runs on
this server, so requests go to 127.0.0.1; when the panel has a domain it
checks the Host header, and when it serves TLS for that domain the
certificate is not checked on the loopback.
"""

from __future__ import annotations

import http.cookiejar
import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlsplit

from kerberos import __version__
from kerberos.clock import Clock
from kerberos.panel import xui_model
from kerberos.panel.client import RETRY_DELAYS, TIMEOUT, NoResponse, Transport, Unreachable
from kerberos.panel.errors import PanelError

CSRF = "csrf-token"
LOGIN = "login"
INBOUNDS = "panel/api/inbounds/list"
INBOUND = "panel/api/inbounds/get/{id}"
UPDATE = "panel/api/inbounds/update/{id}"
ONLINES = "panel/api/inbounds/onlines"


class XuiSession:
    """urllib with a cookie jar: the live transport of XuiClient."""

    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )

    def __call__(
        self, method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read() or b""
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ConnectionRefusedError):
                raise Unreachable(str(exc.reason)) from exc
            raise NoResponse(str(exc.reason)) from exc
        except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            raise NoResponse(str(exc)) from exc


class XuiClient:
    def __init__(
        self, base_url: str, transport: Transport, clock: Clock, domain: Optional[str] = None
    ) -> None:
        self.base = base_url if base_url.endswith("/") else base_url + "/"
        self.transport = transport
        self.clock = clock
        self.domain = domain  # 3x-ui answers 403 when Host is not its webDomain
        self.csrf: Optional[str] = None
        self.calls: list[tuple[str, str]] = []

    # -- transport -----------------------------------------------------
    def request(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        headers = {
            "accept": "application/json",
            "user-agent": f"kerberos/{__version__}",
            # With this header 3x-ui answers 401 instead of hiding the API behind 404.
            "x-requested-with": "XMLHttpRequest",
        }
        if self.domain:
            headers["host"] = self.domain
        if method == "POST" and self.csrf:
            headers["x-csrf-token"] = self.csrf
        data = None
        if body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        operation = f"{method} /{path}"
        self.calls.append((method, "/" + path))
        attempt = 0
        while True:
            try:
                status, raw = self.transport(method, self.base + path, headers, data, TIMEOUT)
            except NoResponse as exc:
                if method == "POST":
                    raise PanelError("no_response", operation=operation, detail=str(exc)) from exc
                if attempt < len(RETRY_DELAYS):
                    self.clock.sleep(RETRY_DELAYS[attempt])
                    attempt += 1
                    continue
                raise PanelError("timeout", operation=operation, detail=str(exc)) from exc
            except Unreachable as exc:
                if attempt < len(RETRY_DELAYS):
                    self.clock.sleep(RETRY_DELAYS[attempt])
                    attempt += 1
                    continue
                raise PanelError("unreachable", operation=operation, detail=str(exc)) from exc
            if status >= 500 and attempt < len(RETRY_DELAYS) and method == "GET":
                self.clock.sleep(RETRY_DELAYS[attempt])
                attempt += 1
                continue
            break
        if status >= 500:
            raise PanelError("server_error", status, operation)
        if status == 401:
            raise PanelError("unauthorized", status, operation)
        if status == 403:
            raise PanelError("forbidden", status, operation)
        if status >= 400:
            raise PanelError("bad_request", status, operation)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError) as exc:
            raise PanelError("bad_response", status, operation, "not JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("success"), bool):
            raise PanelError("bad_response", status, operation, "no envelope")
        if not payload["success"]:
            code = "unauthorized" if path == LOGIN else "bad_request"
            raise PanelError(code, status, operation, str(payload.get("msg") or "")[:200])
        return payload.get("obj")

    def fetch_csrf(self) -> None:
        """v3.0+: a token for the POSTs of this session; older panels have none (404)."""
        try:
            token = self.request("GET", CSRF)
        except PanelError as exc:
            if exc.code in ("unauthorized", "bad_request") and exc.status in (401, 404):
                self.csrf = None
                return
            raise
        self.csrf = token if isinstance(token, str) and token else None

    # -- API -----------------------------------------------------------
    def login(self, username: str, password: str, code: str = "") -> None:
        self.fetch_csrf()
        self.request("POST", LOGIN, {"username": username, "password": password,
                                     "twoFactorCode": code})  # fmt: skip
        self.fetch_csrf()  # the session after login has its own token

    def inbounds(self) -> list[dict]:
        """Inbounds of this server: from v3.0 a panel may also run some on other nodes."""
        raw = self.request("GET", INBOUNDS)
        if not isinstance(raw, list):
            raise PanelError("bad_response", operation=f"GET /{INBOUNDS}", detail="not a list")
        return [xui_model.inbound(item) for item in raw if not item_node(item)]

    def inbound(self, ident: int) -> dict:
        return xui_model.inbound(self.request("GET", INBOUND.format(id=ident)))

    def update_inbound(self, ident: int, stream: dict) -> dict:
        """New streamSettings for one inbound, read fresh first; every other field as it is.

        Panels before v3.9 replace the clients with what is sent, so the inbound
        goes back exactly as it was just read.
        """
        current = self.inbound(ident)
        body = {key: value for key, value in current["raw"].items() if key != "clientStats"}
        body["settings"] = json.dumps(current["settings"], ensure_ascii=False)
        body["sniffing"] = json.dumps(current["sniffing"], ensure_ascii=False)
        body["streamSettings"] = json.dumps(stream, ensure_ascii=False)
        self.request("POST", UPDATE.format(id=ident), body)
        return self.inbound(ident)

    def online(self) -> int:
        try:
            raw = self.request("POST", ONLINES)
        except PanelError:
            return 0
        return len(raw) if isinstance(raw, list) else 0

    def snapshot(self, location: Any, address: str, name: str) -> Any:
        return xui_model.snapshot(location.version, self.inbounds(), address, name,
                                  location.info, location.panel_domain, self.online())  # fmt: skip


def origin(url: str) -> str:
    """scheme://host:port of the panel: its base path is a secret (§7.6) and never shown."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def item_node(raw: Any) -> bool:
    """True when the inbound runs on another node of a v3 multi-node panel."""
    return isinstance(raw, dict) and bool(raw.get("nodeId"))

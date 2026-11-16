"""An in-memory 3x-ui panel (tech.md §7.6) for tests and --demo.

It holds KERBEROS to the contract of the real panel: a v3 panel wants the
CSRF token on every POST and a session for the API, a panel with a domain
wants that Host, fields of an update arrive as the inbound was read. A
request that breaks the contract fails the test loudly.
"""

from __future__ import annotations

import copy
import json
import secrets
from typing import Any, Optional, Union
from urllib.parse import urlsplit

from kerberos.panel.client import NoResponse
from kerberos.panel.fake import ContractError

UPDATE_FIELDS = {
    "id", "up", "down", "total", "remark", "enable", "expiryTime", "listen", "port",
    "protocol", "settings", "streamSettings", "sniffing", "tag", "allTime", "subSortIndex",
    "excludeFromSub", "trafficReset", "trafficResetDay", "nodeId", "shareAddrStrategy",
    "shareAddr", "disableFlow", "userId", "lastTrafficResetTime",
}  # fmt: skip


class FakeXui:
    def __init__(self, *, base: str = "/", version: int = 3, domain: Optional[str] = None,
                 credentials: tuple = ("admin", "admin-password"), two_factor: str = "",
                 accept_any_login: bool = False) -> None:  # fmt: skip
        self.base = base
        self.version = version  # 2: no CSRF, JSON strings; 3: CSRF, objects in answers
        self.domain = domain
        self.credentials = credentials
        self.two_factor = two_factor
        self.accept_any_login = accept_any_login
        self.inbounds: list[dict] = []
        self.online_emails: list[str] = []
        self.logged_in = False
        self.csrf: Optional[str] = None
        self.failures: dict = {}
        self.log: list[tuple[str, str, Any]] = []

    # -- test helpers ------------------------------------------------------
    def fail(self, method: str, path: str, kind: Union[int, str], times: int = 1) -> None:
        self.failures[(method, path)] = [kind, times]

    @property
    def mutations(self) -> list[tuple[str, str, Any]]:
        reads = ("login", "panel/api/inbounds/onlines")  # POSTs that change nothing
        return [entry for entry in self.log if entry[0] == "POST" and entry[1] not in reads]

    def inbound(self, ident: int) -> dict:
        return next(i for i in self.inbounds if i["id"] == ident)

    def stream(self, ident: int) -> dict:
        value = self.inbound(ident)["streamSettings"]
        return json.loads(value) if isinstance(value, str) else value

    # -- the HTTP side -------------------------------------------------------
    def __call__(self, method: str, url: str, headers: dict, body: Optional[bytes],
                 timeout: float) -> tuple[int, bytes]:  # fmt: skip
        parts = urlsplit(url)
        if not parts.path.startswith(self.base):
            return 404, b"404 page not found"
        path = parts.path[len(self.base) :]
        lower = {k.lower(): v for k, v in headers.items()}
        if self.domain and lower.get("host") != self.domain:
            return 403, b""
        data = json.loads(body.decode("utf-8")) if body else None
        self.log.append((method, path, data))
        failure = self.failures.get((method, path))
        if failure:
            kind, left = failure
            failure[1] = left - 1
            if failure[1] <= 0:
                del self.failures[(method, path)]
            if kind == "no_response":
                raise NoResponse("connection closed")
            return int(kind), b"{}"
        if method == "POST" and self.version >= 3:
            if not self.csrf or lower.get("x-csrf-token") != self.csrf:
                return 403, b""
        if method == "GET" and path == "csrf-token":
            if self.version < 3:
                return 404, b"404 page not found"
            self.csrf = secrets.token_hex(8)
            return self._ok(self.csrf)
        if method == "POST" and path == "login":
            return self._login(data)
        if not self.logged_in:
            return (401 if lower.get("x-requested-with") else 404), b""
        if method == "GET" and path == "panel/api/inbounds/list":
            return self._ok([self._answer(i) for i in self.inbounds])
        if method == "GET" and path.startswith("panel/api/inbounds/get/"):
            found = [i for i in self.inbounds if str(i["id"]) == path.rsplit("/", 1)[1]]
            if not found:
                return self._fail("Inbound not found")
            return self._ok(self._answer(found[0]))
        if method == "POST" and path.startswith("panel/api/inbounds/update/"):
            return self._update(int(path.rsplit("/", 1)[1]), data)
        if method == "POST" and path == "panel/api/inbounds/onlines":
            return self._ok(list(self.online_emails))
        return 404, b"404 page not found"

    def _login(self, data: Any) -> tuple[int, bytes]:
        if not isinstance(data, dict) or set(data) - {"username", "password", "twoFactorCode"}:
            raise ContractError(f"bad login body {data!r}")
        good = (data.get("username"), data.get("password")) == tuple(self.credentials)
        if self.accept_any_login and data.get("username") and data.get("password"):
            good = True
        if good and self.two_factor and data.get("twoFactorCode") != self.two_factor:
            good = False
        if not good:
            return self._fail("Wrong username or password")
        self.logged_in = True
        self.csrf = None  # a new session gets a new token
        return self._ok(None)

    def _update(self, ident: int, data: Any) -> tuple[int, bytes]:
        if not isinstance(data, dict):
            raise ContractError("update body must be an object")
        extra = set(data) - UPDATE_FIELDS
        if extra:
            raise ContractError(f"unknown inbound fields {sorted(extra)}")
        current = next((i for i in self.inbounds if i["id"] == ident), None)
        if current is None:
            return self._fail("Inbound not found")
        if data.get("id") != ident or data.get("port") != current["port"]:
            raise ContractError("an update must send the inbound it read")
        for key in ("settings", "streamSettings", "sniffing"):
            value = data.get(key)
            if not isinstance(value, str):
                raise ContractError(f"{key} must be sent as a JSON string")
            parsed = json.loads(value)
            if not isinstance(parsed, dict):
                raise ContractError(f"{key} must be an object")
        if json.loads(data["settings"]) != _object(current["settings"]):
            raise ContractError("clients changed: KERBEROS must send them back as read")
        stored = copy.deepcopy(data)
        if self.version >= 3:
            for key in ("settings", "streamSettings", "sniffing"):
                stored[key] = json.loads(stored[key])
        current.update(stored)
        return self._ok(self._answer(current))

    def _answer(self, item: dict) -> dict:
        answer = copy.deepcopy(item)
        for key in ("settings", "streamSettings", "sniffing"):
            value = answer.get(key)
            if self.version >= 3:
                answer[key] = _object(value)
            elif not isinstance(value, str):
                answer[key] = json.dumps(value)
        return answer

    @staticmethod
    def _ok(obj: Any) -> tuple[int, bytes]:
        return 200, json.dumps({"success": True, "msg": "", "obj": obj}).encode()

    @staticmethod
    def _fail(msg: str) -> tuple[int, bytes]:
        return 200, json.dumps({"success": False, "msg": msg, "obj": None}).encode()


def _object(value: Any) -> dict:
    return json.loads(value) if isinstance(value, str) else copy.deepcopy(value or {})


def raw_inbound(ident: int, port: int, protocol: str, stream: dict, *, remark: str = "",
                enable: bool = True, clients: Optional[list] = None) -> dict:  # fmt: skip
    return {
        "id": ident,
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark or f"inbound-{ident}",
        "enable": enable,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": protocol,
        "settings": {"clients": clients or [], "decryption": "none"},
        "streamSettings": stream,
        "tag": f"inbound-{port}",
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        "nodeId": None,
    }

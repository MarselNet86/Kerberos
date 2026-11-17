"""Prober port: checks the panel server makes from outside (tech.md §10.2).

TLS without SNI to a node, HTTP(S) requests to a node address with a chosen
Host and SNI, DNS resolution and ping. Live uses ssl, socket and the
system ping; the fake answers from tables (tests and --demo). These are the
only network calls besides the panel API, SSH and the consented whois.
"""

from __future__ import annotations

import re
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Protocol


@dataclass
class TlsResult:
    ok: bool
    names: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class HttpResult:
    status: Optional[int]
    headers: dict = field(default_factory=dict)
    body: str = ""


class Prober(Protocol):
    def tls_names(self, ip: str, port: int = 443, sni: Optional[str] = None) -> TlsResult: ...

    def http(
        self, ip: str, port: int, host: str, path: str = "/", *, tls: bool = True,
        headers: Optional[dict] = None,
    ) -> HttpResult: ...  # fmt: skip

    def resolve(self, name: str) -> list[str]: ...

    def ping(self, ip: str) -> bool: ...

    def auth_methods(self, ip: str, port: int) -> Optional[list[str]]: ...


def cert_names(cert: dict) -> list[str]:
    names = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value not in names:
                names.append(value)
    return names


class LiveProber:
    timeout = 8.0

    def tls_names(self, ip: str, port: int = 443, sni: Optional[str] = None) -> TlsResult:
        context = ssl.create_default_context()
        context.check_hostname = False
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=sni) as tls:
                    return TlsResult(True, cert_names(tls.getpeercert() or {}))
        except ssl.SSLCertVerificationError:
            return TlsResult(False, [], "untrusted")
        except (OSError, ssl.SSLError) as exc:
            return TlsResult(False, [], type(exc).__name__)

    def http(
        self, ip: str, port: int, host: str, path: str = "/", *, tls: bool = True,
        headers: Optional[dict] = None,
    ) -> HttpResult:  # fmt: skip
        extra = "".join(f"{key}: {value}\r\n" for key, value in (headers or {}).items())
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n{extra}Connection: close\r\n\r\n"
        ).encode()
        data = b""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                conn = raw
                if tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = context.wrap_socket(raw, server_hostname=host)
                conn.sendall(request)
                while len(data) < 200_000:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
        except (OSError, ssl.SSLError):
            return HttpResult(None)
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            return HttpResult(None)
        headers = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep:
                headers[key.strip().lower()] = value.strip()
        return HttpResult(status, headers, body[:20_000].decode("utf-8", "replace"))

    def resolve(self, name: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            return []
        result: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in result:
                result.append(address)
        return result

    def ping(self, ip: str) -> bool:
        flag = "-6" if ":" in ip else "-4"
        try:
            proc = subprocess.run(
                ["ping", flag, "-c", "1", "-W", "2", ip],
                capture_output=True, timeout=10, check=False,
            )  # fmt: skip
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def auth_methods(self, ip: str, port: int) -> Optional[list[str]]:
        """What the SSH server offers to a stranger: §10.3 wants only publickey."""
        argv = [
            "ssh", "-F", "/dev/null", "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=none", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR", "-p", str(port), f"kerberos-probe@{ip}", "true",
        ]  # fmt: skip
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"Permission denied \(([^)]*)\)", proc.stderr)
        return match.group(1).split(",") if match else None


@dataclass
class FakeProber:
    tls: dict = field(default_factory=dict)  # ip -> TlsResult
    pages: dict = field(default_factory=dict)  # (ip, port, host, path) -> HttpResult
    dns: dict = field(default_factory=dict)  # name -> [ip]
    pings: dict = field(default_factory=dict)  # ip -> bool
    auth: Optional[object] = None  # callable(ip, port) -> methods, or None
    # callable(ip, port, host, path, headers) -> HttpResult or None: a server whose
    # answers change while KERBEROS works on it (the portal of §10.10)
    responder: Optional[object] = None
    calls: list = field(default_factory=list)

    def tls_names(self, ip: str, port: int = 443, sni: Optional[str] = None) -> TlsResult:
        self.calls.append(("tls", ip, port, sni))
        return self.tls.get((ip, sni), self.tls.get(ip, TlsResult(False, [], "refused")))

    def http(
        self, ip: str, port: int, host: str, path: str = "/", *, tls: bool = True,
        headers: Optional[dict] = None,
    ) -> HttpResult:  # fmt: skip
        self.calls.append(("http", ip, port, host, path))
        if callable(self.responder):
            answer = self.responder(ip, port, host, path, dict(headers or {}))
            if answer is not None:
                return answer
        return self.pages.get((ip, port, host, path), HttpResult(None))

    def resolve(self, name: str) -> list[str]:
        self.calls.append(("resolve", name))
        return list(self.dns.get(name.lower().rstrip("."), []))

    def ping(self, ip: str) -> bool:
        self.calls.append(("ping", ip))
        return self.pings.get(ip, False)

    def auth_methods(self, ip: str, port: int) -> Optional[list[str]]:
        self.calls.append(("auth", ip, port))
        return self.auth(ip, port) if callable(self.auth) else None

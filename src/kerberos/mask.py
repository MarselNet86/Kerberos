"""Masking of addresses and domains (tech.md §2.7, §12.3).

`m` on any screen and `--mask` replace IPv4, IPv6 and domains with stable
values from the documentation ranges (RFC 5737, RFC 3849, example.com and
example.net). Screenshots and video are made only this way.

The mapping is a pure function of the value (sha256 with linear probing), so
the same address masks to the same replacement on every screen and in the
report files. Values already in documentation ranges stay as they are.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Optional

DOC_V4_PREFIXES = ("192.0.2", "198.51.100", "203.0.113")
DOC_V4_NETS = tuple(ipaddress.ip_network(p + ".0/24") for p in DOC_V4_PREFIXES)
DOC_V6_NET = ipaddress.ip_network("2001:db8::/32")
DOC_DOMAINS = ("example.com", "example.net", "example.org")

# Domains with these top-level labels are masked even when nobody registered
# them (free text from servers). File names like report.md or id_ed25519.pub
# must not look like domains, so md, pub, log, json and similar are absent.
GENERIC_TLDS = frozenset(
    """com net org ru su xn--p1ai рф io me xyz top site online pro cc tech dev app
    cloud host space store shop info biz de nl fi uk us eu kz by ua am ge tr pl cz
    lv lt ee se no ch at fr it es pt ro bg hu sk si hr rs gr il ae in jp kr sg hk
    tw vn th id my ph au nz ca br ar mx cl co is lu li be dk ie""".split()
)

_V4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?!\d|\.\d)")
_V6_RE = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])((?:[A-Za-z0-9\u0400-\u04ff](?:[A-Za-z0-9\u0400-\u04ff-]{0,61}"
    r"[A-Za-z0-9\u0400-\u04ff])?\.)+([A-Za-z\u0400-\u04ff][A-Za-z0-9\u0400-\u04ff-]{1,62}))"
    r"(?![\w-]|\.[A-Za-z0-9\u0400-\u04ff])"
)

V4_SLOTS = [f"{p}.{h}" for p in DOC_V4_PREFIXES for h in range(1, 255)]


def _digest(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")


def is_doc_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.version == 4:
        return any(addr in net for net in DOC_V4_NETS)
    return addr in DOC_V6_NET


def _keep_ip(addr: ipaddress._BaseAddress) -> bool:
    """Addresses that reveal nothing: documentation, loopback, unspecified."""
    if addr.version == 4:
        return any(addr in net for net in DOC_V4_NETS) or addr.is_loopback or addr.is_unspecified
    return addr in DOC_V6_NET or addr.is_loopback or addr.is_unspecified


def is_doc_domain(value: str) -> bool:
    name = value.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in DOC_DOMAINS) or name == "localhost"


class Masker:
    """Stable replacement of addresses and domains; a no-op while disabled."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled
        self._v4: dict[str, str] = {}
        self._v4_used: set[str] = set()
        self._v6: dict[str, str] = {}
        self._domains: dict[str, str] = {}
        self._domain_used: set[str] = set()
        self._registered: set[str] = set()

    def toggle(self) -> None:
        self.enabled = not self.enabled

    def register(self, *values: Optional[str]) -> None:
        """Remember sensitive domains seen in panel or node data."""
        for value in values:
            if not value:
                continue
            name = value.strip().lower().rstrip(".")
            if "." in name and not is_doc_domain(name) and not _looks_like_ip(name):
                self._registered.add(name)

    # -- single values -------------------------------------------------
    def ip(self, value: str) -> str:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return value
        if _keep_ip(addr):
            return value
        if addr.version == 4:
            return self._mask_v4(str(addr))
        return self._mask_v6(str(addr))

    def domain(self, value: str) -> str:
        name = value.lower().rstrip(".")
        if is_doc_domain(name) or "." not in name:
            return value
        if name not in self._domains:
            start = _digest(name)
            for step in range(10_000):
                candidate = f"site{(start + step) % 9000 + 100}.example.net"
                if candidate not in self._domain_used:
                    break
            self._domains[name] = candidate
            self._domain_used.add(candidate)
        return self._domains[name]

    def _mask_v4(self, value: str) -> str:
        if value not in self._v4:
            octets = set(value.split("."))
            start = _digest(value) % len(V4_SLOTS)
            chosen = None
            for step in range(len(V4_SLOTS)):
                slot = V4_SLOTS[(start + step) % len(V4_SLOTS)]
                if slot in self._v4_used or slot.rsplit(".", 1)[1] in octets:
                    continue
                chosen = slot
                break
            if chosen is None:  # more distinct addresses than slots: reuse
                chosen = V4_SLOTS[start]
            self._v4[value] = chosen
            self._v4_used.add(chosen)
        return self._v4[value]

    def _mask_v6(self, value: str) -> str:
        if value not in self._v6:
            self._v6[value] = str(DOC_V6_NET[(_digest(value) % 0xFFFF_FFFF) + 1])
        return self._v6[value]

    # -- free text -----------------------------------------------------
    def __call__(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        return self.text(value)

    def text(self, value: str) -> str:
        """Mask unconditionally (report files written with --mask)."""
        out = _V6_RE.sub(lambda m: self._sub_v6(m.group(1)), value)
        out = _V4_RE.sub(lambda m: self._sub_v4(m.group(1)), out)
        for name in sorted(self._registered, key=len, reverse=True):
            out = re.sub(
                r"(?<![\w-])" + re.escape(name) + r"(?![\w-])",
                lambda _m, n=name: self.domain(n),
                out,
                flags=re.IGNORECASE,
            )
        return _DOMAIN_RE.sub(self._sub_domain, out)

    def data(self, value: Any) -> Any:
        """Mask every string inside JSON-like data."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.data(v) for v in value]
        if isinstance(value, dict):
            return {k: self.data(v) for k, v in value.items()}
        return value

    def _sub_v4(self, value: str) -> str:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return value
        return self.ip(value)

    def _sub_v6(self, value: str) -> str:
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return value
        return self.ip(value)

    def _sub_domain(self, match: re.Match) -> str:
        name = match.group(1)
        tld = match.group(2).lower()
        low = name.lower()
        if is_doc_domain(low) or (low not in self._registered and tld not in GENERIC_TLDS):
            return name
        return self.domain(name)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

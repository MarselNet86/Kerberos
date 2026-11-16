"""Whois port (tech.md §10.2, topic 1): AS of node addresses from whois.cymru.com.

Called only after consent on S5: the request hands node addresses to a
third party.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Protocol

HOST = "whois.cymru.com"


@dataclass
class AsInfo:
    asn: str
    name: str
    country: str = ""


class Whois(Protocol):
    def lookup(self, addresses: list[str]) -> dict[str, AsInfo]: ...


def parse_bulk(text: str) -> dict[str, AsInfo]:
    """`AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name` lines."""
    result = {}
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) >= 7 and cols[0].isdigit():
            result[cols[1]] = AsInfo(cols[0], cols[6], cols[3])
    return result


class CymruWhois:
    def lookup(self, addresses: list[str]) -> dict[str, AsInfo]:
        query = "begin\nverbose\n" + "\n".join(addresses) + "\nend\n"
        data = b""
        try:
            with socket.create_connection((HOST, 43), timeout=15) as conn:
                conn.sendall(query.encode())
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
        except OSError:
            return {}
        return parse_bulk(data.decode("utf-8", "replace"))


@dataclass
class FakeWhois:
    table: dict = field(default_factory=dict)  # ip -> AsInfo
    queries: list = field(default_factory=list)

    def lookup(self, addresses: list[str]) -> dict[str, AsInfo]:
        self.queries.append(list(addresses))
        return {a: self.table[a] for a in addresses if a in self.table}

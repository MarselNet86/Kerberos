"""Validation of agent answers (tech.md §9.2, §19) before checks use them."""

from __future__ import annotations

from typing import Any


class BadAnswer(ValueError):
    """The agent answered outside the contract of §9.2."""


FACT_SHAPE = {
    "os": dict,
    "ipv4": list,
    "ipv6": list,
    "listening": list,
    "ssh": dict,
    "fail2ban": dict,
    "mptcp": dict,
    "nodeApi": dict,
    "nftTables": list,
    "hostKeys": list,
    "firewall": dict,
    "remnanode": dict,
    "nginx": dict,
    "certbot": dict,
    "watch": dict,
}
WATCH_SHAPE = {"v4": dict, "v6": dict, "xray": dict}


def _shape(answer: Any, shape: dict, what: str) -> dict:
    if not isinstance(answer, dict) or answer.get("protocol") != 1:
        raise BadAnswer(f"{what}: not protocol 1")
    for key, kind in shape.items():
        if not isinstance(answer.get(key), kind):
            raise BadAnswer(f"{what}: {key}")
    return answer


def facts(answer: Any) -> dict:
    value = _shape(answer, FACT_SHAPE, "facts")
    ssh = value["ssh"]
    if not isinstance(ssh.get("ports"), list) or not all(isinstance(p, int) for p in ssh["ports"]):
        raise BadAnswer("facts: ssh.ports")
    for item in value["listening"]:
        if not isinstance(item, dict) or not isinstance(item.get("port"), int):
            raise BadAnswer("facts: listening")
    return value


def watch(answer: Any) -> dict:
    value = _shape(answer, WATCH_SHAPE, "watch")
    for family in ("v4", "v6"):
        part = value[family]
        if not isinstance(part.get("connections"), int) or not isinstance(part.get("cut"), int):
            raise BadAnswer(f"watch: {family}")
    return value


def site(answer: Any) -> dict:
    if not isinstance(answer, dict) or not {"template", "altSvc", "status"} <= set(answer):
        raise BadAnswer("site-check")
    return answer

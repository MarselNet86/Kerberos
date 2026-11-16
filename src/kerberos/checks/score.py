"""Score of §12.2: weights of passed checks over weights of applicable ones."""

from __future__ import annotations

from collections.abc import Iterable

from kerberos.fixes.model import WEIGHTS, Finding


def score(findings: Iterable[Finding]) -> int:
    total = passed = 0
    for item in findings:
        weight = WEIGHTS[item["risk"]]
        total += weight
        if item["ok"]:
            passed += weight
    return 100 if total == 0 else passed * 100 // total


def level(value: int) -> str:
    """red up to 59, yellow 60-84, green from 85."""
    if value >= 85:
        return "green"
    if value >= 60:
        return "yellow"
    return "red"

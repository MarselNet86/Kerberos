"""Findings as people read them: titles, threats and actions from copy.py."""

from __future__ import annotations

import string
from typing import Callable, Optional

from kerberos.checks import spec
from kerberos.copy import TEXT, t
from kerberos.fixes.model import TOPICS, Finding
from kerberos.ui.widgets import FindingItem

RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class _Values(dict):
    def __missing__(self, key: str) -> str:
        return ""


def evidence_value(key: str, value) -> str:
    if key == "ruShare" and isinstance(value, (int, float)):
        return f"{value * 100:.0f} %"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if value is None:
        return "—"
    return str(value)


def fill(key: str, evidence: dict) -> str:
    template = TEXT.get(key, "")
    values = _Values({k: evidence_value(k, v) for k, v in evidence.items()})
    return string.Formatter().vformat(template, (), values)


def details(evidence: dict) -> str:
    return "; ".join(f"{k}: {evidence_value(k, v)}" for k, v in evidence.items())


def action(finding: Finding) -> tuple[str, str]:
    """Label and style of what happens with the finding."""
    if finding["ok"]:
        return t("action.passed"), "ok"
    item = spec(finding["checkId"])
    how = TEXT.get(f"check.{finding['checkId']}.how", "")
    if item.kind == "fix" and finding["fixId"]:
        return t("action.fix"), "ok"
    if item.kind == "fix":
        return t("action.partial"), "risk.medium"
    if item.kind == "explain":
        return t("action.explain", how=how), "muted"
    if item.kind == "plan":
        return t("action.plan", how=how), "accent"
    return t("action.manual", how=how), "risk.medium"


def target_label(finding: Finding, node_names: dict) -> str:
    target = finding["target"]
    kind, _, ref = target.partition(":")
    if kind == "node":
        return node_names.get(ref, ref[:8])
    if kind == "host":
        return t("target.host", name=finding["evidence"].get("host", ref[:8]))
    if kind == "template":
        return t("target.template", name=finding["evidence"].get("template", ref[:8]))
    return t(f"target.{kind}") if f"target.{kind}" in TEXT else target


def ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (TOPICS.index(f["topic"]), RISK_ORDER[f["risk"]], f["checkId"]),
    )


def problems(findings: list[Finding]) -> list[Finding]:
    return ordered([f for f in findings if not f["ok"]])


def finding_items(
    findings: list[Finding], node_names: dict, mask: Optional[Callable[[str], str]] = None
) -> list[FindingItem]:
    mask = mask or (lambda value: value)
    items = []
    for item in problems(findings):
        label, style = action(item)
        items.append(
            FindingItem(
                risk=item["risk"],
                group=t(f"topic.{item['topic']}"),
                target=mask(target_label(item, node_names)),
                title=mask(fill(f"check.{item['checkId']}.title", item["evidence"])),
                threat=TEXT.get(f"check.{item['checkId']}.threat", ""),
                action=mask(label),
                action_style=style,
                details=mask(details(item["evidence"])),
                extra={"checkId": item["checkId"], "target": item["target"]},
            )
        )
    return items


def counts(findings: list[Finding]) -> dict:
    failing = [f for f in findings if not f["ok"] and f["risk"] != "info"]
    auto = [f for f in failing if spec(f["checkId"]).kind == "fix" and f["fixId"]]
    return {"problems": len(failing), "auto": len(auto), "manual": len(failing) - len(auto)}

"""Findings as people read them: titles, threats and actions from copy.py."""

from __future__ import annotations

import ipaddress
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
        # The fix does not apply here (no Caddy of §10.10 for panel.public, padding half set):
        # what to do by hand, in the words of that check (K19).
        manual = TEXT.get(f"check.{finding['checkId']}.manual") or how
        return t("action.manual", how=manual), "risk.medium"
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


def change_target(target: str, params: dict, node_names: dict) -> str:
    """Who a change belongs to: a node, a host, a template or the panel, by name."""
    kind, _, ref = target.partition(":")
    if kind != "node" and params.get("node"):
        kind, ref = "node", params["node"]
    if kind == "host":
        return t("target.host", name=params.get("remark") or ref[:8])
    if kind == "template":
        return t("target.template", name=params.get("name") or ref[:8])
    if kind == "node":
        return node_names.get(ref, ref[:8])
    return t("target.panel")


def ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (TOPICS.index(f["topic"]), RISK_ORDER[f["risk"]], f["checkId"]),
    )


def problems(findings: list[Finding]) -> list[Finding]:
    return ordered([f for f in findings if not f["ok"]])


# Checks of the fleet whose findings name the same nodes from every node's side:
# S6 shows one row a group, not one a node (K22). The findings and the score stay.
GROUPED = ("fleet.same_asn", "fleet.same_24", "fleet.shared_hostkey")


def node_name(finding: Finding, node_names: dict) -> str:
    kind, _, ref = finding["target"].partition(":")
    return node_names.get(ref, ref[:8]) if kind == "node" else ""


def _clusters(findings: list[Finding], node_names: dict) -> dict[str, str]:
    """fleet.same_24: nodes in one or neighbouring /24 nets, chained into clusters."""
    parent: dict[str, str] = {}

    def root(name: str) -> str:
        parent.setdefault(name, name)
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for item in findings:
        if item["checkId"] == "fleet.same_24":
            me = node_name(item, node_names)
            for other in item["evidence"].get("with", []):
                parent[root(other)] = root(me)
    return {name: root(name) for name in list(parent)}


def _group_key(item: Finding, node_names: dict, clusters: dict) -> Optional[tuple]:
    check, evidence = item["checkId"], item["evidence"]
    if check == "fleet.same_asn":
        return (check, evidence.get("asn"), evidence.get("country"))
    if check == "fleet.shared_hostkey":
        return (check, evidence.get("fingerprint"))
    if check == "fleet.same_24":
        name = node_name(item, node_names)
        return (check, clusters.get(name, name))
    return None


def rows(findings: list[Finding], node_names: Optional[dict] = None) -> list[list[Finding]]:
    """Problems as S6 shows them: a row each, a group of the fleet checks one row."""
    node_names = node_names or {}
    failing = problems(findings)
    clusters = _clusters(failing, node_names)
    result: list[list[Finding]] = []
    groups: dict[tuple, list[Finding]] = {}
    for item in failing:
        key = _group_key(item, node_names, clusters)
        if key is None:
            result.append([item])
        elif key in groups:
            groups[key].append(item)
        else:
            groups[key] = [item]
            result.append(groups[key])
    return result


def _net_order(net: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_network(net, strict=False).network_address))
    except ValueError:
        return (1, net)


def row_evidence(members: list[Finding]) -> dict:
    """The evidence of a row: the first finding's, widened to the whole group."""
    evidence = dict(members[0]["evidence"])
    if len(members) > 1:
        evidence.pop("with", None)  # the row names every node itself
        if members[0]["checkId"] == "fleet.same_24":
            nets = {m["evidence"].get("net", "") for m in members} - {""}
            evidence["net"] = ", ".join(sorted(nets, key=_net_order))
    return evidence


def todo(finding: Finding) -> tuple[str, str]:
    """The «Что делать» cell of S6 (K22): in full and in one word."""
    if finding["ok"]:
        return t("action.passed"), t("action.passed")
    item = spec(finding["checkId"])
    how = TEXT.get(f"check.{finding['checkId']}.how", "")
    if item.kind == "fix" and finding["fixId"]:
        return t("todo.fix"), t("todo.fix.short")
    if item.kind == "fix":
        how = TEXT.get(f"check.{finding['checkId']}.manual") or how
        kind = "manual"
    else:
        kind = item.kind if item.kind in ("explain", "plan") else "manual"
    return how[:1].upper() + how[1:], t(f"todo.{kind}.short")


def finding_items(
    findings: list[Finding], node_names: dict, mask: Optional[Callable[[str], str]] = None
) -> list[FindingItem]:
    mask = mask or (lambda value: value)
    items = []
    for members in rows(findings, node_names):
        item = members[0]
        evidence = row_evidence(members)
        if len(members) > 1:
            target = ", ".join(node_name(m, node_names) for m in members)
        else:
            target = target_label(item, node_names)
        label, style = action(item)
        full, short = todo(item)
        items.append(
            FindingItem(
                risk=item["risk"],
                group=t(f"topic.{item['topic']}"),
                target=mask(target),
                title=mask(fill(f"check.{item['checkId']}.title", evidence)),
                threat=TEXT.get(f"check.{item['checkId']}.threat", ""),
                action=mask(label),
                action_style=style,
                details=mask(details(evidence)),
                extra={
                    "checkId": item["checkId"],
                    "target": item["target"],
                    "targets": [m["target"] for m in members],
                },  # fmt: skip
                todo=mask(full),
                todo_short=short,
            )
        )
    return items


def auto_fixable(finding: Finding) -> bool:
    return not finding["ok"] and spec(finding["checkId"]).kind == "fix" and bool(finding["fixId"])


def counts(findings: list[Finding], node_names: Optional[dict] = None) -> dict:
    """Rows as S6 shows them (K22): a group of the fleet checks counts once."""
    failing = [r for r in rows(findings, node_names) if r[0]["risk"] != "info"]
    auto = [r for r in failing if auto_fixable(r[0])]
    high = [r for r in failing if r[0]["risk"] == "high"]
    return {"problems": len(failing), "high": len(high), "auto": len(auto),
            "manual": len(failing) - len(auto)}  # fmt: skip


def projected(findings: list[Finding]) -> int:
    """§12.2 score once every fix KERBEROS can make has passed: «≈», fixes may fail."""
    from kerberos.checks.score import score

    return score([dict(f, ok=True) if auto_fixable(f) else f for f in findings])

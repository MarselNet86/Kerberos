"""report.md (tech.md §12.3): what a person reads after the run."""

from __future__ import annotations

from typing import Callable, Optional

from kerberos.copy import TEXT, t
from kerberos.fixes.model import TOPICS, Run
from kerberos.report.view import action, details, fill, problems, target_label


def render(run: Run, mask: Optional[Callable[[str], str]] = None) -> str:
    mask = mask or (lambda value: value)
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    lines = [f"# {t('report.title.' + run['mode'])}", ""]
    lines.append(
        t(
            "report.head",
            time=run["startedAt"].replace("T", " ").replace("Z", " UTC"),
            mode=t(f"report.mode.{run['mode']}"),
            version=run["panel"].get("version", "?"),
            nodes=len(run["nodes"]),
        )
    )
    lines.append("")
    if run.get("scoreAfter") is not None:
        lines.append(
            "**"
            + t("report.score_before_after", before=run["scoreBefore"], after=run["scoreAfter"])
            + "**"  # fmt: skip
        )
    else:
        lines.append("**" + t("report.score", score=run["scoreBefore"]) + "**")
    findings = run["findings"]
    failing = problems(findings)
    for topic in TOPICS:
        part = [f for f in failing if f["topic"] == topic]
        passed = [f for f in findings if f["topic"] == topic and f["ok"]]
        if not part and not passed:
            continue
        lines += ["", f"## {t('topic.' + topic)}", ""]
        for item in part:
            title = fill(f"check.{item['checkId']}.title", item["evidence"])
            lines.append(f"- ● {t('risk.' + item['risk'])} · {target_label(item, names)} · {title}")
            threat = TEXT.get(f"check.{item['checkId']}.threat", "")
            if threat:
                lines.append("  - " + t("report.threat", text=threat))
            lines.append("  - " + action(item)[0])
            if item["evidence"]:
                lines.append("  - " + t("report.details", text=details(item["evidence"])))
        if passed:
            lines.append(("" if not part else "\n") + "✓ " + t("report.passed", n=len(passed)))
    lines += ["", f"## {t('report.nodes')}", "", t("report.nodes.head"), "|---|---|---|---|"]
    for node in run["nodes"]:
        access = t(f"access.status.{node.get('access', 'none')}")
        lines.append(
            f"| {node['name']} | {node['address']} | {node.get('sshPort', 22)} | {access} |"
        )
    return mask("\n".join(lines) + "\n")

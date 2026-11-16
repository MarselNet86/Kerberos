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
    if run.get("changes"):
        lines += ["", f"## {t('report.changes')}", ""]
        for change in run["changes"]:
            ports = ", ".join(change["params"].get("ports", []))
            lines.append(
                t(
                    "report.change",
                    state=t(f"state.{change['state']}"),
                    node=target_label(
                        {
                            "target": f"node:{change['params']['node']}"
                            if change["params"].get("node")
                            else change["target"],
                            "evidence": {},
                        },
                        names,
                    ),
                    fix=t(
                        f"fix.{change['fixId']}.label",
                        ports=ports,
                        port=change["params"].get("port", ""),
                        domain=change["params"].get("domain", ""),
                    ),
                )
            )
            if change.get("error"):
                reason = TEXT.get(f"error.{change['error']}", change["error"])
                lines.append(t("report.change_error", reason=reason))
            if change["fixId"] == "ssh.port" and change["state"] == "confirmed":
                node = next((n for n in run["nodes"]
                             if change["target"] == f"node:{n['uuid']}"), None)  # fmt: skip
                port = change["details"].get("newPort")
                command = f"ssh -p {port} root@{node['address'] if node else '?'}"
                lines.append("  - **" + t("report.ssh_port", port=port, command=command) + "**")
        lines += ["", t("report.backups")]
    lines += ["", f"## {t('report.nodes')}", "", t("report.nodes.head"), "|---|---|---|---|"]
    for node in run["nodes"]:
        access = t(f"access.status.{node.get('access', 'none')}")
        lines.append(
            f"| {node['name']} | {node['address']} | {node.get('sshPort', 22)} | {access} |"
        )
    if run["mode"] == "fix" and run.get("changes"):
        from kerberos.screens.fix import rollback_command

        lines += ["", f"## {t('report.rollback')}", "", "`" + rollback_command(run["runId"]) + "`"]
    return mask("\n".join(lines) + "\n")

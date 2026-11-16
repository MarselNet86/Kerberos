"""Contracts of run.json and report.json (tech.md §13)."""

from __future__ import annotations

from typing import Literal, Optional, TypedDict

Risk = Literal["high", "medium", "low", "info"]
Topic = Literal["hosting", "sni", "scanning", "dpi", "routing", "reserves"]
ChangeState = Literal[
    "planned", "applying", "applied", "pending_confirm", "confirmed", "failed", "rolled_back"
]

TOPICS: tuple[str, ...] = ("hosting", "sni", "scanning", "dpi", "routing", "reserves")
WEIGHTS = {"high": 10, "medium": 5, "low": 2, "info": 0}
# A change whose automatic rollback failed keeps the state it reached and gets this error;
# details.failure holds why it failed, details.rollbackError why it did not go back.
ROLLBACK_FAILED = "rollback_failed"


def is_applied(change: dict) -> bool:
    """The change worked: not one that failed and could not be rolled back."""
    return change["state"] in ("applied", "confirmed") and change.get("error") != ROLLBACK_FAILED


class Finding(TypedDict):
    checkId: str
    topic: Topic
    risk: Risk
    target: str  # 'node:<uuid>' | 'panel' | 'fleet' | 'template:<uuid>' | 'host:<uuid>'
    ok: bool
    evidence: dict  # short machine facts, no secrets
    fixId: Optional[str]  # None: manual or info


class Change(TypedDict):
    changeId: str
    fixId: str
    target: str
    state: ChangeState
    params: dict
    before: Optional[str]
    details: dict
    error: Optional[str]
    startedAt: str
    finishedAt: Optional[str]


class Run(TypedDict):
    runId: str
    mode: Literal["check", "fix", "rollback", "finalize"]
    kerberos: str
    panel: dict  # {version, nodes, hosts}
    nodes: list  # {uuid, name, address, sshPort, access: 'ok' | 'none' | 'denied'}
    findings: list
    changes: list
    scoreBefore: int
    scoreAfter: Optional[int]
    pending: list  # {changeId, action: 'finalize', due}
    startedAt: str
    finishedAt: Optional[str]

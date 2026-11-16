"""Run journal on the panel server (tech.md §5.4, §11.1, §13).

runs/<runId>/run.json is written before every state transition, so an
interrupted process leaves an honest record. report.md and report.json are
the report of §12; with masking on they are masked too. Files are 0600.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Optional

from kerberos import __version__
from kerberos.clock import Clock
from kerberos.fixes.model import Run
from kerberos.state import State


def iso(clock: Clock) -> str:
    return clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")


class RunStore:
    def __init__(self, state: State, clock: Clock) -> None:
        self.state = state
        self.clock = clock

    def new_id(self) -> str:
        return self.clock.now().strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)

    def path(self, run_id: str) -> Path:
        return self.state.runs / run_id

    def new_run(self, mode: str, panel: dict, nodes: list) -> Run:
        return {
            "runId": self.new_id(),
            "mode": mode,  # type: ignore[typeddict-item]
            "kerberos": __version__,
            "panel": panel,
            "nodes": nodes,
            "findings": [],
            "changes": [],
            "scoreBefore": 0,
            "scoreAfter": None,
            "pending": [],
            "startedAt": iso(self.clock),
            "finishedAt": None,
        }

    def save(self, run: Run) -> None:
        directory = self.path(run["runId"])
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.write_private(
            directory / "run.json", json.dumps(run, ensure_ascii=False, indent=2)
        )

    def log(self, run: Run, line: str) -> None:
        directory = self.path(run["runId"])
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / "kerberos.log"
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
        self.state.write_private(path, previous + f"{iso(self.clock)} {line}\n")

    def write_report(self, run: Run, markdown: str, masked: Optional[dict] = None) -> Path:
        directory = self.path(run["runId"])
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.write_private(directory / "report.md", markdown)
        body = masked if masked is not None else run
        self.state.write_private(
            directory / "report.json", json.dumps(body, ensure_ascii=False, indent=2)
        )
        return directory / "report.md"

    def runs(self) -> list[Run]:
        if not self.state.runs.is_dir():
            return []
        found = []
        for item in self.state.runs.iterdir():
            run = self.load(item.name)
            if run is not None:
                found.append((run.get("startedAt", ""), item.stat().st_mtime_ns, run))
        # Newest first; runs started in the same second go by their last write.
        return [run for *_key, run in sorted(found, key=lambda x: (x[0], x[1]), reverse=True)]

    def load(self, run_id: str) -> Optional[Run]:
        try:
            return json.loads((self.path(run_id) / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def report_text(self, run_id: str) -> Optional[str]:
        try:
            return (self.path(run_id) / "report.md").read_text(encoding="utf-8")
        except OSError:
            return None

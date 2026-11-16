"""Finalization of self-steal after 24 hours (tech.md §10.4 step 6, §7.3).

Old server names leave `serverNames`; clients that did not refresh their
subscription in a day stop connecting through this node. Run by hand
(`kerberos finalize`, reminded on S1) or by a systemd timer on the panel
server that uses a separate panel token kept 0600 until it is used.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from kerberos.clock import Clock
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.profile import finalize_profile
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError

TOKEN_FILE = "finalize.token"


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def due_items(store: RunStore, now: datetime, run_id: Optional[str] = None) -> list:
    found = []
    for run in store.runs():
        if run_id is not None and run["runId"] != run_id:
            continue
        for item in run.get("pending", []):
            if item.get("action") == "finalize" and parse_time(item["due"]) <= now:
                found.append((run, item))
    return found


def finalize_items(client: PanelClient, store: RunStore, pairs: list) -> list:
    """Remove old names; returns the items that failed. Running twice changes nothing."""
    failed = []
    for run, item in pairs:
        try:
            profile = next((p for p in client.profiles() if p.uuid == item["profileUuid"]), None)
            if profile is None:
                raise PanelError("bad_response", detail="profile is gone")
            config = finalize_profile(profile.config, item["domain"])
            if config != profile.config:
                client.patch_profile(profile.uuid, config)
        except PanelError as exc:
            item["error"] = exc.code
            failed.append(item)
            store.save(run)
            continue
        run["pending"] = [p for p in run["pending"] if p is not item]
        run.setdefault("finalized", []).append({**item, "at": iso(store.clock)})
        store.save(run)
    return failed


def schedule(app: Any, client: PanelClient, run: dict, launcher: str) -> bool:
    """«Сделать автоматически»: a 2-day panel token and a systemd timer for the run."""
    store = RunStore(app.env.state, app.env.clock)
    try:
        token_uuid, token = client.create_token("kerberos-finalize", 2)
    except PanelError:
        return False
    path = store.path(run["runId"]) / TOKEN_FILE
    api = run["panel"].get("api", "")
    store.state.write_private(path, json.dumps({"uuid": token_uuid, "token": token, "api": api}))
    unit = f"kerberos-finalize-{run['runId']}"
    result = app.env.host.run(["systemd-run", "--on-active=24h", "--unit", unit, launcher,
                               "finalize", run["runId"]])  # fmt: skip
    run["finalizeTimer"] = unit if result.ok else None
    store.save(run)
    return result.ok


def unattended(store: RunStore, transport: Any, clock: Clock, run_id: Optional[str]) -> int:
    """`kerberos finalize` without a terminal: the timer's call with the saved token."""
    pairs = due_items(store, clock.now(), run_id)
    if not pairs:
        return 0
    code = 0
    for run in {id(r): r for r, _i in pairs}.values():
        path = store.path(run["runId"]) / TOKEN_FILE
        try:
            saved = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            code = 3
            continue
        client = PanelClient(saved["api"], transport, clock)
        client.set_token(saved["token"])
        if finalize_items(client, store, [(r, i) for r, i in pairs if r is run]):
            code = 3
            continue
        try:
            client.delete_token(saved["uuid"])
        except PanelError:
            pass
        path.unlink(missing_ok=True)
    return code

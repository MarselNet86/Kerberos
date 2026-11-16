"""Changes in the panel and their rollback (tech.md §10.4, §10.5, §11.4).

Before KERBEROS changes a panel object it saves the object to
runs/<runId>/panel/. Rollback puts the object back; if the object in the
panel differs from what KERBEROS wrote (someone edited it by hand), rollback
shows the difference and asks first.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Optional

from kerberos.fixes.journal import RunStore
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError

PANEL_FIXES = {"self_steal.profile", "self_steal.squads", "self_steal.hosts"}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def save_snapshot(store: RunStore, run_id: str, name: str, value: Any) -> str:
    path = store.path(run_id) / "panel" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    store.state.write_private(path, json.dumps(value, ensure_ascii=False, indent=2))
    return str(path)


def load_snapshot(path: Optional[str]) -> Any:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def diff_text(written: Any, current: Any) -> str:
    a = json.dumps(written, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    return "\n".join(difflib.unified_diff(a, b, "KERBEROS", "panel", lineterm="", n=2))


def undo(client: PanelClient, change: dict,
         ask: Optional[Callable[[str], bool]] = None) -> Optional[str]:  # fmt: skip
    """Roll one panel change back. None: done; otherwise the reason it was not."""
    fix_id, details = change["fixId"], change["details"]
    try:
        if fix_id == "self_steal.hosts":
            if details.get("disabled"):
                client.enable_hosts(details["disabled"])
            existing = {h.uuid for h in client.hosts()}
            for uuid in details.get("created", []):
                if uuid in existing:
                    client.delete_host(uuid)
            return None
        if fix_id == "self_steal.squads":
            for uuid, inbounds in (details.get("squads") or {}).items():
                client.patch_squad(uuid, inbounds)
            return None
        if fix_id == "self_steal.profile":
            before = load_snapshot(change.get("before"))
            if before is None:
                return "no_snapshot"
            uuid = details["profileUuid"]
            current = next((p for p in client.profiles() if p.uuid == uuid), None)
            if current is None:
                return "gone"
            if digest(current.config) != details.get("written") and details.get("written"):
                # The written config lives in a 0600 snapshot, never in run.json:
                # it holds the Reality private key.
                written = load_snapshot(details.get("writtenPath"))
                if ask is None or not ask(diff_text(written, current.config)):
                    return "changed_in_panel"
            client.patch_profile(uuid, before["config"])
            return None
    except PanelError as exc:
        return exc.code
    return "unknown_change"

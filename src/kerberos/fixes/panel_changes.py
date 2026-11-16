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

PANEL_FIXES = {
    "self_steal.profile",
    "self_steal.squads",
    "self_steal.hosts",
    "sub.templates",
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "reserve",
    "xhttp.padding",
    "xhttp.uplink_get",
    "xui.reality",
}


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
        if fix_id == "sub.templates":
            # Templates KERBEROS created stay (the API has no delete); edited ones go back.
            for uuid, info in (details.get("templates") or {}).items():
                previous = load_snapshot(info.get("previousPath"))
                if previous is not None and info.get("written"):
                    client.patch_template(uuid, previous)
            return None
        if fix_id == "sub.template":
            for uuid, template in (details.get("hosts") or {}).items():
                client.patch_host(uuid, {"xrayJsonTemplateUuid": template})
            return None
        if fix_id == "sub.ping_type":
            if "previous" not in details:
                return None  # failed before anything was written
            current = client.sub_settings()
            headers = dict(current.headers)
            previous = details.get("previous") or {}
            if "ping-type" in previous:
                headers["ping-type"] = previous["ping-type"]
            else:
                headers.pop("ping-type", None)
            client.patch_sub_settings(current.uuid, headers)
            return None
        if fix_id == "host.fingerprint":
            if "previous" not in details:
                return None
            client.patch_host(
                change["params"]["host"], {"fingerprint": details.get("previous", "")}
            )
            return None
        if fix_id == "reserve":
            for uuid, before in (details.get("hosts") or {}).items():
                client.patch_host(uuid, before)
            return None
        if fix_id == "self_steal.squads":
            for uuid, inbounds in (details.get("squads") or {}).items():
                client.patch_squad(uuid, inbounds)
            return None
        if fix_id == "xui.reality":
            return undo_xui_reality(client, change, ask)
        if fix_id == "xhttp.uplink_get":
            return undo_uplink(client, change)
        if fix_id == "xhttp.padding":
            return undo_padding(client, change, ask)
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


def undo_uplink(client: PanelClient, change: dict) -> Optional[str]:
    """Only uplinkHTTPMethod goes back; the rest of the host's extra stays as it is now."""
    from kerberos.fixes import xhttp

    details = change["details"]
    if "previous" not in details:
        return None
    uuid = change["params"]["host"]
    host = next((h for h in client.hosts() if h.uuid == uuid), None)
    if host is None:
        return "gone"
    if str((host.xhttp_extra or {}).get("uplinkHTTPMethod", "")).upper() != "GET":
        return None  # changed back meanwhile: nothing of KERBEROS is left
    extra = xhttp.uplink_back(host.xhttp_extra, details["previous"], details.get("extraWasNone"))
    client.patch_host(uuid, {"xhttpExtraParams": extra})
    return None


def undo_padding(client: PanelClient, change: dict,
                 ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """Only the padding keys KERBEROS wrote go, from the inbound and from its hosts."""
    from kerberos.fixes import xhttp

    details = change["details"]
    if not details.get("inbounds") or not details.get("writtenPath"):
        return None
    written = load_snapshot(details["writtenPath"])
    if written is None:
        return "no_snapshot"
    profile = next((p for p in client.profiles() if p.uuid == details["profileUuid"]), None)
    if profile is None:
        return "gone"
    config, changed = xhttp.remove_padding(profile.config, written)
    hosts = {h.uuid: h for h in client.hosts()}
    for uuid, tag in (details.get("hosts") or {}).items():
        host = hosts.get(uuid)
        current = xhttp.padding_of(host.xhttp_extra) if host else {}
        if current and current != written.get(tag) and tag not in changed:
            changed.append(tag)
    if changed:
        mine = {tag: written[tag] for tag in changed}
        now = {tag: xhttp.padding_of(((profile.inbound_config(tag) or {}).get("streamSettings")
                                      or {}).get("xhttpSettings", {}).get("extra"))
               for tag in changed}  # fmt: skip
        if ask is None or not ask(diff_text(mine, now)):
            return "changed_in_panel"
    if config != profile.config:
        client.patch_profile(profile.uuid, config)
    for uuid in details.get("hosts") or {}:
        host = hosts.get(uuid)
        if host is not None and xhttp.padding_of(host.xhttp_extra):
            rest = xhttp.without_padding(host.xhttp_extra)
            client.patch_host(uuid, {"xhttpExtraParams": rest or None})
    return None


def undo_xui_reality(client: Any, change: dict,
                     ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """3x-ui (§7.6): Reality of the inbounds back from the snapshot; asks when edited since."""
    before = load_snapshot(change.get("before"))
    if before is None:
        return "no_snapshot"
    written = load_snapshot(change["details"].get("writtenPath")) or {}
    edited = {}
    for ident, stream in before.items():
        current = client.inbound(int(ident))["streamSettings"]
        mine = written.get(ident)
        if mine is not None and current not in (mine, stream):
            edited[ident] = (mine, current)
    if edited:
        mine = {k: v[0].get("realitySettings") for k, v in edited.items()}
        now = {k: v[1].get("realitySettings") for k, v in edited.items()}
        if ask is None or not ask(diff_text(mine, now)):
            return "changed_in_panel"
    for ident, stream in before.items():
        client.update_inbound(int(ident), stream)
    return None

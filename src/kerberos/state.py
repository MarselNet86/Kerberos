"""State of KERBEROS on the panel server (tech.md §5.4).

/var/lib/kerberos (0700, root): KERBEROS and admin keys, pinned host keys,
nodes.json, runs and the lock. Tests and --demo use a temporary directory.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from kerberos.nodes.keys import known_hosts_name

DEFAULT_ROOT = Path("/var/lib/kerberos")


class Locked(Exception):
    """Another KERBEROS run holds the lock."""


@dataclass
class NodeRecord:
    uuid: str
    name: str
    address: str
    ssh_port: int = 22
    fingerprint: str = ""
    agent: str = ""
    panel_ip: str = ""
    access: str = "none"  # ok | none | denied
    extra: dict = field(default_factory=dict)


_CAMEL = {"ssh_port": "sshPort", "panel_ip": "panelIp"}
_SNAKE = {v: k for k, v in _CAMEL.items()}


class State:
    def __init__(self, root: Path = DEFAULT_ROOT) -> None:
        self.root = Path(root)

    # -- layout ------------------------------------------------------------
    @property
    def key(self) -> Path:
        return self.root / "id_ed25519"

    @property
    def admin_key(self) -> Path:
        return self.root / "admin_ed25519"

    @property
    def known_hosts(self) -> Path:
        return self.root / "known_hosts"

    @property
    def nodes_file(self) -> Path:
        return self.root / "nodes.json"

    @property
    def runs(self) -> Path:
        return self.root / "runs"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    @contextmanager
    def lock(self) -> Iterator[None]:
        """One KERBEROS at a time (flock on /var/lib/kerberos/lock)."""
        import fcntl

        self.ensure()
        fd = os.open(self.root / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise Locked() from exc
            yield
        finally:
            os.close(fd)

    # -- files ---------------------------------------------------------------
    def write_private(self, path: Path, text: str) -> None:
        """Write a file only root may read (keys, reports, run files)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def public_key(self, admin: bool = False) -> Optional[str]:
        path = (self.admin_key if admin else self.key).with_suffix(".pub")
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    # -- nodes.json ------------------------------------------------------
    def nodes(self) -> dict[str, NodeRecord]:
        try:
            raw = json.loads(self.nodes_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        records = {}
        for uuid, item in raw.items() if isinstance(raw, dict) else ():
            if not isinstance(item, dict):
                continue
            fields = {_SNAKE.get(k, k): v for k, v in item.items()}
            fields = {k: v for k, v in fields.items() if k in NodeRecord.__dataclass_fields__}
            fields.pop("uuid", None)
            try:
                records[uuid] = NodeRecord(uuid=uuid, **fields)
            except TypeError:
                continue
        return records

    def node(self, uuid: str) -> Optional[NodeRecord]:
        return self.nodes().get(uuid)

    def save_node(self, record: NodeRecord) -> None:
        records = self.nodes()
        records[record.uuid] = record
        data = {
            uuid: {_CAMEL.get(k, k): v for k, v in asdict(r).items() if k != "uuid"}
            for uuid, r in sorted(records.items())
        }
        self.ensure()
        self.write_private(self.nodes_file, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    def find_node(self, name_or_uuid: str) -> Optional[NodeRecord]:
        records = self.nodes()
        if name_or_uuid in records:
            return records[name_or_uuid]
        matches = [r for r in records.values() if r.name == name_or_uuid]
        return matches[0] if len(matches) == 1 else None

    # -- known_hosts -----------------------------------------------------
    def pin(self, address: str, port: int, key_type: str, blob: str) -> None:
        """Pin the host key; an older key for the same name is replaced."""
        name = known_hosts_name(address, port)
        lines = []
        try:
            lines = self.known_hosts.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
        kept = [line for line in lines if line.split(" ", 1)[0] != name]
        kept.append(f"{name} {key_type} {blob}")
        self.ensure()
        self.write_private(self.known_hosts, "\n".join(kept) + "\n")

    def pinned(self, address: str, port: int) -> Optional[str]:
        name = known_hosts_name(address, port)
        try:
            for line in self.known_hosts.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == name:
                    return parts[2]
        except OSError:
            return None
        return None

"""SSH keys as data: fingerprints, authorized_keys lines (pure functions)."""

from __future__ import annotations

import base64
import binascii
import hashlib
import shlex
from dataclasses import dataclass
from typing import Optional

KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
AGENT_PATH = "/usr/local/sbin/kerberos-agent"


@dataclass
class PublicKey:
    type: str
    blob: str
    comment: str = ""
    options: str = ""

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.blob)

    @property
    def line(self) -> str:
        parts = [self.options] if self.options else []
        parts += [self.type, self.blob]
        if self.comment:
            parts.append(self.comment)
        return " ".join(parts)

    @property
    def is_kerberos(self) -> bool:
        return f'command="{AGENT_PATH}"' in self.options


def fingerprint(blob: str) -> str:
    """The SHA256 fingerprint as `ssh-keygen -l` prints it."""
    raw = base64.b64decode(blob)
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def _valid_blob(key_type: str, blob: str) -> bool:
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(raw) < 4:
        return False
    size = int.from_bytes(raw[:4], "big")
    return raw[4 : 4 + size].decode("ascii", "replace") == key_type


def parse_key(line: str) -> Optional[PublicKey]:
    """One public key line, with or without authorized_keys options."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        words = shlex.split(line, posix=False)
    except ValueError:
        return None
    for i, word in enumerate(words):
        if word in KEY_TYPES and i + 1 < len(words):
            blob = words[i + 1]
            if not _valid_blob(word, blob):
                return None
            options = " ".join(words[:i])
            comment = " ".join(words[i + 2 :])
            return PublicKey(word, blob, comment, options)
    return None


def parse_authorized_keys(text: str) -> list[PublicKey]:
    keys = []
    for line in text.splitlines():
        key = parse_key(line)
        if key is not None:
            keys.append(key)
    return keys


def kerberos_line(panel_ip: str, public_key: str) -> str:
    """The restricted line of §8.2: only from the panel, only the agent."""
    return f'from="{panel_ip}",command="{AGENT_PATH}",restrict {public_key.strip()}'


def scan_key(scan_output: str) -> Optional[PublicKey]:
    """The ed25519 key from `ssh-keyscan -t ed25519` output."""
    for line in scan_output.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "ssh-ed25519" and _valid_blob(parts[1], parts[2]):
            return PublicKey(parts[1], parts[2])
    return None


def known_hosts_name(address: str, port: int) -> str:
    return address if port == 22 else f"[{address}]:{port}"


def demo_blob(seed: str, key_type: str = "ssh-ed25519") -> str:
    """A well-formed but fake public key blob (demo fleet, tests)."""
    name = key_type.encode()
    material = hashlib.sha256(seed.encode()).digest()
    raw = len(name).to_bytes(4, "big") + name + len(material).to_bytes(4, "big") + material
    return base64.b64encode(raw).decode()

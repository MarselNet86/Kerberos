"""Bootstrap of node access (tech.md §8.2).

One root session on the node (opened with the panel server's root keys or
with the password typed into ssh) runs a small Python script: it writes the
agent and checks its sha256, learns from SSH_CONNECTION which address the
node sees the panel server from, and adds the restricted KERBEROS key line
to /root/.ssh/authorized_keys unless it is already there. Running it again
changes nothing; a KERBEROS line with an old panel address is replaced.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Optional

from kerberos.nodes.keys import AGENT_PATH

REMOTE_COMMAND = "command -v python3 >/dev/null 2>&1 || exit 42; exec python3 -"
NO_PYTHON = 42
INSTALL_PYTHON = (
    "DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-minimal >/dev/null 2>&1 "
    "|| { apt-get update -q >/dev/null 2>&1 && "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3-minimal >/dev/null 2>&1; }"
)
PAYLOAD_RE = re.compile(r'^PAYLOAD = "([A-Za-z0-9+/=]+)"$', re.M)

BODY = r"""
import base64, hashlib, json, os, sys

P = json.loads(base64.b64decode(PAYLOAD).decode())
# Tests run this script against a temporary root; on a node the root is "/".
R = os.environ.get("KERBEROS_TEST_ROOT", "")
AK_DIR = R + "/root/.ssh"
AK = AK_DIR + "/authorized_keys"


def out(value, code=0):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def read_lines():
    try:
        with open(AK, encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def write_lines(lines):
    os.makedirs(AK_DIR, mode=0o700, exist_ok=True)
    tmp = AK + ".kerberos-tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(tmp, 0o600)
    os.replace(tmp, AK)


blob = P["publicKey"].split()[1]
if P["mode"] == "remove":
    lines = read_lines()
    kept = [line for line in lines if blob not in line]
    if kept != lines:
        write_lines(kept)
    out({"removed": len(lines) - len(kept)})

data = base64.b64decode(P["agent"])
if hashlib.sha256(data).hexdigest() != P["sha256"]:
    out({"error": "sha_mismatch"}, 1)
os.makedirs(R + "/var/lib/kerberos", mode=0o700, exist_ok=True)
os.chmod(R + "/var/lib/kerberos", 0o700)
path = R + P["agentPath"]
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".kerberos-tmp"
with open(tmp, "wb") as fh:
    fh.write(data)
os.chmod(tmp, 0o755)
os.replace(tmp, path)
with open(path, "rb") as fh:
    if hashlib.sha256(fh.read()).hexdigest() != P["sha256"]:
        out({"error": "sha_mismatch"}, 1)
conn = os.environ.get("SSH_CONNECTION", "").split()
if not conn:
    out({"error": "no_ssh_connection"}, 1)
panel_ip = conn[0]
line = 'from="%s",command="%s",restrict %s' % (panel_ip, P["agentPath"], P["publicKey"].strip())
lines = read_lines()
added = False
if line not in lines:
    lines = [item for item in lines if blob not in item] + [line]
    write_lines(lines)
    added = True
out({"panelIp": panel_ip, "python": sys.version.split()[0], "keyAdded": added})
"""


def agent_source() -> bytes:
    return (Path(__file__).resolve().parent.parent / "agent.py").read_bytes()


def agent_sha256(data: Optional[bytes] = None) -> str:
    return hashlib.sha256(agent_source() if data is None else data).hexdigest()


def script(payload: dict) -> str:
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return f'PAYLOAD = "{encoded}"\n{BODY}'


def install_script(public_key: str, agent: Optional[bytes] = None) -> str:
    data = agent_source() if agent is None else agent
    return script(
        {
            "mode": "install",
            "agent": base64.b64encode(data).decode(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "publicKey": public_key,
            "agentPath": AGENT_PATH,
        }
    )


# 3x-ui (§7.6): KERBEROS sets itself up on its own server, without ssh: the
# key line then admits only connections from this server to itself.
LOCAL_CONNECTION = "127.0.0.1 0 127.0.0.1 22"


def local_install_script(public_key: str, agent: Optional[bytes] = None) -> str:
    prefix = f'import os\nos.environ["SSH_CONNECTION"] = "{LOCAL_CONNECTION}"\n'
    return prefix + install_script(public_key, agent)


def remove_script(public_key: str) -> str:
    return script({"mode": "remove", "publicKey": public_key, "agentPath": AGENT_PATH})


def read_payload(source: str) -> Optional[dict]:
    """The payload of a bootstrap script (the fake transport reads it)."""
    match = PAYLOAD_RE.search(source)
    if not match:
        return None
    return json.loads(base64.b64decode(match.group(1)).decode())


def parse_result(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return {"error": "no_answer"}

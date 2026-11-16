"""A recorded node: files under tests/fixtures/agent/<name>/root, command outputs under cmd/."""

from __future__ import annotations

import time
from pathlib import Path

from agent_helpers import Recorder

from kerberos import agent

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "agent"
NOW = time.mktime(time.strptime("2026/11/16 12:00:00", "%Y/%m/%d %H:%M:%S"))

COMMANDS = {
    ("ip", "-j", "addr", "show"): "ip-addr.json",
    ("sshd", "-T"): "sshd-T.txt",
    ("systemctl", "is-active", "ssh.socket"): "ssh-socket-active.txt",
    ("systemctl", "show", "ssh.socket", "-p", "Listen"): "ssh-socket-listen.txt",
    ("nft", "-j", "list", "ruleset"): "nft.json",
    ("ufw", "status", "verbose"): "ufw.txt",
    ("docker", "ps"): "docker-ps.txt",
    ("docker", "inspect", "remnanode"): "docker-inspect.json",
    ("docker", "exec", "remnanode", "xray", "version"): "xray-version.txt",
    ("ss", "-Hlntup"): "ss-listen.txt",
    ("ss", "-Htn", "state", "established"): "ss-node-api.txt",
    ("ss", "-Htin", "state", "established"): "ss-443.txt",
    ("systemctl", "is-active", "fail2ban"): "f2b-active.txt",
}


def recorded(name: str) -> tuple[agent.System, Recorder]:
    base = FIXTURES / name
    recorder = Recorder()
    for prefix, file in COMMANDS.items():
        text = (base / "cmd" / file).read_text(encoding="utf-8")
        code = 3 if prefix[:2] == ("systemctl", "is-active") and text.strip() != "active" else 0
        recorder.on(prefix, agent.Result(code, text))
    system = agent.System(
        root=str(base / "root"),
        run=recorder,
        environ={"SSH_CONNECTION": "198.51.100.5 41022 203.0.113.10 22"},
        now=lambda: NOW,
    )
    return system, recorder

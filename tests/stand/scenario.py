#!/usr/bin/env python3
"""Stand scenario (tech.md §17, §18): apply, roll back, apply again, on a real node.

Runs as root on a disposable stand VM only (tools/stand.sh copies it there).
It installs the agent from this checkout and drives it the way KERBEROS does,
then checks the effect through the agent's own facts. Never run it on a
production server: it changes SSH, nftables and fail2ban.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "..", "src", "kerberos", "agent.py")
AGENT = "/usr/local/sbin/kerberos-agent"
PANEL = "198.51.100.5"  # documentation address standing in for the panel server
results: list = []


def agent(*args: str, payload: dict | None = None) -> tuple[int, dict]:
    env = dict(os.environ, SSH_CONNECTION=f"{PANEL} 50000 127.0.0.1 22")
    proc = subprocess.run(
        [sys.executable, AGENT, *args],
        input=json.dumps(payload or {}).encode(),
        capture_output=True,
        env=env,
        check=False,
    )
    lines = proc.stdout.decode().strip().splitlines()
    return proc.returncode, json.loads(lines[-1]) if lines else {}


def facts() -> dict:
    return agent("facts")[1]


def report(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(f"{'ok  ' if ok else 'FAIL'}  {name}" + (f": {detail}" if detail and not ok else ""))


def cycle(fix_id: str, params: dict, applied, restored, confirm: bool = False) -> None:
    """Apply, check, roll back, check, apply again, roll back."""
    for round_no in (1, 2):
        change = str(uuid.uuid4())
        code, answer = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} apply #{round_no}", code == 0, json.dumps(answer))
        if code != 0:
            return
        if confirm:
            code, answer = agent("confirm", change)
            report(f"{fix_id} confirm #{round_no}", answer.get("state") == "confirmed")
        report(f"{fix_id} effect #{round_no}", applied(facts()))
        code, again = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} same changeId is noop", again.get("state") == "noop")
        code, answer = agent("rollback", change)
        report(f"{fix_id} rollback #{round_no}", answer.get("state") == "rolled_back",
               json.dumps(answer))  # fmt: skip
        report(f"{fix_id} restored #{round_no}", restored(facts()))


def listen(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    return server


def main() -> int:
    if os.geteuid() != 0:
        print("run as root on a stand VM")
        return 2
    shutil.copyfile(SOURCE, AGENT)
    os.chmod(AGENT, 0o755)
    before = facts()
    print(f"{before['os']['id']} {before['os']['version']}, OpenSSH ports {before['ssh']['ports']}")

    if before["mptcp"]["enabled"] or os.path.exists("/proc/sys/net/mptcp/enabled"):
        cycle("mptcp.guard", {},
              lambda f: not f["mptcp"]["enabled"] and f["mptcp"]["ipOptionsDrop"],
              lambda f: f["mptcp"]["enabled"] == before["mptcp"]["enabled"]
              and "inet kerberos_mptcp" not in f["nftTables"])  # fmt: skip

    cycle("fail2ban.sshd", {"sshPorts": before["ssh"]["ports"], "panelIp": PANEL},
          lambda f: f["fail2ban"]["sshdJail"],
          lambda f: f["fail2ban"]["sshdJail"] == before["fail2ban"]["sshdJail"])  # fmt: skip

    server = listen(8099)
    try:

        def firewalled(f: dict) -> bool:
            return any(s["port"] == 8099 and s["firewalled"] for s in f["listening"])

        cycle("ports.drop", {"ports": ["8099/tcp"]}, firewalled, lambda f: not firewalled(f))
    finally:
        server.close()

    if before["nodeApi"]["port"] and before["remnanode"].get("network") == "host":
        cycle("node_api.panel_only", {"port": before["nodeApi"]["port"], "panelIp": PANEL},
              lambda f: f["nodeApi"]["panelOnly"],
              lambda f: f["nodeApi"]["panelOnly"] == before["nodeApi"]["panelOnly"])  # fmt: skip

    old = {k["fingerprint"] for k in before["hostKeys"]}
    cycle("hostkeys.regenerate", {},
          lambda f: not ({k["fingerprint"] for k in f["hostKeys"]} & old),
          lambda f: {k["fingerprint"] for k in f["hostKeys"]} == old, confirm=True)  # fmt: skip

    if before["ssh"]["adminKeys"]:
        cycle("ssh.key_only", {},
              lambda f: not f["ssh"]["passwordAuthentication"],
              lambda f: f["ssh"]["passwordAuthentication"]
              == before["ssh"]["passwordAuthentication"], confirm=True)  # fmt: skip
        # The confirmation never comes: the undo timer must exist and roll back.
        change = str(uuid.uuid4())
        agent("apply", "ssh.key_only", change)
        timers = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"],
                                capture_output=True, text=True).stdout  # fmt: skip
        report("undo timer is armed", f"kerberos-undo-{change}" in timers)
        subprocess.run(["systemctl", "start", f"kerberos-undo-{change}.service"], check=False)
        code, answer = agent("confirm", change)
        report("timer rolled the change back", answer.get("error", {}).get("code")
               == "change_conflict")  # fmt: skip
        report("password login is back as it was", facts()["ssh"]["passwordAuthentication"]
               == before["ssh"]["passwordAuthentication"])  # fmt: skip
    else:
        code, answer = agent("apply", "ssh.key_only", str(uuid.uuid4()))
        report("ssh.key_only refuses without an admin key",
               answer.get("error", {}).get("code") == "no_admin_key")  # fmt: skip

    failed = results.count(False)
    print(f"\n{len(results) - failed} ok, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

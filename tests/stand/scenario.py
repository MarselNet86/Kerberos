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


def cycle(fix_id: str, params: dict, applied, restored, confirm: bool = False,
          describe=None) -> None:  # fmt: skip
    """Apply, check, roll back, check, apply again, roll back.

    `describe` turns facts into the detail printed when a check fails.
    """
    for round_no in (1, 2):
        change = str(uuid.uuid4())
        code, answer = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} apply #{round_no}", code == 0, json.dumps(answer))
        if code != 0:
            return
        if confirm:
            code, answer = agent("confirm", change)
            report(f"{fix_id} confirm #{round_no}", answer.get("state") == "confirmed")
        now = facts()
        report(f"{fix_id} effect #{round_no}", applied(now), describe(now) if describe else "")
        code, again = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} same changeId is noop", again.get("state") == "noop")
        code, answer = agent("rollback", change)
        report(f"{fix_id} rollback #{round_no}", answer.get("state") == "rolled_back",
               json.dumps(answer))  # fmt: skip
        now = facts()
        report(f"{fix_id} restored #{round_no}", restored(now), describe(now) if describe else "")


def listen(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    return server


WATCH_LOG = "/var/log/kerberos-watch.log"
STAND_KEY = "/tmp/kerberos-stand-key"
EDGE_SITE = "/etc/nginx/sites-enabled/kerberos-stand-cdn"
EDGE_CONF = "/etc/nginx/conf.d/kerberos-edges.conf"
EDGE_TEXT = """server {
    listen 127.0.0.1:8098;
    location /stand-tunnel {
        return 200;
    }
    location = /cdn-check {
        return 204;
    }
}
"""


def edge_filter() -> None:
    """cdn.edge_only on a plain nginx site of the stand: nginx must take the filter."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if shutil.which("nginx") is None:
        subprocess.run(["apt-get", "install", "-y", "-qq", "nginx"], env=env, check=False,
                       capture_output=True)  # fmt: skip
    if shutil.which("nginx") is None:
        report("cdn.edge_only: nginx installed", False)
        return
    with open(EDGE_SITE, "w") as fh:
        fh.write(EDGE_TEXT)
    subprocess.run(["systemctl", "reload-or-restart", "nginx"], check=False)

    def guarded(_facts: dict) -> bool:
        return os.path.exists(EDGE_CONF) and "@kerberos_not_edge" in open(EDGE_SITE).read()

    def clean(_facts: dict) -> bool:
        return not os.path.exists(EDGE_CONF) and open(EDGE_SITE).read() == EDGE_TEXT

    try:
        cycle("cdn.edge_only", {"paths": ["/stand-tunnel"], "nets": ["192.0.2.0/24"]},
              guarded, clean)  # fmt: skip
    finally:
        os.remove(EDGE_SITE)
        subprocess.run(["systemctl", "reload", "nginx"], check=False)


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

    # K8: the watch, and the CDN filter on a stand site of its own.
    cycle("watch.install", {},
          lambda f: f["watch"]["installed"],
          lambda f: f["watch"]["installed"] == before["watch"]["installed"])  # fmt: skip
    change = str(uuid.uuid4())
    agent("apply", "watch.install", change)
    watch = subprocess.run(["/usr/local/sbin/kerberos-watch"], capture_output=True, check=False)
    lines = (open(WATCH_LOG).read().splitlines() if os.path.exists(WATCH_LOG) else []) or [""]
    report("watch writes one line of counts", watch.returncode == 0 and " conn=" in lines[-1],
           watch.stderr.decode()[-300:])  # fmt: skip
    agent("rollback", change)
    edge_filter()

    if before["nodeApi"]["port"] and before["remnanode"].get("network") == "host":
        cycle("node_api.panel_only", {"port": before["nodeApi"]["port"], "panelIp": PANEL},
              lambda f: f["nodeApi"]["panelOnly"],
              lambda f: f["nodeApi"]["panelOnly"] == before["nodeApi"]["panelOnly"])  # fmt: skip

    # Self-steal needs a real domain of the stand with its A record on this VM (§22).
    domain_file = os.path.join(HERE, "..", "..", "domain")
    domain = open(domain_file).read().strip() if os.path.exists(domain_file) else ""
    if domain:

        def has_site(f: dict) -> bool:
            return any(domain in s["serverNames"] for s in f["nginx"]["sites"])

        cycle("self_steal.site", {"domain": domain, "siteSeed": 1},
              lambda f: has_site(f) and any(c["domain"] == domain for c in f["certbot"]["certs"]),
              lambda f: not has_site(f))  # fmt: skip
    else:
        print("skip  self_steal.site: no stand domain for this VM")
    if os.path.exists("/opt/remnanode/docker-compose.yml"):
        cycle("node.letsencrypt_mount", {},
              lambda f: f["remnanode"]["letsencryptMounted"],
              lambda f: f["remnanode"]["letsencryptMounted"]
              == before["remnanode"]["letsencryptMounted"])  # fmt: skip

    # §8.5: the person's own key reaches the node: a throwaway key of this stand VM.
    for leftover in (STAND_KEY, STAND_KEY + ".pub"):  # a run before left its key
        if os.path.exists(leftover):
            os.remove(leftover)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "stand@kerberos",
                    "-f", STAND_KEY], check=True)  # fmt: skip
    key = open(STAND_KEY + ".pub").read().strip()
    cycle("access.admin_keys", {"keys": [key]},
          lambda f: f["ssh"]["adminKeys"] == before["ssh"]["adminKeys"] + 1,
          lambda f: f["ssh"]["adminKeys"] == before["ssh"]["adminKeys"])  # fmt: skip

    # Taken right before the cycle: the keys of a fresh cloud VM may change at first boot.
    old = {k["fingerprint"] for k in facts()["hostKeys"]}

    def renewed(f: dict) -> set:
        """A DSA key of the image stays as it is (tech.md §10.3); every other key is new."""
        return {k["fingerprint"] for k in f["hostKeys"] if k["type"] not in ("ssh-dss", "DSA")}

    cycle("hostkeys.regenerate", {},
          lambda f: bool(renewed(f)) and not (renewed(f) & old),
          lambda f: {k["fingerprint"] for k in f["hostKeys"]} == old, confirm=True,
          describe=lambda f: json.dumps(sorted(k["fingerprint"][-8:] for k in f["hostKeys"])
                                        + ["was"] + sorted(o[-8:] for o in old)))  # fmt: skip

    port = next(p for p in range(24622, 32767)
                if all(s["port"] != p for s in before["listening"]))  # fmt: skip
    cycle("ssh.port", {"port": port},
          lambda f: f["ssh"]["ports"] == [port],
          lambda f: f["ssh"]["ports"] == before["ssh"]["ports"], confirm=True)  # fmt: skip

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
        # --wait: the undo must finish before the late confirm, or the confirm may win.
        subprocess.run(["systemctl", "--wait", "start", f"kerberos-undo-{change}.service"],
                       check=False)  # fmt: skip
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

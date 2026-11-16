#!/usr/bin/env python3
"""KERBEROS agent (tech.md §9): one file, Python 3.9+, standard library only.

Installed on a node as /usr/local/sbin/kerberos-agent and reached only
through the restricted KERBEROS key (`command=` in authorized_keys), so the
requested command arrives in SSH_ORIGINAL_COMMAND. The rollback timer of
systemd calls it with arguments instead. Only the commands of §9.1 are
accepted; parameters are checked with regular expressions and data comes as
JSON on stdin. The answer is one JSON object on stdout; on an error the exit
code is not 0 and the body is {"error": {"code", "message"}}.

Every function works on a `System`: the root of the file system and the
command runner, so tests run the same code against a temporary directory
and recorded command outputs.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
from typing import Any, Callable, Optional

PROTOCOL = 1
AGENT_VERSION = "0.6.0"
AGENT_PATH = "/usr/local/sbin/kerberos-agent"
STATE_DIR = "/var/lib/kerberos"

ERROR_CODES = frozenset(
    """bad_params unknown_command sha_mismatch no_admin_key sshd_test_failed ssh_port
    port_busy bridge_network docker_published mptcp_absent port80_busy certbot_failed
    nginx_test_failed realip_enabled apt_failed change_conflict no_backup backup_damaged
    not_implemented command_failed""".split()
)

FIX_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
CHANGE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AgentError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown agent error code {code}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Result:
    def __init__(self, code: int, stdout: str = "", stderr: str = "") -> None:
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.code == 0


def run_command(argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
    try:
        proc = subprocess.run(
            argv,
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(os.environ, LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive"),
        )
    except FileNotFoundError:
        return Result(127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return Result(124, "", f"{argv[0]}: timeout")
    return Result(proc.returncode, proc.stdout, proc.stderr)


class System:
    """File system root, command runner and environment of one agent call."""

    def __init__(
        self,
        root: str = "/",
        run: Callable[..., Result] = run_command,
        environ: Optional[dict] = None,
        fetch: Optional[Callable[..., tuple]] = None,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        self.root = root
        self._run = run
        self.environ = dict(os.environ if environ is None else environ)
        self.fetch = fetch or https_get
        self.now = now or time.time

    def path(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.path(path))

    def read(self, path: str) -> Optional[str]:
        try:
            with open(self.path(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def read_bytes(self, path: str) -> Optional[bytes]:
        try:
            with open(self.path(path), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def write_bytes(self, path: str, data: bytes, mode: int) -> None:
        """Atomic write: a temporary file in the same directory, then rename."""
        full = self.path(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = f"{full}.kerberos-tmp-{os.getpid()}"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, full)

    def write(self, path: str, text: str, mode: int = 0o644) -> None:
        self.write_bytes(path, text.encode("utf-8"), mode)

    def run(self, argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
        return self._run(argv, input=input, timeout=timeout)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def own_source(system: System) -> bytes:
    data = system.read_bytes(AGENT_PATH)
    if data is None:
        with open(os.path.abspath(__file__), "rb") as fh:
            data = fh.read()
    return data


# -- reading the node (tech.md §9.2): pure parsers ---------------------------
PRIVATE_V4 = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
              "127.0.0.0/8")
)  # fmt: skip
PRIVATE_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128"))
KEY_TYPE_NAMES = {
    "ssh-ed25519": "ED25519",
    "ssh-rsa": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
}
UFW_APPS = {"openssh": [(22, "tcp")], "nginx full": [(80, "tcp"), (443, "tcp")],
            "nginx http": [(80, "tcp")], "nginx https": [(443, "tcp")]}  # fmt: skip
XRAY_LOGS = ("/var/log/remnanode/access.log", "/var/log/xray/access.log")
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".xn--p1acf", ".xn--p1ag")


def parse_os_release(text: str) -> dict:
    values = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return {"id": values.get("ID", ""), "version": values.get("VERSION_ID", "")}


def is_public(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    nets = PRIVATE_V4 if addr.version == 4 else PRIVATE_V6
    return not any(addr in net for net in nets) and not addr.is_multicast


def parse_ip_addr(text: str) -> tuple[list, list]:
    """Global addresses from `ip -j addr show`, private ranges left out."""
    v4: list = []
    v6: list = []
    try:
        links = json.loads(text or "[]")
    except ValueError:
        return v4, v6
    for link in links if isinstance(links, list) else []:
        for info in link.get("addr_info") or []:
            if info.get("scope") != "global" or not is_public(str(info.get("local", ""))):
                continue
            target = v4 if info.get("family") == "inet" else v6
            if info["local"] not in target:
                target.append(info["local"])
    return v4, v6


def split_host_port(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    host = host.strip("[]")
    if "%" in host:
        host = host.split("%", 1)[0]
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_ss_listen(text: str) -> list:
    """`ss -Hlntup`: proto, local address and port, process."""
    sockets = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        address, port = split_host_port(parts[4])
        match = re.search(r'users:\(\("([^"]+)"', line)
        sockets.append(
            {
                "proto": parts[0],
                "address": "0.0.0.0" if address == "*" else address,
                "port": port,
                "process": match.group(1) if match else "",
            }
        )
    return sockets


def parse_ss_connections(text: str) -> list:
    """`ss -Htin state established`: peer, bytes received, ms since the last receive."""
    connections = []
    current: Optional[dict] = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if current is not None:
                received = re.search(r"\bbytes_received:(\d+)", line)
                last = re.search(r"\blastrcv:(\d+)", line)
                current["received"] = int(received.group(1)) if received else 0
                current["lastrcv"] = int(last.group(1)) if last else 0
            continue
        parts = line.split()
        if len(parts) >= 4:
            peer, _ = split_host_port(parts[3])
            local, port = split_host_port(parts[2])
            current = {"peer": peer, "local": local, "port": port, "received": 0, "lastrcv": 0}
            connections.append(current)
    return connections


def parse_sshd_t(text: str) -> dict:
    values: dict = {"port": []}
    for line in (text or "").splitlines():
        key, _, value = line.strip().partition(" ")
        key = key.lower()
        if key == "port":
            if value.strip().isdigit():
                values["port"].append(int(value))
        elif key:
            values.setdefault(key, value.strip())
    return values


def parse_socket_ports(text: str) -> list:
    """`systemctl show ssh.socket -p Listen`: Listen=[::]:22 (Stream) ..."""
    ports = []
    for match in re.finditer(r":(\d+) \(Stream\)", text or ""):
        port = int(match.group(1))
        if port not in ports:
            ports.append(port)
    return ports


def count_admin_keys(text: str) -> int:
    count = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"(^|\s)(ssh-|ecdsa-|sk-)\S+\s+\S+", line) and AGENT_PATH not in line:
            count += 1
    return count


def host_key_facts(files: dict) -> list:
    keys = []
    for name in sorted(files):
        parts = (files[name] or "").split()
        if len(parts) < 2:
            continue
        try:
            raw = base64.b64decode(parts[1])
        except (ValueError, TypeError):
            continue
        digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        keys.append(
            {"type": KEY_TYPE_NAMES.get(parts[0], parts[0]), "fingerprint": f"SHA256:{digest}"}
        )
    return keys


def _port_values(right: Any) -> list:
    """Ports in the right side of an nft match: a number, a set or a range."""
    if isinstance(right, int):
        return [right]
    if isinstance(right, dict):
        if "set" in right:
            values = []
            for item in right["set"]:
                values += _port_values(item)
            return values
        if "range" in right and len(right["range"]) == 2:
            low, high = right["range"]
            if isinstance(low, int) and isinstance(high, int) and high - low < 70000:
                return list(range(low, high + 1))
    return []


class Ruleset:
    """The effective nft rules that matter here (from `nft -j list ruleset`)."""

    def __init__(self, text: str) -> None:
        try:
            items = json.loads(text or "{}").get("nftables", [])
        except (ValueError, AttributeError):
            items = []
        self.tables: list = []
        self.input_chains: set = set()
        self.rules: list = []
        for item in items:
            if "table" in item:
                table = item["table"]
                self.tables.append(f"{table.get('family')} {table.get('name')}")
            elif "chain" in item and item["chain"].get("hook") == "input":
                chain = item["chain"]
                self.input_chains.add((chain.get("family"), chain.get("table"), chain.get("name")))
            elif "rule" in item:
                self.rules.append(item["rule"])

    def _input_rules(self):
        for rule in self.rules:
            if (rule.get("family"), rule.get("table"), rule.get("chain")) in self.input_chains:
                yield rule

    @staticmethod
    def _parse(rule: dict) -> dict:
        info: dict = {"ports": [], "proto": None, "saddr": None, "verdict": None, "hdrlen": False}
        for expr in rule.get("expr") or []:
            match = expr.get("match")
            if match:
                left = match.get("left") or {}
                payload = left.get("payload") if isinstance(left, dict) else None
                if payload and payload.get("field") == "dport":
                    info["proto"] = payload.get("protocol")
                    info["ports"] += _port_values(match.get("right"))
                elif payload and payload.get("field") == "saddr":
                    info["saddr"] = match.get("right")
                elif (
                    payload
                    and payload.get("field") == "hdrlength"
                    and match.get("op") in (">", "!=")
                ):
                    info["hdrlen"] = True
            for verdict in ("accept", "drop", "reject"):
                if verdict in expr:
                    info["verdict"] = verdict
        return info

    def dropped(self, proto: str) -> set:
        """Ports dropped for every source on input."""
        ports: set = set()
        for rule in self._input_rules():
            info = self._parse(rule)
            if info["verdict"] in ("drop", "reject") and info["saddr"] is None:
                if info["proto"] in (proto, "th", None) and info["ports"]:
                    ports.update(info["ports"])
        return ports

    def accepted_from(self, port: int) -> list:
        sources = []
        for rule in self._input_rules():
            info = self._parse(rule)
            if info["verdict"] == "accept" and port in info["ports"] and info["saddr"]:
                sources.append(str(info["saddr"]))
        return sources

    def drops_ip_options(self) -> bool:
        return any(
            self._parse(rule)["hdrlen"] and self._parse(rule)["verdict"] == "drop"
            for rule in self._input_rules()
        )


def parse_ufw(text: str) -> dict:
    """`ufw status verbose`: state, default policy and allowed ports from anywhere."""
    if not text:
        return {"state": "absent", "deny": False, "allowed": set()}
    state = "active" if re.search(r"^Status: active", text, re.M) else "inactive"
    deny = bool(re.search(r"^Default: (deny|reject) \(incoming\)", text, re.M))
    allowed: set = set()
    rules = False
    for line in text.splitlines():
        if line.startswith("--"):
            rules = True
            continue
        if not rules or not line.strip():
            continue
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 3 or not cols[1].startswith(("ALLOW", "LIMIT")):
            continue
        if not cols[2].startswith("Anywhere"):
            continue
        target = cols[0].replace(" (v6)", "").strip()
        for port, proto in _ufw_target(target):
            allowed.add((port, proto))
    return {"state": state, "deny": deny, "allowed": allowed}


def _ufw_target(target: str) -> list:
    if target.lower() in UFW_APPS:
        return UFW_APPS[target.lower()]
    port, _, proto = target.partition("/")
    result = []
    for part in port.split(","):
        low, _, high = part.partition(":")
        if low.isdigit():
            for value in range(int(low), int(high or low) + 1):
                for kind in [proto] if proto else ["tcp", "udp"]:
                    result.append((value, kind))
    return result


def parse_fail2ban(configs: list, ssh_ports: list) -> dict:
    """The sshd jail from fail2ban's files in their own order of precedence."""
    if not configs:
        return {"enabled": False, "jailPorts": []}
    enabled = False
    port_value = "ssh"
    defaults_enabled = False
    for _name, text in configs:
        section = None
        for raw in (text or "").splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            header = re.match(r"^\[(.+)\]$", line)
            if header:
                section = header.group(1).strip()
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key, value = key.strip().lower(), value.strip()
            if section == "DEFAULT" and key == "enabled":
                defaults_enabled = value.lower() in ("true", "yes", "1")
            if section == "sshd":
                if key == "enabled":
                    enabled = value.lower() in ("true", "yes", "1")
                elif key == "port":
                    port_value = value
    jail_ports: list = []
    for part in re.split(r"[,\s]+", port_value):
        part = part.strip()
        if part in ("ssh", "%(ssh_port)s"):
            part = "22"
        low, _, high = part.partition(":")
        if low.isdigit() and high.isdigit():
            jail_ports += [p for p in ssh_ports if int(low) <= p <= int(high)]
        elif low.isdigit():
            jail_ports.append(int(low))
    return {"enabled": enabled or defaults_enabled, "jailPorts": sorted(set(jail_ports))}


def docker_published(text: str) -> set:
    ports: set = set()
    for line in (text or "").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        for match in re.finditer(r":(\d+)->\d+/(tcp|udp)", str(item.get("Ports", ""))):
            ports.add((int(match.group(1)), match.group(2)))
    return ports


def parse_remnanode(text: str) -> dict:
    """`docker inspect remnanode`: only network, node port and mounts. The
    environment holds SECRET_KEY: only NODE_PORT or APP_PORT is taken from it."""
    try:
        data = json.loads(text or "[]")[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return {"present": False, "network": None, "nodePort": None, "letsencryptMounted": False}
    port = None
    for item in (data.get("Config") or {}).get("Env") or []:
        name, _, value = str(item).partition("=")
        if name in ("NODE_PORT", "APP_PORT") and value.isdigit():
            port = int(value)
    mode = (data.get("HostConfig") or {}).get("NetworkMode") or ""
    mounts = [m.get("Destination") for m in data.get("Mounts") or []]
    return {
        "present": True,
        "network": "host" if mode == "host" else "bridge",
        "nodePort": port,
        "letsencryptMounted": any(str(d).rstrip("/") == "/etc/letsencrypt" for d in mounts),
    }


def parse_nginx(files: dict) -> dict:
    realip = False
    sites = []
    for name in sorted(files):
        text = re.sub(r"#[^\n]*", "", files[name] or "")
        if re.search(r"\b(real_ip_header|set_real_ip_from)\b", text):
            realip = True
        for block in _server_blocks(text):
            names = []
            for match in re.finditer(r"\bserver_name\s+([^;]+);", block):
                names += [n for n in match.group(1).split() if n != "_"]
            listen = []
            for match in re.finditer(r"\blisten\s+([^;]+);", block):
                listen.append(" ".join(match.group(1).split()))
            sites.append({"file": name, "serverNames": names, "listen": listen})
    return {"realip": realip, "sites": sites}


def _server_blocks(text: str) -> list:
    blocks = []
    for match in re.finditer(r"\bserver\s*\{", text):
        depth, i = 1, match.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        blocks.append(text[match.end() : i - 1])
    return blocks


def cert_not_after(path: str) -> Optional[str]:
    try:
        import _ssl

        decoded = _ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib has no public decoder
    except Exception:  # noqa: BLE001 - any failure means "unknown"
        return None
    value = decoded.get("notAfter")
    if not value:
        return None
    try:
        stamp = ssl.cert_time_to_seconds(value)
    except ValueError:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def parse_xray_log(text: str, now: float) -> dict:
    """Counts of the last five minutes of the Xray access log; never addresses."""
    accepted = 0
    users: set = set()
    russian = 0
    since = now - 300
    for line in (text or "").splitlines():
        match = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        if not match or " accepted " not in line:
            continue
        try:
            stamp = time.mktime(time.strptime(match.group(1), "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            continue
        if stamp < since:
            continue
        accepted += 1
        dest = re.search(r" accepted (?:tcp|udp):([^:\s]+):\d+", line)
        if dest and dest.group(1).lower().endswith(RU_TLDS):
            russian += 1
        email = re.search(r"email: (\S+)", line)
        if email:
            users.add(email.group(1))
    share = round(russian / accepted, 4) if accepted else 0.0
    return {"accepted5m": accepted, "users5m": len(users), "ruShare": share}


def net_of(address: str, v4_prefix: int, v6_prefix: int) -> str:
    addr = ipaddress.ip_address(address)
    prefix = v4_prefix if addr.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def watch_family(connections: list) -> dict:
    cut = [c for c in connections if c["received"] <= 1500 and c["lastrcv"] > 3000]
    nets: dict = {}
    for item in cut:
        net = net_of(item["peer"], 16, 32)
        nets[net] = nets.get(net, 0) + 1
    return {
        "connections": len(connections),
        "clientIps": len({c["peer"] for c in connections}),
        "cut": len(cut),
        "cutNets": [{"net": n, "count": c} for n, c in sorted(nets.items(), key=lambda x: -x[1])],
    }


def template_hash(html: str) -> str:
    """Structure of a page: the sequence of its tags, not the text."""
    tags = re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)", html or "")
    return hashlib.sha256(" ".join(t.lower() for t in tags).encode()).hexdigest()[:16]


def parse_access_log(text: str, path: str) -> dict:
    nets: dict = {}
    for line in (text or "").splitlines():
        match = re.match(r'^(\S+) \S+ \S+ \[[^\]]*\] "(?:GET|POST|PUT|HEAD|OPTIONS) (\S+)', line)
        if not match or not match.group(2).startswith(path):
            continue
        try:
            net = net_of(match.group(1), 24, 48)
        except ValueError:
            continue
        nets[net] = nets.get(net, 0) + 1
    return nets


# -- reading the node: collectors ------------------------------------------
def panel_address(system: System) -> str:
    parts = system.environ.get("SSH_CONNECTION", "").split()
    return parts[0] if parts else ""


def collect_ssh(system: System) -> dict:
    values = parse_sshd_t(system.run(["sshd", "-T"]).stdout)
    socket_active = system.run(["systemctl", "is-active", "ssh.socket"]).stdout.strip() == "active"
    ports = values.get("port") or [22]
    if socket_active:
        listen = parse_socket_ports(
            system.run(["systemctl", "show", "ssh.socket", "-p", "Listen"]).stdout
        )
        socket_active = bool(listen)
        ports = listen or ports
    admin = count_admin_keys(
        (system.read("/root/.ssh/authorized_keys") or "")
        + "\n"
        + (system.read("/root/.ssh/authorized_keys2") or "")
    )
    kbd = values.get("kbdinteractiveauthentication", values.get("challengeresponseauthentication"))
    return {
        "ports": ports,
        "socketActivated": socket_active,
        "passwordAuthentication": values.get("passwordauthentication") == "yes",
        "kbdInteractive": kbd == "yes",
        "permitRootLogin": values.get("permitrootlogin", ""),
        "adminKeys": admin,
    }


def fail2ban_files(system: System) -> list:
    order = ["/etc/fail2ban/jail.conf"]
    jail_d = system.path("/etc/fail2ban/jail.d")
    names = sorted(os.listdir(jail_d)) if os.path.isdir(jail_d) else []
    order += [f"/etc/fail2ban/jail.d/{n}" for n in names if n.endswith(".conf")]
    order.append("/etc/fail2ban/jail.local")
    order += [f"/etc/fail2ban/jail.d/{n}" for n in names if n.endswith(".local")]
    return [(name, system.read(name)) for name in order if system.read(name) is not None]


def collect_files(system: System, directory: str, suffix: str = "") -> dict:
    full = system.path(directory)
    if not os.path.isdir(full):
        return {}
    files = {}
    for name in sorted(os.listdir(full)):
        if suffix and not name.endswith(suffix):
            continue
        path = f"{directory.rstrip('/')}/{name}"
        text = system.read(path)
        if text is not None:
            files[path] = text
    return files


def collect_facts(system: System) -> dict:
    os_release = parse_os_release(system.read("/etc/os-release") or "")
    kernel = (system.read("/proc/sys/kernel/osrelease") or "").strip()
    v4, v6 = parse_ip_addr(system.run(["ip", "-j", "addr", "show"]).stdout)
    ssh = collect_ssh(system)
    ruleset = Ruleset(system.run(["nft", "-j", "list", "ruleset"]).stdout)
    ufw_out = system.run(["ufw", "status", "verbose"])
    ufw = parse_ufw(ufw_out.stdout if ufw_out.code != 127 else "")
    published = docker_published(system.run(["docker", "ps", "--format", "{{json .}}"]).stdout)
    remnanode = parse_remnanode(system.run(["docker", "inspect", "remnanode"]).stdout)
    if remnanode["present"]:
        version = system.run(["docker", "exec", "remnanode", "xray", "version"]).stdout
        match = re.search(r"Xray (\d+\.\d+\.\d+)", version)
        remnanode["xrayVersion"] = match.group(1) if match else None
    else:
        remnanode["xrayVersion"] = None
    listening = []
    for item in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout):
        key = (item["port"], item["proto"])
        firewalled = item["port"] in ruleset.dropped(item["proto"]) or (
            ufw["state"] == "active" and ufw["deny"] and key not in ufw["allowed"]
        )
        item["docker"] = item["process"] == "docker-proxy" or key in published
        item["firewalled"] = firewalled
        listening.append(item)
    node_port = remnanode.get("nodePort")
    panel_ip = panel_address(system)
    other_peers = 0
    if node_port:
        out = system.run(["ss", "-Htn", "state", "established", f"( sport = :{node_port} )"])
        peers = {c["peer"] for c in parse_ss_connections(out.stdout)}
        other_peers = len([p for p in peers if p != panel_ip])
    jail = parse_fail2ban(fail2ban_files(system), ssh["ports"])
    f2b_installed = system.exists("/usr/bin/fail2ban-client")
    f2b_active = system.run(["systemctl", "is-active", "fail2ban"]).stdout.strip() == "active"
    mptcp_sockets = 0
    for line in (system.read("/proc/net/protocols") or "").splitlines():
        parts = line.split()
        if parts and parts[0] in ("MPTCP", "MPTCPv6") and len(parts) > 2 and parts[2].isdigit():
            mptcp_sockets += int(parts[2])
    host_keys = host_key_facts({
        p: t for p, t in collect_files(system, "/etc/ssh", ".pub").items()
        if os.path.basename(p).startswith("ssh_host_")
    })  # fmt: skip
    nginx_files = collect_files(system, "/etc/nginx/sites-enabled")
    nginx_files.update(collect_files(system, "/etc/nginx/conf.d", ".conf"))
    nginx = parse_nginx(nginx_files)
    certs = []
    live = system.path("/etc/letsencrypt/live")
    if os.path.isdir(live):
        for name in sorted(os.listdir(live)):
            cert = os.path.join(live, name, "cert.pem")
            if os.path.exists(cert):
                certs.append({"domain": name, "notAfter": cert_not_after(cert)})
    return {
        "protocol": PROTOCOL,
        "agent": AGENT_VERSION,
        "os": {**os_release, "kernel": kernel},
        "ipv4": v4,
        "ipv6": v6,
        "python": platform.python_version(),
        "listening": listening,
        "ssh": ssh,
        "fail2ban": {
            "installed": f2b_installed,
            "sshdJail": f2b_installed and f2b_active and jail["enabled"],
            "jailPorts": jail["jailPorts"],
        },
        "mptcp": {
            "enabled": (system.read("/proc/sys/net/mptcp/enabled") or "0").strip() == "1",
            "ipOptionsDrop": ruleset.drops_ip_options(),
            "sockets": mptcp_sockets,
        },
        "nodeApi": {
            "port": node_port,
            "panelOnly": bool(node_port) and node_port in ruleset.dropped("tcp"),
            "otherPeers": other_peers,
        },
        "nftTables": ruleset.tables,
        "hostKeys": host_keys,
        "firewall": {"ufw": ufw["state"]},
        "remnanode": remnanode,
        "nginx": {
            "installed": system.exists("/usr/sbin/nginx"),
            "realip": nginx["realip"],
            "sites": nginx["sites"],
        },
        "certbot": {"installed": system.exists("/usr/bin/certbot"), "certs": certs},
        "watch": {
            "installed": system.exists("/usr/local/sbin/kerberos-watch")
            and system.exists("/etc/cron.d/kerberos-watch")
        },
    }


def collect_watch(system: System, port: int = 443) -> dict:
    out = system.run(["ss", "-Htin", "state", "established", f"( sport = :{port} )"])
    connections = parse_ss_connections(out.stdout)
    v4 = [c for c in connections if ":" not in c["peer"]]
    v6 = [c for c in connections if ":" in c["peer"]]
    log = ""
    for path in XRAY_LOGS:
        data = system.read_bytes(path)
        if data is not None:
            log = data[-2_000_000:].decode("utf-8", "replace")
            break
    xray = parse_xray_log(log, system.now()) if log else {
        "accepted5m": None, "users5m": None, "ruShare": None,
    }  # fmt: skip
    return {
        "protocol": PROTOCOL,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(system.now())),
        "port": port,
        "v4": watch_family(v4),
        "v6": watch_family(v6),
        "xray": xray,
    }


def https_get(host: str, port: int, sni: str, path: str, timeout: float = 10.0) -> tuple:
    """GET over TLS with a chosen SNI; the certificate is not checked (local stub)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n"
    )
    data = b""
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            tls.sendall(request.encode())
            while len(data) < 1_000_000:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _unchunk(body)
    return status, headers, body


def _unchunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2 :]
    return out


DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
URL_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")


def cmd_facts(system: System, args: list, data: Any) -> dict:
    return collect_facts(system)


def cmd_watch(system: System, args: list, data: Any) -> dict:
    return collect_watch(system)


def cmd_site_check(system: System, args: list, data: dict) -> dict:
    domain = str(data.get("domain", "")).lower()
    if not DOMAIN.match(domain):
        raise AgentError("bad_params", "domain")
    try:
        status, headers, body = system.fetch("127.0.0.1", 8445, domain, "/")
    except (OSError, ValueError, IndexError):
        return {"template": None, "altSvc": None, "status": None}
    return {
        "template": template_hash(body.decode("utf-8", "replace")),
        "altSvc": headers.get("alt-svc"),
        "status": status,
    }


def cmd_edge_sources(system: System, args: list, data: dict) -> dict:
    path = str(data.get("path", ""))
    if not URL_PATH.match(path):
        raise AgentError("bad_params", "path")
    nets: dict = {}
    for name in ("/var/log/nginx/access.log.1", "/var/log/nginx/access.log"):
        for net, count in parse_access_log(system.read(name) or "", path).items():
            nets[net] = nets.get(net, 0) + count
    ordered = sorted(nets.items(), key=lambda item: (-item[1], item[0]))
    return {"nets": [{"net": n, "count": c} for n, c in ordered]}


# -- changes (tech.md §9.3) ---------------------------------------------------
CHANGES_DIR = STATE_DIR + "/changes"
PENDING_FILE = STATE_DIR + "/pending"
UNDO_DELAY = 180
SSHD_CONF = "/etc/ssh/sshd_config.d/10-kerberos.conf"
AUTHORIZED_KEYS = "/root/.ssh/authorized_keys"
HOST_KEY_NAMES = ("rsa", "ecdsa", "ed25519")


class Plan:
    """What one fix changes: files, packages, commands, how to undo."""

    def __init__(self, fix_id: str) -> None:
        self.fix_id = fix_id
        self.files: dict = {}  # path -> (text or None to delete, mode)
        self.created: list = []  # paths commands create; absent before
        self.packages: list = []
        self.commands: list = []  # (argv, error code), after the files
        self.undo_before: list = []  # argv, before files are restored
        self.undo_after: list = []  # argv, after files are restored
        self.access = False  # timer and confirmation by a new connection
        self.details: dict = {}
        self.after: Optional[Callable[[System], dict]] = None
        self.keep: list = []  # backed up now, changed only by `confirm`
        self.confirm_files: dict = {}  # path -> (text, mode), written by `confirm`
        self.confirm_commands: list = []  # (argv, error code), run by `confirm`
        self.steps: list = []  # ordered writes and runs after files and commands

    def write(self, path: str, text: Optional[str], mode: int = 0o644) -> None:
        self.files[path] = (text, mode)

    def run(self, argv: list, code: str = "command_failed") -> None:
        self.commands.append((argv, code))

    def on_confirm(self, path: Optional[str] = None, text: Optional[str] = None,
                   argv: Optional[list] = None, code: str = "command_failed") -> None:  # fmt: skip
        """Second phase (§10.3, ssh.port): after the new connection has worked."""
        if path is not None:
            self.confirm_files[path] = (text, 0o644)
            if path not in self.files and path not in self.keep:
                self.keep.append(path)
        if argv is not None:
            self.confirm_commands.append((argv, code))

    def step_write(self, path: str, text: str, mode: int = 0o644) -> None:
        """An ordered step: for fixes that must interleave files and commands."""
        self.steps.append(("write", path, text, mode))
        if path not in self.keep and path not in self.files:
            self.keep.append(path)

    def step_run(self, argv: list, code: str = "command_failed", timeout: float = 120) -> None:
        self.steps.append(("run", argv, code, timeout))


FIXES: dict = {}


def fix(name: str):
    def register(builder):
        FIXES[name] = builder
        return builder

    return register


def change_dir(change_id: str) -> str:
    return f"{CHANGES_DIR}/{change_id}"


def load_record(system: System, change_id: str) -> Optional[dict]:
    text = system.read(f"{change_dir(change_id)}/rollback.json")
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AgentError("backup_damaged", "rollback.json is not JSON") from exc


def save_record(system: System, record: dict) -> None:
    system.write(f"{change_dir(record['changeId'])}/rollback.json",
                 json.dumps(record, indent=2, sort_keys=True), 0o600)  # fmt: skip


def answer_of(record: dict, state: Optional[str] = None) -> dict:
    return {
        "protocol": PROTOCOL,
        "changeId": record["changeId"],
        "fixId": record["fixId"],
        "state": state or record["state"],
        "files": [item["path"] for item in record["files"]],
        "details": record.get("details", {}),
    }


def file_sha(system: System, path: str) -> Optional[str]:
    data = system.read_bytes(path)
    return None if data is None else sha256_bytes(data)


def mode_of(system: System, path: str) -> Optional[int]:
    try:
        return os.stat(system.path(path)).st_mode & 0o7777
    except OSError:
        return None


def backup(system: System, change_id: str, plan: Plan) -> dict:
    """Copy every file the change touches before anything happens (§9.3)."""
    entries = []
    paths = list(plan.files) + [p for p in plan.created + plan.keep if p not in plan.files]
    paths = list(dict.fromkeys(paths))
    for index, path in enumerate(paths):
        data = system.read_bytes(path)
        entry = {"path": path, "existed": data is not None, "mode": mode_of(system, path),
                 "backup": None, "sha256": None}  # fmt: skip
        if data is not None:
            name = f"files/{index}"
            system.write_bytes(f"{change_dir(change_id)}/{name}", data, 0o600)
            entry["backup"] = name
            entry["sha256"] = sha256_bytes(data)
        entries.append(entry)
    return {
        "changeId": change_id,
        "fixId": plan.fix_id,
        "state": "applying",
        "files": entries,
        "undoBefore": plan.undo_before,
        "undoAfter": plan.undo_after,
        "access": plan.access,
        "details": dict(plan.details),
        "confirm": {
            "files": {p: [text, mode] for p, (text, mode) in plan.confirm_files.items()},
            "commands": [[argv, code] for argv, code in plan.confirm_commands],
        },
        "written": {},
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(system.now())),
    }


def restore(system: System, record: dict) -> list:
    """Files back to their bytes and modes; undo commands around it."""
    problems = []
    for argv in record.get("undoBefore", []):
        if not system.run(argv).ok:
            problems.append(" ".join(argv))
    for entry in record["files"]:
        path = entry["path"]
        if entry["existed"]:
            data = system.read_bytes(f"{change_dir(record['changeId'])}/{entry['backup']}")
            if data is None or sha256_bytes(data) != entry["sha256"]:
                raise AgentError("backup_damaged", path)
            system.write_bytes(path, data, entry["mode"] if entry["mode"] is not None else 0o644)
        elif system.exists(path):
            os.remove(system.path(path))
    for argv in record.get("undoAfter", []):
        if not system.run(argv).ok:
            problems.append(" ".join(argv))
    return problems


def install_packages(system: System, packages: list) -> None:
    if not packages:
        return
    argv = ["apt-get", "install", "-y", "-q", *packages]
    if system.run(argv, timeout=600).ok:
        return
    system.run(["apt-get", "update", "-q"], timeout=600)
    if not system.run(argv, timeout=600).ok:
        raise AgentError("apt_failed", " ".join(packages))


def pending_change(system: System) -> Optional[str]:
    value = (system.read(PENDING_FILE) or "").strip()
    return value or None


def cmd_apply(system: System, args: list, data: dict) -> dict:
    fix_id, change_id = args
    record = load_record(system, change_id)
    if record is not None:
        if record["fixId"] != fix_id:
            raise AgentError("change_conflict", "the changeId belongs to another fix")
        return answer_of(record, "noop")
    builder = FIXES.get(fix_id)
    if builder is None:
        raise AgentError("not_implemented", fix_id)
    waiting = pending_change(system)
    if waiting:
        other = load_record(system, waiting)
        if other is not None and other["state"] == "pending_confirm":
            raise AgentError("change_conflict", f"change {waiting} waits for confirmation")
    plan = builder(system, data)
    install_packages(system, plan.packages)
    record = backup(system, change_id, plan)
    save_record(system, record)
    try:
        for path, (text, mode) in plan.files.items():
            if text is None:
                if system.exists(path):
                    os.remove(system.path(path))
            else:
                system.write(path, text, mode)
        for argv, code in plan.commands:
            result = system.run(argv, timeout=600 if argv[:1] == ["apt-get"] else 120)
            if not result.ok:
                raise AgentError(code, " ".join(argv))
        for step in plan.steps:
            if step[0] == "write":
                system.write(step[1], step[2], step[3])
            elif not system.run(step[1], timeout=step[3]).ok:
                raise AgentError(step[2], " ".join(step[1]))
        if plan.after is not None:
            record["details"].update(plan.after(system))
    except AgentError:
        restore(system, record)
        record["state"] = "failed"
        save_record(system, record)
        raise
    record["written"] = {e["path"]: file_sha(system, e["path"]) for e in record["files"]}
    if plan.access:
        unit = f"kerberos-undo-{change_id}"
        timer = system.run(["systemd-run", f"--on-active={UNDO_DELAY}", "--unit", unit,
                            AGENT_PATH, "rollback", change_id])  # fmt: skip
        if not timer.ok:
            restore(system, record)
            record["state"] = "failed"
            save_record(system, record)
            raise AgentError("command_failed", "systemd-run")
        record["state"] = "pending_confirm"
        system.write(PENDING_FILE, change_id + "\n", 0o600)
    else:
        record["state"] = "applied"
    save_record(system, record)
    return answer_of(record)


def stop_timer(system: System, change_id: str) -> None:
    system.run(["systemctl", "stop", f"kerberos-undo-{change_id}.timer"])


def cmd_confirm(system: System, args: list, data: Any) -> dict:
    change_id = args[0]
    record = load_record(system, change_id)
    if record is None:
        raise AgentError("no_backup", change_id)
    if record["state"] in ("confirmed", "applied"):
        return answer_of(record, "noop")
    if record["state"] != "pending_confirm":
        raise AgentError("change_conflict", f"change is {record['state']}")
    second = record.get("confirm") or {}
    try:
        for path, (text, mode) in (second.get("files") or {}).items():
            if text is None:
                if system.exists(path):
                    os.remove(system.path(path))
            else:
                system.write(path, text, mode)
        for argv, code in second.get("commands") or []:
            if not system.run(argv).ok:
                raise AgentError(code, " ".join(argv))
    except AgentError:
        stop_timer(system, change_id)
        restore(system, record)
        record["state"] = "failed"
        if pending_change(system) == change_id:
            system.write(PENDING_FILE, "", 0o600)
        save_record(system, record)
        raise
    stop_timer(system, change_id)
    record["written"] = {e["path"]: file_sha(system, e["path"]) for e in record["files"]}
    record["state"] = "confirmed"
    if pending_change(system) == change_id:
        system.write(PENDING_FILE, "", 0o600)
    save_record(system, record)
    return answer_of(record)


def cmd_rollback(system: System, args: list, data: Any) -> dict:
    change_id = args[0]
    record = load_record(system, change_id)
    if record is None:
        raise AgentError("no_backup", change_id)
    if record["state"] == "rolled_back":
        return answer_of(record, "noop")
    if record["state"] in ("applied", "confirmed"):
        for path, sha in record.get("written", {}).items():
            if file_sha(system, path) != sha:
                raise AgentError("change_conflict", f"{path} changed after KERBEROS")
    if record["state"] == "pending_confirm":
        stop_timer(system, change_id)
    problems = restore(system, record)
    record["state"] = "rolled_back"
    record["details"]["undoProblems"] = problems
    if pending_change(system) == change_id:
        system.write(PENDING_FILE, "", 0o600)
    save_record(system, record)
    return answer_of(record)


def cmd_plan(system: System, args: list, data: dict) -> dict:
    builder = FIXES.get(args[0])
    if builder is None:
        raise AgentError("not_implemented", args[0])
    plan = builder(system, data)
    return {
        "files": [{"path": p, "content": text} for p, (text, _mode) in plan.files.items()],
        "commands": [" ".join(argv) for argv, _code in plan.commands],
        "packages": plan.packages,
    }


# -- the fixes of §10.3 -------------------------------------------------------
def nft_unit(name: str, table: str, conf: str, about: str) -> str:
    return (
        "[Unit]\n"
        f"Description=KERBEROS: {about}\n"
        "After=network-pre.target\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/usr/sbin/nft -f {conf}\n"
        f"ExecStop=/usr/sbin/nft delete table {table}\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def nft_table(table: str, rules: list) -> str:
    """Loading is idempotent: the table is created, flushed and filled again."""
    body = "\n".join(f"    {rule}" for rule in rules)
    return (
        f"table {table}\nflush table {table}\n"
        f"table {table} {{\n  chain input {{\n"
        "    type filter hook input priority -10; policy accept;\n"
        f"{body}\n  }}\n}}\n"
    )


def nft_service(plan: Plan, name: str, table: str, rules: list, about: str) -> None:
    conf = f"/etc/kerberos/{name}.nft"
    unit = f"kerberos-{name}.service"
    plan.write(conf, nft_table(table, rules))
    plan.write(f"/etc/systemd/system/{unit}", nft_unit(name, table, conf, about))
    plan.run(["systemctl", "daemon-reload"])
    plan.run(["systemctl", "enable", unit])
    plan.run(["systemctl", "restart", unit])
    plan.undo_before.append(["systemctl", "disable", "--now", unit])
    plan.undo_after.append(["systemctl", "daemon-reload"])


@fix("mptcp.guard")
def fix_mptcp(system: System, params: dict) -> Plan:
    current = system.read("/proc/sys/net/mptcp/enabled")
    if current is None:
        raise AgentError("mptcp_absent", "no net.mptcp in this kernel")
    plan = Plan("mptcp.guard")
    plan.write("/etc/sysctl.d/98-kerberos-mptcp.conf", "net.mptcp.enabled = 0\n")
    plan.run(["sysctl", "-w", "net.mptcp.enabled=0"])
    nft_service(plan, "mptcp", "inet kerberos_mptcp",
                ["ip protocol tcp ip hdrlength > 5 counter drop"],
                "drop TCP packets with IP options (MPTCP guard)")  # fmt: skip
    plan.undo_after.append(["sysctl", "-w", f"net.mptcp.enabled={current.strip() or '0'}"])
    return plan


def int_list(value: Any, what: str) -> list:
    if not isinstance(value, list) or not value:
        raise AgentError("bad_params", what)
    result = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 < item < 65536:
            raise AgentError("bad_params", what)
        result.append(item)
    return result


def address_param(system: System, params: dict) -> str:
    value = str(params.get("panelIp") or panel_address(system))
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise AgentError("bad_params", "panelIp") from exc


@fix("fail2ban.sshd")
def fix_fail2ban(system: System, params: dict) -> Plan:
    ports = int_list(params.get("sshPorts"), "sshPorts")
    panel = address_param(system, params)
    installed = system.exists("/usr/bin/fail2ban-client")
    plan = Plan("fail2ban.sshd")
    if not installed:
        plan.packages.append("fail2ban")
    if not system.exists("/usr/lib/python3/dist-packages/systemd"):
        plan.packages.append("python3-systemd")
    plan.write(
        "/etc/fail2ban/jail.d/zz-kerberos.local",
        "[DEFAULT]\n"
        f"ignoreip = 127.0.0.1/8 ::1 {panel}\n"
        "[sshd]\n"
        "enabled = true\n"
        f"port = {','.join(str(p) for p in ports)}\n"
        "backend = systemd\n"
        "maxretry = 5\n"
        "findtime = 10m\n"
        "bantime = 1h\n",
    )
    plan.run(["systemctl", "enable", "fail2ban"])
    plan.run(["systemctl", "restart", "fail2ban"])
    if installed:
        plan.undo_after.append(["systemctl", "restart", "fail2ban"])
    else:
        plan.undo_after += [["systemctl", "disable", "--now", "fail2ban"],
                            ["apt-get", "remove", "-y", "-q", "fail2ban"]]  # fmt: skip
    return plan


@fix("node_api.panel_only")
def fix_node_api(system: System, params: dict) -> Plan:
    port = int_list([params.get("port")], "port")[0]
    panel = address_param(system, params)
    remnanode = parse_remnanode(system.run(["docker", "inspect", "remnanode"]).stdout)
    if remnanode.get("network") == "bridge":
        raise AgentError("bridge_network", "remnanode publishes its port through Docker")
    family = "ip6" if ":" in panel else "ip"
    plan = Plan("node_api.panel_only")
    nft_service(plan, "node-api", "inet kerberos_node_api", [
        f"tcp dport {port} {family} saddr {panel} counter accept",
        f"tcp dport {port} counter drop",
    ], "the node API only for the panel")  # fmt: skip
    plan.details = {"port": port, "panelIp": panel}
    return plan


PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)$")


@fix("ports.drop")
def fix_ports(system: System, params: dict) -> Plan:
    wanted = []
    for item in params.get("ports") or []:
        match = PORT_RE.match(str(item))
        if not match or not 0 < int(match.group(1)) < 65536:
            raise AgentError("bad_params", "ports")
        wanted.append((int(match.group(1)), match.group(2)))
    if not wanted:
        raise AgentError("bad_params", "ports")
    published = docker_published(system.run(["docker", "ps", "--format", "{{json .}}"]).stdout)
    for sock in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout):
        if sock["process"] == "docker-proxy":
            published.add((sock["port"], sock["proto"]))
    blocked = [f"{p}/{proto}" for p, proto in wanted if (p, proto) in published]
    if blocked:
        raise AgentError("docker_published", ", ".join(blocked))
    existing = re.findall(
        r"(tcp|udp) dport (\d+) drop", system.read("/etc/kerberos/ports.nft") or ""
    )
    ports = sorted({(int(p), proto) for proto, p in existing} | set(wanted))
    rules = [f'iifname != "lo" {proto} dport {port} drop' for port, proto in ports]
    plan = Plan("ports.drop")
    nft_service(plan, "ports", "inet kerberos_ports", rules, "drop ports nobody should reach")
    plan.details = {"ports": [f"{p}/{proto}" for p, proto in wanted]}
    return plan


def ssh_reload(plan: Plan) -> None:
    plan.run(["sshd", "-t"], "sshd_test_failed")
    plan.run(["systemctl", "try-reload-or-restart", "ssh.service"])
    plan.undo_after.append(["systemctl", "try-reload-or-restart", "ssh.service"])


@fix("hostkeys.regenerate")
def fix_hostkeys(system: System, params: dict) -> Plan:
    plan = Plan("hostkeys.regenerate")
    existing = [p for p in collect_files(system, "/etc/ssh")
                if os.path.basename(p).startswith("ssh_host_")]  # fmt: skip
    for path in existing:
        plan.write(path, None)
    for name in HOST_KEY_NAMES:
        for suffix in ("", ".pub"):
            path = f"/etc/ssh/ssh_host_{name}_key{suffix}"
            if path not in plan.files:
                plan.created.append(path)
    plan.run(["ssh-keygen", "-A"])
    ssh_reload(plan)
    plan.access = True

    def new_keys(system_: System) -> dict:
        files = {p: t for p, t in collect_files(system_, "/etc/ssh", ".pub").items()
                 if os.path.basename(p).startswith("ssh_host_")}  # fmt: skip
        return {"hostKeys": host_key_facts(files)}

    plan.after = new_keys
    return plan


@fix("ssh.key_only")
def fix_key_only(system: System, params: dict) -> Plan:
    if count_admin_keys(system.read(AUTHORIZED_KEYS) or "") == 0:
        raise AgentError("no_admin_key", "no key of the administrator besides KERBEROS")
    kept = [line for line in (system.read(SSHD_CONF) or "").splitlines()
            if line.split(" ", 1)[0].lower() == "port"]  # fmt: skip
    lines = ["PasswordAuthentication no", "KbdInteractiveAuthentication no",
             "PermitRootLogin prohibit-password", *kept]  # fmt: skip
    plan = Plan("ssh.key_only")
    plan.write(SSHD_CONF, "\n".join(lines) + "\n")
    ssh_reload(plan)
    plan.access = True
    return plan


SOCKET_DROPIN = "/etc/systemd/system/ssh.socket.d/zz-kerberos.conf"
SSHD_MAIN = "/etc/ssh/sshd_config"
JAIL_FILE = "/etc/fail2ban/jail.d/zz-kerberos.local"


def socket_listen(text: str) -> list:
    """Addresses of `systemctl show ssh.socket -p Listen`: [("0.0.0.0", 22), ("[::]", 22)]."""
    found = []
    for match in re.finditer(r"(\[[^\]]*\]|[0-9.]+|\*)?:(\d+) \(Stream\)", text or ""):
        host = match.group(1) or ""
        item = (host, int(match.group(2)))
        if item not in found:
            found.append(item)
    return found


def socket_dropin(hosts: list, ports: list) -> str:
    lines = ["[Socket]", "ListenStream="]
    for port in ports:
        for host in hosts:
            lines.append(f"ListenStream={host}:{port}" if host else f"ListenStream={port}")
    return "\n".join(lines) + "\n"


def with_ports(text: str, ports: list) -> str:
    """Our sshd file: other lines as they are, Port lines for `ports`."""
    kept = [line for line in (text or "").splitlines() if line.split(" ", 1)[0].lower() != "port"]
    return "\n".join(kept + [f"Port {p}" for p in ports]) + "\n"


def comment_ports(text: str) -> str:
    lines = []
    for line in (text or "").splitlines():
        if re.match(r"^\s*Port\s+\d+", line, re.I):
            line = f"# {line.strip()}  # KERBEROS: the port lives in sshd_config.d"
        lines.append(line)
    return "\n".join(lines) + "\n"


def jail_ports(text: str, ports: list) -> str:
    joined = ",".join(str(p) for p in ports)
    return re.sub(r"(?m)^port\s*=.*$", f"port = {joined}", text)


@fix("ssh.port")
def fix_ssh_port(system: System, params: dict) -> Plan:
    port = int_list([params.get("port")], "port")[0]
    if port < 1024:
        raise AgentError("bad_params", "port")
    if any(s["port"] == port for s in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout)):
        raise AgentError("port_busy", str(port))
    plan = Plan("ssh.port")
    plan.access = True
    if parse_ufw(system.run(["ufw", "status", "verbose"]).stdout)["state"] == "active":
        plan.run(["ufw", "allow", f"{port}/tcp"])
        plan.undo_after.append(["ufw", "delete", "allow", f"{port}/tcp"])
    socket = system.run(["systemctl", "is-active", "ssh.socket"]).stdout.strip() == "active"
    listen = socket_listen(system.run(["systemctl", "show", "ssh.socket", "-p", "Listen"]).stdout)
    if socket and listen:
        old = sorted({p for _host, p in listen})
        hosts = list(dict.fromkeys(host for host, _p in listen)) or ["0.0.0.0", "[::]"]
        plan.write(SOCKET_DROPIN, socket_dropin(hosts, old + [port]))
        plan.run(["systemctl", "daemon-reload"])
        plan.run(["systemctl", "restart", "ssh.socket"])
        plan.on_confirm(SOCKET_DROPIN, socket_dropin(hosts, [port]))
        plan.on_confirm(argv=["systemctl", "daemon-reload"])
        plan.on_confirm(argv=["systemctl", "restart", "ssh.socket"])
        plan.undo_after += [["systemctl", "daemon-reload"], ["systemctl", "restart", "ssh.socket"]]
    else:
        old = parse_sshd_t(system.run(["sshd", "-T"]).stdout).get("port") or [22]
        current = system.read(SSHD_CONF) or ""
        plan.write(SSHD_CONF, with_ports(current, old + [port]))
        ssh_reload(plan)
        plan.on_confirm(SSHD_CONF, with_ports(current, [port]))
        main = system.read(SSHD_MAIN)
        if main is not None and re.search(r"(?m)^\s*Port\s+\d+", main, re.I):
            plan.on_confirm(SSHD_MAIN, comment_ports(main))
        plan.on_confirm(argv=["sshd", "-t"], code="sshd_test_failed")
        plan.on_confirm(argv=["systemctl", "try-reload-or-restart", "ssh.service"])
    jail = system.read(JAIL_FILE)
    if jail is not None:
        plan.write(JAIL_FILE, jail_ports(jail, old + [port]))
        plan.run(["systemctl", "restart", "fail2ban"])
        plan.on_confirm(JAIL_FILE, jail_ports(jail, [port]))
        plan.on_confirm(argv=["systemctl", "restart", "fail2ban"])
        plan.undo_after.append(["systemctl", "restart", "fail2ban"])
    plan.details = {"newPort": port, "oldPorts": old, "socket": bool(socket and listen)}
    return plan


# -- self-steal on the node (§10.4 step 1, §10.9) ------------------------------
SITE_CONF = "/etc/nginx/sites-enabled/kerberos-site"
ACME_ROOT = "/var/www/kerberos-acme"
SITE_ROOT = "/var/www/kerberos-site"
RENEW_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/kerberos-nginx-reload"
COMPOSE_FILE = "/opt/remnanode/docker-compose.yml"
LETSENCRYPT_VOLUME = "/etc/letsencrypt:/etc/letsencrypt:ro"

WORDS = {
    "studio": ["Design", "Craft", "Atelier", "Works", "Studio", "Lab"],
    "topics": [
        "Mountains",
        "Coffee",
        "Gardens",
        "Bicycles",
        "Old maps",
        "Bread",
        "Jazz",
        "Pottery",
    ],
    "items": ["Notebook", "Lamp", "Mug", "Backpack", "Poster", "Candle", "Scarf", "Bottle"],
    "roles": ["photographer", "translator", "architect", "illustrator", "editor", "engineer"],
}

# Four stub sites with different HTML structure: two nodes never look alike.
SITE_LAYOUTS = (
    """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name} {w0}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{css}</style></head>
<body><header><h1>{name} {w0}</h1><nav><a href="#work">Work</a> <a href="#about">About</a>
<a href="#contact">Contact</a></nav></header><main><section id="work"><h2>Selected work</h2>
<article><h3>{t0}</h3><p>{p0}</p></article><article><h3>{t1}</h3><p>{p1}</p></article>
<article><h3>{t2}</h3><p>{p2}</p></article></section><section id="about"><h2>About</h2>
<p>{p3}</p></section></main><footer id="contact"><p>{name} &middot; {year}</p></footer>
</body></html>""",
    """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Notes on {t0}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{css}</style></head>
<body><div class="wrap"><h1>Notes on {t0}</h1><ul class="posts"><li><time>{d0}</time>
<a href="#">{t1}</a></li><li><time>{d1}</time><a href="#">{t2}</a></li><li><time>{d2}</time>
<a href="#">{t0} again</a></li></ul><blockquote>{p0}</blockquote><p class="small">{p1}</p>
</div></body></html>""",
    """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name} shop</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{css}</style></head>
<body><header class="bar"><strong>{name}</strong><span>Free delivery</span></header>
<div class="grid"><figure><figcaption>{i0}</figcaption><b>{price0}</b></figure><figure>
<figcaption>{i1}</figcaption><b>{price1}</b></figure><figure><figcaption>{i2}</figcaption>
<b>{price2}</b></figure><figure><figcaption>{i3}</figcaption><b>{price3}</b></figure></div>
<form><input type="email" placeholder="Your email"><button>Subscribe</button></form>
</body></html>""",
    """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>{css}</style></head>
<body><table class="card"><tr><td><h1>{name}</h1><p>{role}</p></td></tr><tr><td><dl>
<dt>Based in</dt><dd>{t0}</dd><dt>Interests</dt><dd>{t1}, {t2}</dd><dt>Mail</dt>
<dd>hello at {domain}</dd></dl></td></tr></table><p>{p0}</p></body></html>""",
)
SITE_CSS = (
    "body{{font-family:{font};margin:0 auto;max-width:{width}px;padding:24px;color:#{fg};"
    "background:#{bg}}}a{{color:#{accent}}}h1{{font-weight:{weight}}}"
)
FONTS = ("Georgia,serif", "Helvetica,Arial,sans-serif", "Verdana,sans-serif", "monospace")


def site_html(seed: int, domain: str) -> str:
    """The stub site of `seed` for `domain`: layout by seed, words by seed and domain."""
    import random

    rng = random.Random(f"{seed}:{domain}")
    pick = lambda key, n: rng.sample(WORDS[key], n)  # noqa: E731
    name = domain.split(".")[0].replace("-", " ").title()
    topics, items = pick("topics", 3), pick("items", 4)
    sentences = [
        f"We work on {rng.choice(topics).lower()} and small things that last.",
        f"Since {rng.randint(2009, 2021)} we keep it simple and slow.",
        "Write to us and we will answer within a few days.",
        f"Most of our time goes to {rng.choice(topics).lower()}.",
    ]
    css = SITE_CSS.format(
        font=rng.choice(FONTS), width=rng.choice((640, 720, 860, 960)),
        fg=rng.choice(("222", "333", "1d2a33")), bg=rng.choice(("fff", "fbf8f1", "f4f6f8")),
        accent=rng.choice(("8a3b12", "1f5fa8", "2e7d32")), weight=rng.choice((400, 600, 700)),
    )  # fmt: skip
    values = {
        "name": name, "domain": domain, "css": css, "w0": rng.choice(WORDS["studio"]),
        "t0": topics[0], "t1": topics[1], "t2": topics[2], "role": rng.choice(WORDS["roles"]),
        "i0": items[0], "i1": items[1], "i2": items[2], "i3": items[3],
        "year": rng.randint(2022, 2026),
    }  # fmt: skip
    for i in range(4):
        values[f"p{i}"] = sentences[i]
        values[f"price{i}"] = f"{rng.randint(9, 89)}.00"
    for i in range(3):
        values[f"d{i}"] = f"2026-{rng.randint(1, 11):02d}-{rng.randint(1, 28):02d}"
    return SITE_LAYOUTS[seed % len(SITE_LAYOUTS)].format(**values)


def nginx_site(domain: str, with_tls: bool) -> str:
    acme = (
        "server {\n"
        "    listen 80;\n"
        "    listen [::]:80;\n"
        f"    server_name {domain};\n"
        f"    location /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}\n"
        "    location / { return 301 https://$host$request_uri; }\n"
        "}\n"
    )
    if not with_tls:
        return acme
    return acme + (
        "server {\n"
        "    listen 127.0.0.1:8445 ssl http2;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
        f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        f"    root {SITE_ROOT};\n"
        "    index index.html;\n"
        "    location / { try_files $uri $uri/ =404; }\n"
        "}\n"
    )


def domain_param(params: dict) -> str:
    domain = str(params.get("domain", "")).lower().rstrip(".")
    if not DOMAIN.match(domain):
        raise AgentError("bad_params", "domain")
    return domain


@fix("self_steal.site")
def fix_site(system: System, params: dict) -> Plan:
    domain = domain_param(params)
    seed = params.get("siteSeed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 1000:
        raise AgentError("bad_params", "siteSeed")
    on80 = [s for s in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout)
            if s["port"] == 80 and s["proto"] == "tcp"]  # fmt: skip
    if any(s["process"] != "nginx" for s in on80):
        raise AgentError("port80_busy", ", ".join(s["process"] or "?" for s in on80))
    had_nginx = system.exists("/usr/sbin/nginx")
    plan = Plan("self_steal.site")
    if not had_nginx:
        plan.packages.append("nginx")
    if not system.exists("/usr/bin/certbot"):
        plan.packages.append("certbot")
    html = site_html(seed, domain)
    plan.step_write(f"{ACME_ROOT}/.kerberos", "acme webroot of KERBEROS\n")
    plan.step_write(SITE_CONF, nginx_site(domain, with_tls=False))
    plan.step_run(["nginx", "-t"], "nginx_test_failed")
    plan.step_run(["systemctl", "enable", "nginx"])
    plan.step_run(["systemctl", "reload-or-restart", "nginx"])
    plan.step_run(["certbot", "certonly", "--webroot", "-w", ACME_ROOT, "-d", domain,
                   "--register-unsafely-without-email", "--agree-tos", "--non-interactive",
                   "--keep-until-expiring"], "certbot_failed", timeout=300)  # fmt: skip
    plan.step_write(f"{SITE_ROOT}/index.html", html)
    plan.step_write(SITE_CONF, nginx_site(domain, with_tls=True))
    # Renewal reloads nginx only: Xray rereads certificates itself every hour.
    plan.step_write(RENEW_HOOK, "#!/bin/sh\nsystemctl reload nginx\n", 0o755)
    plan.step_run(["nginx", "-t"], "nginx_test_failed")
    plan.step_run(["systemctl", "reload", "nginx"])
    plan.undo_after.append(["systemctl", "reload-or-restart", "nginx"])
    if not had_nginx:
        plan.undo_after.append(["systemctl", "disable", "--now", "nginx"])
    plan.details = {"domain": domain, "template": template_hash(html), "siteSeed": seed}
    return plan


def add_volume(text: str, service: str, volume: str) -> str:
    """Add a volume to one service of a compose file, keeping its indentation."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.match(rf"^(\s+){re.escape(service)}:\s*$", line)), None)  # fmt: skip
    if start is None:
        raise AgentError("bad_params", f"service {service} not in the compose file")
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if (
            stripped
            and not stripped.startswith("#")
            and len(lines[i]) - len(lines[i].lstrip()) <= indent
        ):
            end = i
            break
    block = range(start + 1, end)
    child = next((len(lines[i]) - len(lines[i].lstrip()) for i in block if lines[i].strip()),
                 indent + 2)  # fmt: skip
    key = next((i for i in block if re.match(rf"^\s{{{child}}}volumes:\s*$", lines[i])), None)
    if key is None:
        insert = [f"{' ' * child}volumes:", f"{' ' * (child + 2)}- {volume}"]
        return "\n".join(lines[:end] + insert + lines[end:]) + "\n"
    items = []
    for i in range(key + 1, end):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(lines[i]) - len(lines[i].lstrip()) <= child:
            break  # the next key of the service: the volumes list is over
        if stripped.startswith("- "):
            items.append(i)
    item_indent = (len(lines[items[0]]) - len(lines[items[0]].lstrip())) if items else child + 2
    after = (items[-1] if items else key) + 1
    return "\n".join(lines[:after] + [f"{' ' * item_indent}- {volume}"] + lines[after:]) + "\n"


@fix("node.letsencrypt_mount")
def fix_mount(system: System, params: dict) -> Plan:
    text = system.read(COMPOSE_FILE)
    if text is None:
        raise AgentError("bad_params", f"no {COMPOSE_FILE}")
    plan = Plan("node.letsencrypt_mount")
    if "/etc/letsencrypt" in text:
        return plan
    plan.write(COMPOSE_FILE, add_volume(text, "remnanode", LETSENCRYPT_VOLUME))
    plan.run(["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"])
    plan.undo_after.append(["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"])
    return plan


KEY_LINE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com)"
    r" [A-Za-z0-9+/=]{16,}( [\x20-\x7e]{0,200})?$"
)


@fix("access.admin_keys")
def fix_admin_keys(system: System, params: dict) -> Plan:
    keys = params.get("keys")
    if (
        not isinstance(keys, list)
        or not keys
        or not all(isinstance(k, str) and KEY_LINE.match(k.strip()) for k in keys)
    ):
        raise AgentError("bad_params", "keys")
    current = system.read(AUTHORIZED_KEYS) or ""
    lines = current.splitlines()
    blobs = {
        line.split()[1] for line in lines if len(line.split()) > 1 and not line.startswith("#")
    }
    blobs |= {w for line in lines for w in line.split() if len(w) > 40}
    added = [k.strip() for k in keys if k.split()[1] not in blobs]
    plan = Plan("access.admin_keys")
    if added:
        plan.write(AUTHORIZED_KEYS, "\n".join(lines + added) + "\n", 0o600)
    plan.details = {"added": len(added)}
    return plan


# -- commands ---------------------------------------------------------------
def cmd_version(system: System, args: list[str], data: Any) -> dict:
    return {
        "protocol": PROTOCOL,
        "agent": AGENT_VERSION,
        "sha256": sha256_bytes(own_source(system)),
    }


VERSION_RE = re.compile(rb'^AGENT_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.M)


def cmd_update(system: System, args: list[str], data: bytes) -> dict:
    expected = args[0]
    if sha256_bytes(data) != expected:
        raise AgentError("sha_mismatch", "the new agent file does not match its sha256")
    match = VERSION_RE.search(data)
    if not match:
        raise AgentError("bad_params", "the new file is not a KERBEROS agent")
    system.write_bytes(AGENT_PATH, data, 0o755)
    if sha256_bytes(system.read_bytes(AGENT_PATH) or b"") != expected:
        raise AgentError("sha_mismatch", "the written agent differs from the sent one")
    return {"agent": match.group(1).decode()}


# name -> (handler, argument patterns, stdin: None | "json" | "bytes")
COMMANDS: dict[str, tuple[Callable[[System, list[str], Any], dict], tuple, Optional[str]]] = {
    "version": (cmd_version, (), None),
    "facts": (cmd_facts, (), None),
    "watch": (cmd_watch, (), None),
    "site-check": (cmd_site_check, (), "json"),
    "edge-sources": (cmd_edge_sources, (), "json"),
    "plan": (cmd_plan, (FIX_ID,), "json"),
    "apply": (cmd_apply, (FIX_ID, CHANGE_ID), "json"),
    "confirm": (cmd_confirm, (CHANGE_ID,), None),
    "rollback": (cmd_rollback, (CHANGE_ID,), None),
    "update": (cmd_update, (SHA256,), "bytes"),
}


def dispatch(system: System, words: list[str], stdin: bytes) -> dict:
    if not words:
        raise AgentError("unknown_command", "no command")
    name, args = words[0], words[1:]
    if name not in COMMANDS:
        raise AgentError("unknown_command", name)
    handler, patterns, stdin_kind = COMMANDS[name]
    if len(args) != len(patterns) or not all(p.match(a) for p, a in zip(patterns, args)):
        raise AgentError("bad_params", f"{name} expects {len(patterns)} valid arguments")
    data: Any = None
    if stdin_kind == "bytes":
        data = stdin
    elif stdin_kind == "json":
        try:
            data = json.loads(stdin.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentError("bad_params", "stdin is not JSON") from exc
        if not isinstance(data, dict):
            raise AgentError("bad_params", "stdin must be a JSON object")
    return handler(system, args, data)


def command_words(argv: list[str], environ: dict) -> list[str]:
    if argv:
        return list(argv)
    try:
        return shlex.split(environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError as exc:
        raise AgentError("bad_params", "cannot parse the command") from exc


def main(
    argv: Optional[list[str]] = None,
    system: Optional[System] = None,
    stdin: Optional[bytes] = None,
    out: Any = None,
) -> int:
    system = system or System()
    out = out or sys.stdout
    argv = sys.argv[1:] if argv is None else argv
    try:
        words = command_words(argv, system.environ)
        needs_stdin = bool(words) and COMMANDS.get(words[0], (None, (), None))[2] is not None
        if stdin is None:
            stdin = sys.stdin.buffer.read() if needs_stdin else b""
        answer = dispatch(system, words, stdin)
    except AgentError as exc:
        out.write(json.dumps({"error": {"code": exc.code, "message": exc.message}}) + "\n")
        return 1
    out.write(json.dumps(answer, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

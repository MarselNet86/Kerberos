"""The portal in front of the panel (tech.md §10.10).

Remnawave behind Caddy in Docker (the scheme of the Remnawave docs) gets a
caddy-security login portal at a secret path: subscriptions and API requests
with a token pass by it, everything else waits for the portal login. 3x-ui
gets its own protection: a random port and a secret path, set with its CLI;
only its web server restarts, Xray keeps running.

Both change how the person reaches the panel's web UI, so after switching
KERBEROS checks the panel from this server and asks the person to log in at
the new link from their browser; no login, or no answer for 180 s, puts
everything back. Parsing, building the new Caddyfile and editing compose are
pure functions; the runners talk to the server through the Host port.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import random
import re
import string
import uuid
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from kerberos.fixes.journal import iso
from kerberos.fixes.model import ROLLBACK_FAILED, Change
from kerberos.fixes.panel_changes import load_snapshot, save_snapshot
from kerberos.panel.errors import PanelError

PORTAL_FIXES = ("panel.portal", "xui.panel_hide")
# caddy:2.9.1 with caddy-security 1.1.27 (github.com/remnawave/caddy-with-auth); the same
# image as `latest` when K15 was written.
IMAGE = "remnawave/caddy-with-auth:0.0.1"
ENV_FILE = "kerberos-portal.env"
IN_CONTAINER = "/etc/caddy/Caddyfile"
ROUTE_LENGTH = 18
ROUTE_CHARS = string.ascii_lowercase + string.digits
# The local identity store of caddy-security: usernames of 3-50 lowercase letters and
# digits, passwords of 8-128 characters. The env file is read by compose and by
# `docker run`, which treat quotes, `$` and `#` differently: the password leaves them out.
LOGIN_RE = re.compile(r"[a-z0-9]{3,50}")
PASSWORD_RE = re.compile(r"[A-Za-z0-9!%&()*+,\-./:;<=>?@\[\]^_{|}~]{8,128}")
TOKEN_LIFETIME = 3600
CHECK_ATTEMPTS = 6
CHECK_PAUSE = 5
LOGIN_WAIT = 180
COMPOSE_TIMEOUT = 600
# A Caddyfile with any of these has a barrier already: KERBEROS leaves it alone.
BARRIER = re.compile(
    r"^[ \t]*(security|authenticate|authorize|forward_auth|basic_?auth)\b", re.M | re.I
)
KEPT_DIRECTIVES = ("encode", "header", "log")


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_route(rng: random.Random) -> str:
    return "".join(rng.choice(ROUTE_CHARS) for _ in range(ROUTE_LENGTH))


# -- Caddyfile --------------------------------------------------------------------
@dataclass
class Block:
    head: str  # the text before `{`: comments, addresses; "" for the global options
    body: str
    start: int  # where the head starts
    end: int  # after the closing brace

    @property
    def body_start(self) -> int:
        return self.end - len(self.body) - 1


def split_blocks(text: str) -> Optional[list[Block]]:
    """Top-level blocks; None for a file this parser does not follow (unbalanced, text
    outside blocks). Comments, quotes and placeholders like `{$VAR}` are skipped."""
    blocks: list[Block] = []
    depth, i, head_start, open_at = 0, 0, 0, -1
    quote: Optional[str] = None
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "`"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t\r\n"):
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline
            continue
        elif ch == "{":
            close = text.find("}", i)
            if (
                i + 1 < len(text)
                and text[i + 1] not in " \t\r\n"
                and close > i
                and ("\n" not in text[i:close])
            ):
                i = close + 1  # a placeholder: {$VAR}, {host}, {http.request.uri}
                continue
            if depth == 0:
                open_at = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                blocks.append(Block(text[head_start:open_at], text[open_at + 1 : i],
                                    head_start, i + 1))  # fmt: skip
                head_start = i + 1
        i += 1
    if depth or quote or uncommented(text[head_start:]).strip():
        return None
    return blocks


def strip_comment(line: str) -> str:
    """The line without its comment: `#` starts one only at the start of a token and
    outside quotes, so `header X "a#b"` keeps its value."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ('"', "`"):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def uncommented(text: str) -> str:
    return "\n".join(strip_comment(line) for line in text.splitlines())


def addresses(head: str) -> list[str]:
    return [a for a in re.split(r"[\s,]+", uncommented(head).strip()) if a]


def site_name(address: str) -> str:
    name = re.sub(r"^[a-z]+://", "", address.lower()).rstrip("/")
    return re.sub(r":(443|80)$", "", name)


def has_barrier(text: str) -> bool:
    return bool(BARRIER.search(uncommented(text)))


def panel_block(blocks: list[Block], domain: str) -> Optional[Block]:
    """The one site block of the panel's domain; None when there are several (another
    scheme or port would keep the panel open past the portal)."""
    wanted = domain.lower().rstrip(".")
    found = [b for b in blocks if any(site_name(a) == wanted for a in addresses(b.head))]
    return found[0] if len(found) == 1 else None


def plain_proxy(body: str) -> Optional[tuple[str, list[str]]]:
    """(upstream, lines to keep) of a block that only proxies to the panel; None otherwise."""
    upstream, kept = None, []
    for raw in uncommented(body).splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.search(r"(^|\s)\{\s*$", line) or line.startswith("}"):
            return None  # a nested block: not the plain scheme
        words = line.split()
        if words[0] == "reverse_proxy":
            args = words[1:]
            if args and args[0] == "*":
                args = args[1:]
            if not args or args[0].startswith(("/", "@")) or upstream is not None:
                return None
            upstream = " ".join(args)
        elif words[0] in KEPT_DIRECTIVES:
            kept.append(line)
        else:
            return None
    return (upstream, kept) if upstream else None


GLOBAL_PORTAL = """\
\torder authenticate before respond
\torder authorize before respond
\tsecurity {
\t\tlocal identity store localdb {
\t\t\trealm local
\t\t\tpath USERS
\t\t}
\t\tauthentication portal kerberosportal {
\t\t\tcrypto default token lifetime {$AUTH_TOKEN_LIFETIME}
\t\t\tenable identity store localdb
\t\t\tcookie domain {$REMNAWAVE_PANEL_DOMAIN}
\t\t\tui {
\t\t\t\tlinks {
\t\t\t\t\t"Remnawave" "/dashboard/home" icon "las la-tachometer-alt"
\t\t\t\t\t"MFA" "/{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}/settings/mfa" icon "lab la-keycdn"
\t\t\t\t}
\t\t\t}
\t\t\ttransform user {
\t\t\t\tmatch origin local
\t\t\t\trequire mfa
\t\t\t\taction add role authp/admin
\t\t\t}
\t\t}
\t\tauthorization policy kerberospolicy {
\t\t\tset auth url /restricted
\t\t\tallow roles authp/admin
\t\t\twith api key auth portal kerberosportal realm local
\t\t\tacl rule {
\t\t\t\tcomment "Accept"
\t\t\t\tmatch role authp/admin
\t\t\t\tallow stop log info
\t\t\t}
\t\t\tacl rule {
\t\t\t\tcomment "Deny"
\t\t\t\tmatch any
\t\t\t\tdeny log warn
\t\t\t}
\t\t}
\t}
"""

SITE_PORTAL = """\
\t@kerberos_login path /{$REMNAWAVE_CUSTOM_LOGIN_ROUTE} /{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}/ \
/{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}/auth
\t@kerberos_token {
\t\tpath /api/*
\t\tnot path /api/auth/*
\t\theader Authorization "Bearer *"
\t}
\troute {
\t\thandle @kerberos_login {
\t\t\trewrite * /auth
\t\t\trequest_header +X-Forwarded-Prefix /{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}
\t\t\tauthenticate with kerberosportal
\t\t}
\t\thandle /{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}* {
\t\t\tauthenticate with kerberosportal
\t\t}
\t\thandle_path /restricted* {
\t\t\tabort
\t\t}
\t\thandle @kerberos_token {
\t\t\treverse_proxy UPSTREAM
\t\t}
\t\thandle /api/sub/* {
\t\t\treverse_proxy UPSTREAM
\t\t}
\t\thandle {
\t\t\tauthorize with kerberospolicy
\t\t\treverse_proxy UPSTREAM
\t\t}
\t}
"""


def portal_caddyfile(text: str, domain: str, users_path: str) -> Optional[str]:
    """The Caddyfile with the portal in front of the panel's site; None when the file is
    not the plain scheme (§10.10): then KERBEROS changes nothing."""
    blocks = split_blocks(text)
    if blocks is None or has_barrier(text):
        return None
    if re.search(r"^\s*(import|tls\s+/)", uncommented(text), re.M):
        return None  # files the validation container would not see
    glob = blocks[0] if blocks and not addresses(blocks[0].head) else None
    if glob is not None and re.search(r"^\s*(order|security)\b", uncommented(glob.body), re.M):
        return None
    site = panel_block(blocks, domain)
    if site is None or site is glob:
        return None
    plain = plain_proxy(site.body)
    if plain is None:
        return None
    upstream, kept = plain
    inner = "".join(f"\t{line}\n" for line in kept) + SITE_PORTAL.replace("UPSTREAM", upstream)
    result = text[: site.body_start] + "\n" + inner + text[site.end - 1 :]
    portal = GLOBAL_PORTAL.replace("USERS", users_path)
    if glob is not None:
        return result[: glob.body_start] + "\n" + portal + result[glob.body_start :]
    return "{\n" + portal + "}\n\n" + result.lstrip("\n")


# -- compose ----------------------------------------------------------------------
def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def compose_with_portal(text: str, service: str) -> Optional[str]:
    """compose with the Caddy service on the portal image and the env file of KERBEROS;
    None when the file is not laid out as this edit understands."""
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    top = next((i for i, line in enumerate(lines) if re.match(r"^services:\s*(#.*)?$", line)),
               None)  # fmt: skip
    if top is None:
        return None

    def meaningful(line: str) -> bool:
        return bool(line.strip()) and not line.lstrip().startswith("#")

    start = next((i for i in range(top + 1, len(lines))
                  if meaningful(lines[i]) and _indent(lines[i]) > 0), None)  # fmt: skip
    if start is None:
        return None
    level = _indent(lines[start])
    head = None
    for i in range(start, len(lines)):
        line = lines[i]
        if meaningful(line) and _indent(line) == 0:
            break
        if _indent(line) == level and re.match(rf"^\s*{re.escape(service)}:\s*(#.*)?$", line):
            head = i
            break
    if head is None:
        return None
    end = len(lines)
    for i in range(head + 1, len(lines)):
        if meaningful(lines[i]) and _indent(lines[i]) <= level:
            end = i
            break
    body = [i for i in range(head + 1, end) if meaningful(lines[i])]
    if not body:
        return None
    keys = _indent(lines[body[0]])
    pad = " " * keys
    image = next((i for i in body if re.match(rf"^{pad}image:\s*\S", lines[i])), None)
    if image is None:
        return None
    lines[image] = f"{pad}image: {IMAGE}\n"
    env = next((i for i in body if re.match(rf"^{pad}env_file:", lines[i])), None)
    if env is None:
        lines.insert(image + 1, f"{pad}env_file:\n{pad}  - {ENV_FILE}\n")
        return "".join(lines)
    value = lines[env].split(":", 1)[1].split("#", 1)[0].strip()
    if value.startswith("["):
        return None
    if value:
        if value.strip("'\"") == ENV_FILE:
            return "".join(lines)
        lines[env] = f"{pad}env_file:\n{pad}  - {value}\n{pad}  - {ENV_FILE}\n"
        return "".join(lines)
    items = []
    for i in range(env + 1, end):
        if not meaningful(lines[i]):
            continue
        compact = _indent(lines[i]) == keys and lines[i].lstrip().startswith("- ")
        if _indent(lines[i]) <= keys and not compact:
            break  # the next key of the service: the list ended
        items.append(i)
    if any(ENV_FILE in lines[i] for i in items):
        return "".join(lines)
    last = items[-1] if items else env
    item_pad = " " * (_indent(lines[items[0]]) if items else keys + 2)
    lines.insert(last + 1, f"{item_pad}- {ENV_FILE}\n")
    return "".join(lines)


def portal_env(domain: str, route: str, login: str, password: str) -> str:
    return (f"REMNAWAVE_PANEL_DOMAIN={domain}\n"
            f"REMNAWAVE_CUSTOM_LOGIN_ROUTE={route}\n"
            f"AUTHP_ADMIN_USER={login}\n"
            f"AUTHP_ADMIN_EMAIL={login}@localdomain.local\n"
            f"AUTHP_ADMIN_SECRET={password}\n"
            f"AUTH_TOKEN_LIFETIME={TOKEN_LIFETIME}\n")  # fmt: skip


def text_diff(mine: str, now: str, name: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            mine.splitlines(), now.splitlines(), f"KERBEROS {name}", f"{name} now", lineterm="", n=2
        )
    )


# -- finding the panel's Caddy (read only, S5) -----------------------------------------
def detect_caddy(host: Any, domain: Optional[str]) -> dict:
    """{proxy: none | custom | protected | caddy, ...}: what the portal fix can rely on."""
    if host is None or not domain:
        return {"proxy": "none"}
    listing = host.run(["docker", "ps", "--format", "{{json .}}"], timeout=20)
    if not listing.ok:
        return {"proxy": "none"}
    found = []
    for line in listing.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and "caddy" in str(item.get("Image", "")).lower():
            found.append(str(item.get("Names") or item.get("ID") or ""))
    if not found:
        return {"proxy": "none"}
    machine = host.run(["uname", "-m"], timeout=10)
    if machine.ok and machine.stdout.strip() not in ("x86_64", "amd64"):
        return {"proxy": "arch"}  # the image is built for amd64 only: the pull would fail
    if not host.run(["docker", "compose", "version"], timeout=20).ok:
        return {"proxy": "custom"}  # compose v1 only: KERBEROS speaks the plugin
    verdict = {"proxy": "custom"}
    for name in found:
        result = inspect_caddy(host, name, domain)
        if result["proxy"] in ("caddy", "protected"):
            return result
        verdict = result
    return verdict


def inspect_caddy(host: Any, name: str, domain: str) -> dict:
    inspect = host.run(["docker", "inspect", name], timeout=20)
    try:
        data = json.loads(inspect.stdout)[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return {"proxy": "custom"}
    caddyfile = None
    for mount in data.get("Mounts") or []:
        source, target = str(mount.get("Source") or ""), mount.get("Destination")
        if target == IN_CONTAINER:
            caddyfile = source
        elif target == "/etc/caddy" and caddyfile is None and source:
            caddyfile = str(PurePosixPath(source) / "Caddyfile")
    labels = (data.get("Config") or {}).get("Labels") or {}
    files = [f for f in str(labels.get("com.docker.compose.project.config_files") or "")
             .split(",") if f]  # fmt: skip
    found = {
        "container": name,
        "image": str((data.get("Config") or {}).get("Image") or ""),
        "caddyfile": caddyfile,
        "composeDir": labels.get("com.docker.compose.project.working_dir"),
        "composeFile": files[0] if len(files) == 1 else None,
        "project": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
    }
    text = host.read_text(caddyfile) if caddyfile else None
    if text is not None and has_barrier(text):
        return {"proxy": "protected", "container": name}
    if None in found.values() or text is None:
        return {"proxy": "custom", "container": name}
    if portal_caddyfile(text, domain, "/data/kerberos.json") is None:
        return {"proxy": "custom", "container": name}
    compose = host.read_text(found["composeFile"])
    if compose is None or compose_with_portal(compose, found["service"]) is None:
        return {"proxy": "custom", "container": name}
    return {"proxy": "caddy", **found}


# -- the change ---------------------------------------------------------------------
class StepFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def new_change(engine: Any, fix_id: str, target: str, params: dict) -> Change:
    change: Change = {
        "changeId": str(uuid.uuid4()),
        "fixId": fix_id,
        "target": target,
        "state": "applying",
        "params": params,
        "before": None,
        "details": {},
        "error": None,
        "startedAt": iso(engine.env.clock),
        "finishedAt": None,
    }
    engine.run["changes"].append(change)
    engine.save()
    return change


def page_shows_panel(page: Any) -> bool:
    """The check of panel.public: the Remnawave login page answers on the domain."""
    return page is not None and page.status == 200 and "remnawave" in (page.body or "").lower()


class Runner:
    """What both portals share: journal, steps on the board, the person's login, undo."""

    fix_id = ""
    steps = ("backup", "apply", "check", "confirm")

    def __init__(self, engine: Any, item: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.item = item
        self.host = self.env.host
        self.store = engine.store
        self.step = "backup"
        # The secret path comes from the system's secure source; the demo is repeatable.
        self.rng = random.Random(20261117) if self.env.demo else random.SystemRandom()

    def event(self, step: str, state: str, note: str = "") -> None:
        self.step = step
        self.engine.event(step, self.item, state, note)

    def run(self) -> bool:
        change = new_change(self.engine, self.fix_id, self.item.target, self.params())
        self.event("backup", "running")
        try:
            self.apply(change)
        except Exception as exc:  # noqa: BLE001 - the panel's way in is never left half changed
            code = exc.code if isinstance(exc, StepFailed) else "internal_error"
            if code == "internal_error":
                self.store.log(self.engine.run, f"{self.fix_id}: internal error "
                                                f"{type(exc).__name__}")  # fmt: skip
            error = self.undo(change)
            rolled = self.engine.settle(change, code, error)
            if rolled:
                self.engine.failed += 1
            self.event(self.step, "rolled_back" if rolled else "failed",
                       code if rolled else ROLLBACK_FAILED)  # fmt: skip
            return False
        self.engine.finish(change, "confirmed")
        self.event("confirm", "ok")
        self.done(change)
        return True

    def params(self) -> dict:
        return {}

    def apply(self, change: Change) -> None:
        raise NotImplementedError

    def undo(self, change: Change) -> Optional[str]:
        raise NotImplementedError

    def done(self, change: Change) -> None:
        """The data of the run learns what the check saw, only once all of it passed."""

    def wait_login(self, change: Change, link: str, login: Optional[str]) -> None:
        self.event("confirm", "running")
        # With masking on, the screen hides the secret path: the 0600 snapshot has it.
        if not self.engine.ask_portal(link, login, change["details"].get("linkPath", "")):
            raise StepFailed("portal_login_failed")


# -- Remnawave: caddy-security in front of the panel ----------------------------------
class PortalRemnawave(Runner):
    fix_id = "panel.portal"

    def __init__(self, engine: Any, item: Any) -> None:
        super().__init__(engine, item)
        self.data = self.session.data["input"]
        self.proxy = dict(self.data.panel_proxy or {})
        self.domain = self.session.snapshot.panel_domain or ""
        self.page: Any = None

    def address(self) -> Optional[str]:
        return next((a for a in self.data.dns.get(self.domain.lower(), []) if ":" not in a),
                    None)  # fmt: skip

    def compose(self, *args: str) -> list[str]:
        return ["docker", "compose", "--project-name", self.proxy["project"],
                "--project-directory", self.proxy["composeDir"], "-f",
                self.proxy["composeFile"], *args]  # fmt: skip

    def apply(self, change: Change) -> None:
        if self.proxy.get("proxy") != "caddy":
            raise StepFailed("portal_custom")
        creds = self.session.data.get("portal") or {}
        login, password = creds.get("login", ""), creds.get("password", "")
        if not LOGIN_RE.fullmatch(login) or not PASSWORD_RE.fullmatch(password):
            raise StepFailed("bad_params")
        address = self.address()
        # A subscription nobody has: the panel's own answer to it must pass the portal.
        self.probe = "/api/sub/" + "".join(self.rng.choice("0123456789abcdef") for _ in range(16))
        sub_before = self.env.prober.http(address, 443, self.domain, self.probe) \
            if address else None  # fmt: skip
        if sub_before is None or sub_before.status is None:
            raise StepFailed("portal_check_failed")  # the domain does not answer from here
        caddy_text = self.host.read_text(self.proxy["caddyfile"])
        compose_text = self.host.read_text(self.proxy["composeFile"])
        short = change["changeId"][:8]
        users = f"/data/.local/caddy/kerberos-{short}.json"
        new_caddy = portal_caddyfile(caddy_text or "", self.domain, users)
        new_compose = compose_with_portal(compose_text or "", self.proxy["service"])
        if caddy_text is None or compose_text is None or new_caddy is None or not new_compose:
            raise StepFailed("portal_custom")
        route = new_route(self.rng)
        env_path = str(PurePosixPath(self.proxy["composeFile"]).parent / ENV_FILE)
        run_id = self.engine.run["runId"]
        change["details"] = {
            "container": self.proxy["container"], "service": self.proxy["service"],
            "project": self.proxy["project"], "composeDir": self.proxy["composeDir"],
            "composeFiles": [self.proxy["composeFile"]], "caddyfile": self.proxy["caddyfile"],
            "envFile": env_path, "image": IMAGE,
            # The secret path lives in a 0600 snapshot, never in run.json.
            "linkPath": save_snapshot(self.store, run_id, f"portal-{short}",
                                      {"link": f"https://{self.domain}/{route}",
                                       "login": login}),
        }  # fmt: skip
        self.engine.save()
        if not self.host.run(["docker", "pull", IMAGE], timeout=COMPOSE_TIMEOUT).ok:
            raise StepFailed("image_pull_failed")
        self.host.write_text(env_path, portal_env(self.domain, route, login, password), 0o600)
        trial = self.store.path(run_id) / "panel-server" / f"Caddyfile-{short}"
        trial.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store.state.write_private(trial, new_caddy)
        checked = self.host.run(["docker", "run", "--rm", "--env-file", env_path, "-v",
                                 f"{trial}:{IN_CONTAINER}:ro", IMAGE, "caddy", "validate",
                                 "--config", IN_CONTAINER, "--adapter", "caddyfile"],
                                timeout=180)  # fmt: skip
        if not checked.ok:
            raise StepFailed("caddy_invalid")
        self.backup(change, caddy_text, compose_text)
        self.event("backup", "ok")
        self.event("apply", "running")
        change["details"]["written"] = {"caddyfile": text_digest(new_caddy),
                                        "compose": text_digest(new_compose)}  # fmt: skip
        self.engine.save()
        self.host.write_text(self.proxy["caddyfile"], new_caddy)
        self.host.write_text(self.proxy["composeFile"], new_compose)
        if not self.host.run(self.compose("config", "-q"), timeout=60).ok:
            raise StepFailed("compose_invalid")
        change["details"]["started"] = True  # from here on Caddy may run the new files
        self.engine.save()
        if not self.host.run(self.compose("up", "-d", self.proxy["service"]),
                             timeout=COMPOSE_TIMEOUT).ok:  # fmt: skip
            raise StepFailed("compose_failed")
        self.event("apply", "ok")
        self.event("check", "running")
        self.check(address, route, sub_before.status)
        self.event("check", "ok")
        self.wait_login(change, f"https://{self.domain}/{route}", login)

    def backup(self, change: Change, caddy_text: str, compose_text: str) -> None:
        run_dir = self.store.path(self.engine.run["runId"]) / "panel-server"
        short = change["changeId"][:8]
        backups = {}
        for name, path, text in (
            ("caddyfile", self.proxy["caddyfile"], caddy_text),
            ("compose", self.proxy["composeFile"], compose_text),
        ):
            copy = run_dir / f"{name}-{short}.bak"
            self.store.state.write_private(copy, text)
            backups[name] = {"path": str(copy), "mode": self.host.file_mode(path)}
        change["details"]["backups"] = backups
        self.engine.save()

    def check(self, address: str, route: str, sub_status: Optional[int]) -> None:
        """§10.10 step 4: the panel hides, the portal answers, subscriptions and token
        requests still pass; the panel's API on this server works as before."""
        token = self.env.state.read_panel_token() if self.env.state is not None else None
        for attempt in range(CHECK_ATTEMPTS):
            if attempt:
                self.env.clock.sleep(CHECK_PAUSE)
            root = self.env.prober.http(address, 443, self.domain, "/")
            # The secret path itself redirects there (checked on Caddy 2.9.1 with
            # caddy-security 1.1.27): its sign-in page answers 200.
            portal = self.env.prober.http(address, 443, self.domain, f"/{route}/auth/login")
            sub = self.env.prober.http(address, 443, self.domain, self.probe)
            api_ok = True
            if token:
                api = self.env.prober.http(
                    address,
                    443,
                    self.domain,
                    "/api/nodes",
                    headers={"Authorization": f"Bearer {token}"},
                )
                api_ok = api.status == 200
            if (root.status is not None and not page_shows_panel(root) and portal.status == 200
                    and sub.status == sub_status and api_ok):  # fmt: skip
                try:
                    self.session.panel.nodes()
                except PanelError as exc:
                    raise StepFailed("portal_check_failed") from exc
                self.page = root
                return
        raise StepFailed("portal_check_failed")

    def undo(self, change: Change) -> Optional[str]:
        return undo_portal(self.host, change, ask=self.engine.ask_undo)

    def done(self, change: Change) -> None:
        self.data.panel_page = self.page


def undo_portal(host: Any, change: Change,
                ask: Optional[Callable[[str], bool]] = None) -> Optional[str]:  # fmt: skip
    """Caddyfile and compose back from the backups, the env file away, Caddy up again.

    A file edited after KERBEROS wrote it is shown with `ask` first; without `ask`
    (the automatic undo of S8) it is left and `kerberos rollback` asks later.
    """
    details = change["details"]
    env_path = details.get("envFile")
    backups = details.get("backups") or {}
    if not backups:
        if env_path:
            host.remove(env_path)  # nothing else was written yet
        return None
    paths = {"caddyfile": details["caddyfile"], "compose": details["composeFiles"][0]}
    restore, edited = {}, []
    for name, path in paths.items():
        copy = backups.get(name) or {}
        try:
            with open(copy["path"], encoding="utf-8") as fh:
                original = fh.read()
        except (OSError, KeyError):
            return "no_backup"
        current = host.read_text(path)
        if current == original:
            continue
        written = (details.get("written") or {}).get(name)
        if current is not None and written and text_digest(current) != written:
            edited.append(text_diff(original, current, name))
        restore[name] = (path, original, copy.get("mode"))
    if edited and (ask is None or not ask("\n".join(edited))):
        return "changed_in_panel"
    for path, original, mode in restore.values():
        host.write_text(path, original, mode)
    if env_path:
        host.remove(env_path)
    if not details.get("started"):
        return None  # Caddy never restarted: it still runs the old files
    command = ["docker", "compose", "--project-name", details["project"],
               "--project-directory", details["composeDir"], "-f", paths["compose"], "up",
               "-d", details["service"]]  # fmt: skip
    return None if host.run(command, timeout=COMPOSE_TIMEOUT).ok else "compose_failed"


# -- 3x-ui: its own random port and secret path ---------------------------------------
XUI_BIN = "/usr/local/x-ui/x-ui"


def xui_hup(host: Any) -> bool:
    """Restart the panel's web server only: SIGHUP to the main process (Xray keeps running).

    `systemctl kill` would reach Xray too, a child in the same cgroup.
    """
    shown = host.run(["systemctl", "show", "-p", "MainPID", "--value", "x-ui"], timeout=20)
    pid = shown.stdout.strip()
    if not shown.ok or not pid.isdigit() or pid == "0":
        return False
    return host.run(["kill", "-HUP", pid], timeout=20).ok


def xui_setting(host: Any, info: dict, port: Optional[int], path: Optional[str]) -> bool:
    """Port and base path with the panel's own CLI, then read back: the CLI prints its
    errors yet exits with 0."""
    from kerberos.panel.discover import base_path

    argv = [XUI_BIN, "setting"]
    if port:
        argv += ["-port", str(port)]
    if path:
        argv += ["-webBasePath", path]
    if info.get("dbFolder"):
        argv = ["env", f"XUI_DB_FOLDER={info['dbFolder']}", *argv]
    host.run(argv, timeout=60)
    settings = host.read_settings(info["db"], ("webPort", "webBasePath")) or {}
    if port and str(settings.get("webPort", "")) != str(port):
        return False
    return not (path and base_path(settings.get("webBasePath", "/")) != path)


class PortalXui(Runner):
    fix_id = "xui.panel_hide"

    def __init__(self, engine: Any, item: Any) -> None:
        super().__init__(engine, item)
        self.location = self.session.location
        self.info = dict(self.location.info or {})
        parts = urlsplit(self.location.api)
        self.scheme, self.old_path = parts.scheme, parts.path or "/"
        # §7.6: 3x-ui with webDomain answers 403 to any other Host, so the link names it.
        self.address = self.location.panel_domain or self.session.snapshot.nodes[0].address

    def params(self) -> dict:
        return {"port": self.item.params.get("port")}

    def apply(self, change: Change) -> None:
        from kerberos.panel.xui import XuiClient

        if not self.info.get("db"):
            raise StepFailed("xui_setting_failed")
        port = self.item.params.get("port")
        new_path = self.old_path if self.info.get("secretPath") else (
            "/" + new_route(self.rng) + "/")  # fmt: skip
        changes_path = new_path != self.old_path
        new_port = port or self.info.get("port")
        link = f"{self.scheme}://{self.address}:{new_port}{new_path}"
        short = change["changeId"][:8]
        ufw = (self.local_facts().get("firewall") or {}).get("ufw") == "active" and bool(port)
        change["details"] = {
            "oldPort": self.info.get("port"), "newPort": new_port, "pathChanged": changes_path,
            "ufw": ufw,
            # Both paths are secrets of sorts: a 0600 snapshot, never run.json.
            "linkPath": save_snapshot(self.store, self.engine.run["runId"], f"xui-panel-{short}",
                                      {"link": link, "oldPath": self.old_path,
                                       "newPath": new_path, "db": self.info["db"],
                                       "dbFolder": self.info.get("dbFolder", "")}),
        }  # fmt: skip
        self.engine.save()
        self.event("backup", "ok")
        self.event("apply", "running")
        if not xui_setting(self.host, self.info, port, new_path if changes_path else None):
            raise StepFailed("xui_setting_failed")
        if ufw and not self.host.run(["ufw", "allow", f"{port}/tcp"], timeout=60).ok:
            raise StepFailed("command_failed")
        if not xui_hup(self.host):
            raise StepFailed("xui_restart_failed")
        self.event("apply", "ok")
        self.event("check", "running")
        new_api = f"{self.scheme}://{urlsplit(self.location.api).hostname}:{new_port}{new_path}"
        client = XuiClient(new_api, self.env.xui_transport, self.env.clock,
                           self.location.panel_domain)  # fmt: skip
        client.csrf = getattr(self.session.panel, "csrf", None)
        for attempt in range(CHECK_ATTEMPTS):
            if attempt:
                self.env.clock.sleep(CHECK_PAUSE)
            try:
                client.inbounds()
                break
            except PanelError:
                continue
        else:
            raise StepFailed("portal_check_failed")
        self.event("check", "ok")
        self.new_api = new_api
        self.new_port = new_port
        self.wait_login(change, link, None)

    def local_facts(self) -> dict:
        data = self.session.data["input"]
        node = data.nodes[0] if data.nodes else None
        return (node.facts or {}) if node else {}

    def undo(self, change: Change) -> Optional[str]:
        return undo_xui_hide(self.host, change)

    def done(self, change: Change) -> None:
        """KERBEROS goes on at the new address: the score after reads the panel there."""
        from kerberos.panel.discover import discover_xui

        self.session.panel.base = self.new_api
        found = discover_xui(self.host)
        if found is not None:
            self.session.location = found
        old = self.info.get("port")
        for socket in self.local_facts().get("listening") or []:
            if socket.get("port") == old and socket.get("proto") == "tcp":
                socket["port"] = self.new_port


def undo_xui_hide(host: Any, change: Change) -> Optional[str]:
    """The old port and path with the same CLI, the ufw rule away, the web server again."""
    details = change["details"]
    saved = load_snapshot(details.get("linkPath"))
    if not saved:
        return None  # nothing was written yet
    info = {"db": saved["db"], "dbFolder": saved.get("dbFolder", "")}
    port = details.get("oldPort") if details.get("oldPort") != details.get("newPort") else None
    path = saved["oldPath"] if details.get("pathChanged") else None
    if not xui_setting(host, info, port, path):
        return "xui_setting_failed"
    if details.get("ufw"):
        host.run(["ufw", "delete", "allow", f"{details['newPort']}/tcp"], timeout=60)
    return None if xui_hup(host) else "xui_restart_failed"


def undo_change(host: Any, change: Change,
                ask: Optional[Callable[[str], bool]] = None) -> Optional[str]:  # fmt: skip
    """`kerberos rollback` of a portal change."""
    if change["fixId"] == "panel.portal":
        return undo_portal(host, change, ask)
    return undo_xui_hide(host, change)


def run_portal(engine: Any, item: Any) -> bool:
    kind = PortalXui if item.fix_id == "xui.panel_hide" else PortalRemnawave
    return kind(engine, item).run()

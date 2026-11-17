"""Caddy in Docker in front of the demo panel, as the Remnawave docs set it up (§10.10).

Its answers on the panel's domain follow what `docker compose up` last started: the
Remnawave login page, or the caddy-security portal at the secret path.
"""

from __future__ import annotations

import json

from kerberos.fixes.portal import ENV_FILE, IMAGE
from kerberos.host import CommandResult, parse_env_keys
from kerberos.probe import HttpResult

DOMAIN = "panel.example.com"
PANEL_IP = "198.51.100.5"
CADDY_DIR = "/opt/remnawave/caddy"
CADDYFILE = f"{CADDY_DIR}/Caddyfile"
COMPOSE = f"{CADDY_DIR}/docker-compose.yml"
ENV_PATH = f"{CADDY_DIR}/{ENV_FILE}"

CADDY_TEXT = """\
https://panel.example.com {
\treverse_proxy * http://remnawave:3000
}

https://sub.example.com {
\treverse_proxy * http://remnawave-subscription-page:3010
}

:443 {
\ttls internal
\trespond 204
}
"""

COMPOSE_TEXT = """\
services:
    caddy:
        image: caddy:2.9
        container_name: 'caddy'
        hostname: caddy
        restart: always
        ports:
            - '0.0.0.0:443:443'
            - '0.0.0.0:80:80'
        networks:
            - remnawave-network
        volumes:
            - ./Caddyfile:/etc/caddy/Caddyfile
            - caddy-ssl-data:/data

networks:
    remnawave-network:
        name: remnawave-network
        driver: bridge
        external: true

volumes:
    caddy-ssl-data:
        driver: local
        external: false
        name: caddy-ssl-data
"""

INSPECT = [{
    "Config": {
        "Image": "caddy:2.9",
        "Labels": {
            "com.docker.compose.project": "caddy",
            "com.docker.compose.project.working_dir": CADDY_DIR,
            "com.docker.compose.project.config_files": COMPOSE,
            "com.docker.compose.service": "caddy",
        },
    },
    "Mounts": [
        {"Type": "bind", "Source": CADDYFILE, "Destination": "/etc/caddy/Caddyfile"},
        {"Type": "volume", "Source": "caddy-ssl-data", "Destination": "/data"},
    ],
}]  # fmt: skip


class FakeCaddy:
    def __init__(self, host, prober, *, caddyfile: str = CADDY_TEXT, fail=()) -> None:
        self.host = host
        # "pull", "validate", "config", "up"; "ignore": up changes nothing; "leak": the portal
        # answers, yet the domain's root still shows the panel
        self.fail = set(fail)
        self.portal = False
        self.route = None
        self.ups = 0
        self.commands: list = []
        host.files[CADDYFILE] = caddyfile
        host.files[COMPOSE] = COMPOSE_TEXT
        listing = host.commands[("docker", "ps")].stdout
        mine = json.dumps({"ID": "d4e5f6a1b2c3", "Image": "caddy:2.9", "Names": "caddy"})
        host.on(["docker", "ps"], CommandResult(0, listing + mine + "\n"))
        host.on(["docker", "inspect", "caddy"], CommandResult(0, json.dumps(INSPECT)))
        host.on(["docker", "pull"], self.answer("pull"))
        host.on(["docker", "run"], self.answer("validate"))
        host.on(["docker", "compose"], self.compose)
        prober.responder = self.respond

    def answer(self, what):
        def respond(argv, _stdin):
            self.commands.append(tuple(argv))
            return CommandResult(1, "", f"{what} failed") if what in self.fail else CommandResult(0)

        return respond

    def compose(self, argv, _stdin):
        self.commands.append(tuple(argv))
        if "config" in argv:
            return CommandResult(1 if "config" in self.fail else 0)
        if "up" in argv:
            self.ups += 1
            if "up" in self.fail:
                return CommandResult(1, "", "up failed")
            if "ignore" in self.fail:
                return CommandResult(0)
            text = self.host.files.get(CADDYFILE, "")
            compose = self.host.files.get(COMPOSE, "")
            env = parse_env_keys(
                self.host.files.get(ENV_PATH, ""), ["REMNAWAVE_CUSTOM_LOGIN_ROUTE"]
            )
            self.portal = "authenticate with" in text and IMAGE in compose and ENV_FILE in compose
            self.route = env.get("REMNAWAVE_CUSTOM_LOGIN_ROUTE") if self.portal else None
            return CommandResult(0)
        return CommandResult(0)

    def respond(self, ip, port, host, path, headers):
        if (ip, port, host) != (PANEL_IP, 443, DOMAIN):
            return None
        token = headers.get("Authorization", "").startswith("Bearer ")
        if path.startswith("/api/sub/"):
            return HttpResult(404, {}, '{"message":"Not found"}')
        if path.startswith("/api/") and token:
            return HttpResult(200, {}, '{"response":[]}')
        if not self.portal or (path == "/" and "leak" in self.fail):
            if path == "/":
                return HttpResult(200, {}, "<html><head><title>Remnawave</title></head></html>")
            return HttpResult(401 if path.startswith("/api/") else 404, {}, "")
        if self.route and path == f"/{self.route}/auth/login":
            return HttpResult(200, {}, "<title>Authentication Portal - Sign In</title>")
        if self.route and path in (f"/{self.route}", f"/{self.route}/", f"/{self.route}/auth"):
            return HttpResult(302, {"location": f"/{self.route}/auth/login"}, "")
        return HttpResult(302, {"location": "/restricted"}, "")

"""Finding Remnawave on this server (tech.md §7.1).

`docker ps` finds the container of the `remnawave/backend` image, `docker
inspect` gives its published API port and the compose directory, the
version comes from /opt/app/package.json inside the container (else from
the image tag). From the panel's .env only APP_PORT and PANEL_DOMAIN are
read: the other values of that file are secrets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from kerberos.host import Host

IMAGE = "remnawave/backend"
DEFAULT_PORT = 3000


@dataclass
class PanelLocation:
    api: str
    version: str
    container: str = ""
    panel_domain: Optional[str] = None


def _image_tag(image: str) -> str:
    name, _, tag = image.rpartition(":")
    return tag if name and "/" not in tag else ""


def _bind_ip(ip: str) -> str:
    return "127.0.0.1" if ip in ("", "0.0.0.0", "::", "[::]") else ip


def discover(host: Host) -> Optional[PanelLocation]:
    ps = host.run(["docker", "ps", "--format", "{{json .}}"], timeout=20)
    if not ps.ok:
        return None
    container = image = ""
    for line in ps.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and IMAGE in str(item.get("Image", "")):
            container = str(item.get("Names") or item.get("ID") or "")
            image = str(item["Image"])
            break
    if not container:
        return None
    inspect = host.run(["docker", "inspect", container], timeout=20)
    try:
        data = json.loads(inspect.stdout)[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return None
    labels = (data.get("Config") or {}).get("Labels") or {}
    workdir = labels.get("com.docker.compose.project.working_dir")
    env = (
        host.read_env_keys(workdir.rstrip("/") + "/.env", ["APP_PORT", "PANEL_DOMAIN"])
        if workdir
        else {}
    )
    try:
        app_port = int(env.get("APP_PORT") or DEFAULT_PORT)
    except ValueError:
        app_port = DEFAULT_PORT
    settings = data.get("NetworkSettings") or {}
    mode = (data.get("HostConfig") or {}).get("NetworkMode") or ""
    address: Optional[str] = None
    if mode == "host":
        address = f"127.0.0.1:{app_port}"
    else:
        for binding in (settings.get("Ports") or {}).get(f"{app_port}/tcp") or []:
            if binding.get("HostPort"):
                address = f"{_bind_ip(binding.get('HostIp', ''))}:{binding['HostPort']}"
                break
        if address is None:
            for network in (settings.get("Networks") or {}).values():
                if network.get("IPAddress"):
                    address = f"{network['IPAddress']}:{app_port}"
                    break
    if address is None:
        return None
    version = _image_tag(image)
    package = host.run(["docker", "exec", container, "cat", "/opt/app/package.json"], timeout=20)
    if package.ok:
        try:
            version = str(json.loads(package.stdout).get("version") or version)
        except ValueError:
            pass
    domain = env.get("PANEL_DOMAIN") or None
    return PanelLocation(
        api=f"http://{address}/api",
        version=version or "?",
        container=container,
        panel_domain=domain,
    )

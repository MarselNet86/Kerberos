"""A 3x-ui server as a panel snapshot (tech.md §7.6). Pure functions.

3x-ui runs on the server it protects: one node, this server. Its inbounds
become one profile; every inbound also stands for the host clients connect
to, because 3x-ui builds client links from the inbound itself. The checks
then read 3x-ui the same way as Remnawave; the ones about hosts, templates,
squads and reserves are Remnawave-only.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from kerberos.panel.errors import PanelError
from kerberos.panel.model import Host, Inbound, Node, PanelSnapshot, Profile

LOCAL = "local"  # the uuid of the one node: this server
PROFILE = "3x-ui"
UDP = {"hysteria", "hysteria2", "wireguard"}


def _bad(what: str) -> PanelError:
    return PanelError("bad_response", detail=what)


def _json(value: Any, what: str) -> dict:
    """3x-ui keeps settings, streamSettings and sniffing as JSON strings."""
    if value in (None, ""):
        return {}
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise _bad(f"{what} is not JSON")
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        raise _bad(f"{what} is not JSON") from exc
    if not isinstance(parsed, dict):
        raise _bad(f"{what} is not an object")
    return parsed


def inbound(raw: Any) -> dict:
    """One inbound of /panel/api/inbounds/list, checked and with its JSON parsed."""
    if not isinstance(raw, dict):
        raise _bad("inbound is not an object")
    ident, port = raw.get("id"), raw.get("port")
    if isinstance(ident, bool) or not isinstance(ident, int):
        raise _bad("inbound id")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise _bad("inbound port")
    protocol = raw.get("protocol")
    if not isinstance(protocol, str) or not protocol:
        raise _bad("inbound protocol")
    return {
        "id": ident,
        "remark": str(raw.get("remark") or ""),
        "enable": raw.get("enable", True) is not False,
        "listen": str(raw.get("listen") or ""),
        "port": port,
        "protocol": protocol,
        "tag": str(raw.get("tag") or f"inbound-{port}"),
        "settings": _json(raw.get("settings"), "settings"),
        "streamSettings": _json(raw.get("streamSettings"), "streamSettings"),
        "sniffing": _json(raw.get("sniffing"), "sniffing"),
        "raw": raw,
    }


def client_sni(stream: dict) -> str:
    """The server name a client link of this inbound carries."""
    reality = stream.get("realitySettings")
    if isinstance(reality, dict):
        settings = reality.get("settings") if isinstance(reality.get("settings"), dict) else {}
        names = [n for n in reality.get("serverNames") or [] if isinstance(n, str) and n]
        return str(settings.get("serverName") or (names[0] if names else ""))
    tls = stream.get("tlsSettings")
    return str(tls.get("serverName") or "") if isinstance(tls, dict) else ""


def client_fingerprint(stream: dict) -> str:
    for key in ("realitySettings", "tlsSettings"):
        block = stream.get(key)
        if isinstance(block, dict) and isinstance(block.get("settings"), dict):
            return str(block["settings"].get("fingerprint") or "")
    return ""


def snapshot(
    version: str,
    inbounds: list[dict],
    address: str,
    name: str,
    info: dict,
    panel_domain: Optional[str] = None,
    online: int = 0,
) -> PanelSnapshot:
    """`inbounds` as `inbound()` returns them; `address`: the public IPv4 of this server."""
    models, configs, hosts, ports = [], [], [], []
    for item in inbounds:
        uuid = f"xui-{item['id']}"
        stream = item["streamSettings"]
        configs.append({
            "tag": item["tag"],
            "listen": item["listen"] or None,
            "port": item["port"],
            "protocol": item["protocol"],
            "settings": item["settings"],
            "streamSettings": stream,
            "sniffing": item["sniffing"],
        })  # fmt: skip
        models.append(Inbound(uuid=uuid, tag=item["tag"], type=item["protocol"],
                              network=stream.get("network"), security=stream.get("security"),
                              port=item["port"], profile_uuid=PROFILE))  # fmt: skip
        hosts.append(Host(uuid=uuid, remark=item["remark"], address=address, port=item["port"],
                          sni=client_sni(stream), fingerprint=client_fingerprint(stream),
                          is_disabled=not item["enable"], is_hidden=False, tags=[],
                          xhttp_extra=None, profile_uuid=PROFILE, inbound_uuid=uuid,
                          template_uuid=None, override_sni=False, view_position=None))  # fmt: skip
        if item["enable"] and item["listen"] in ("", "0.0.0.0", "::"):
            proto = "udp" if item["protocol"] in UDP or stream.get("network") == "kcp" else "tcp"
            ports.append((item["port"], proto))
    for key in ("port", "subPort"):
        if info.get(key):
            ports.append((int(info[key]), "tcp"))
    profile = Profile(uuid=PROFILE, name="3x-ui", config={"inbounds": configs}, inbounds=models,
                      node_uuids=[LOCAL])  # fmt: skip
    node = Node(uuid=LOCAL, name=name, address=address, port=0, is_connected=True,
                is_disabled=False, country="", users_online=online,
                profile_uuid=PROFILE)  # fmt: skip
    return PanelSnapshot(
        version=version,
        nodes=[node],
        hosts=hosts,
        profiles=[profile],
        host_shape="tags",
        panel_domain=panel_domain,
        kind="3x-ui",
        open_ports={LOCAL: sorted(set(ports))},
        panel_info=dict(info),
    )

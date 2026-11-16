"""XHTTP padding and the uplink method (tech.md §10.6). Pure functions.

Padding fields must match on the server (the inbound's `extra` in the
profile) and on every client (the `extra` of each host of that inbound),
or the tunnel breaks. The key and the header are random per inbound, so
the fleet shares no signature. Rollback removes only the keys KERBEROS
added.
"""

from __future__ import annotations

import copy
import random
import string
from typing import Any, Optional

PADDING_KEYS = (
    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
)
# Header names that look like what browsers and frameworks send.
HEADER_WORDS = ("Request", "Trace", "Session", "Client", "Cache", "Edge", "Origin", "Span")


def padding_fields(rng: random.Random) -> dict:
    letters = string.ascii_lowercase
    key = "".join(rng.choice(letters) for _ in range(rng.randint(6, 10)))
    suffix = "".join(rng.choice(letters) for _ in range(4))
    return {
        "xPaddingBytes": "100-1000",
        "xPaddingObfsMode": True,
        "xPaddingKey": key,
        "xPaddingHeader": f"X-{rng.choice(HEADER_WORDS)}-{suffix.capitalize()}",
        "xPaddingPlacement": "queryInHeader",
        "xPaddingMethod": "tokenish",
    }


def has_padding(extra: Optional[dict]) -> bool:
    return bool(extra) and "xPaddingBytes" in extra


def padding_of(extra: Optional[dict]) -> dict:
    return {k: (extra or {})[k] for k in PADDING_KEYS if k in (extra or {})}


def with_padding(extra: Optional[dict], fields: dict) -> dict:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    result.update(copy.deepcopy(fields))
    return result


def without_padding(extra: Optional[dict]) -> dict:
    return {k: copy.deepcopy(v) for k, v in (extra or {}).items() if k not in PADDING_KEYS}


def xhttp_settings(inbound: dict) -> dict:
    stream = inbound.setdefault("streamSettings", {})
    return stream.setdefault("xhttpSettings", {})


def add_padding(config: dict, tags: list[str], rng: random.Random) -> tuple[dict, dict]:
    """A copy of the profile with padding on the inbounds that have none; {tag: fields}."""
    config = copy.deepcopy(config)
    written: dict = {}
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("tag") not in tags:
            continue
        settings = xhttp_settings(inbound)
        extra = settings.get("extra") if isinstance(settings.get("extra"), dict) else None
        if has_padding(extra):
            continue  # someone did it meanwhile, e.g. a profile shared with another node
        fields = padding_fields(rng)
        settings["extra"] = with_padding(extra, fields)
        written[inbound["tag"]] = fields
    return config, written


def remove_padding(config: dict, written: dict) -> tuple[dict, list[str]]:
    """Padding KERBEROS wrote taken out again; tags whose padding was changed since."""
    config = copy.deepcopy(config)
    changed = []
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("tag") not in written:
            continue
        settings = xhttp_settings(inbound)
        extra = settings.get("extra") if isinstance(settings.get("extra"), dict) else None
        current = padding_of(extra)
        if not current:
            continue
        if current != written[inbound["tag"]]:
            changed.append(inbound["tag"])
            continue
        rest = without_padding(extra)
        if rest:
            settings["extra"] = rest
        else:
            settings.pop("extra", None)  # an empty extra means no extra
    return config, changed


def uplink_get(extra: Optional[dict]) -> dict:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    result["uplinkHTTPMethod"] = "GET"
    return result


def uplink_back(extra: Optional[dict], previous: Any, was_none: bool) -> Optional[dict]:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    if previous is None:
        result.pop("uplinkHTTPMethod", None)
    else:
        result["uplinkHTTPMethod"] = previous
    return None if was_none and not result else result

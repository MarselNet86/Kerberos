"""The verified configs of templates/ (tech.md §10.9), read-only."""

from __future__ import annotations

import copy
import json
from functools import cache
from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
PROFILE = "profile.json"
RESERVE = "subscription-reserve.json"
SINGLE = "subscription-single.json"


@cache
def _load(name: str) -> dict:
    return json.loads((TEMPLATES_DIR / name).read_text(encoding="utf-8"))


def load(name: str) -> dict:
    """A fresh copy: callers may change it."""
    return copy.deepcopy(_load(name))

"""Test setup: the app and vendored Rich come from the repository only."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for path in (ROOT / "vendor", ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

try:
    from hypothesis import HealthCheck, settings

    settings.register_profile(
        "kerberos", deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=200
    )
    settings.load_profile("kerberos")
except ImportError:  # the agent tests on stand VMs run without Hypothesis
    pass

SNAPSHOTS = ROOT / "tests" / "snapshots"


def assert_snapshot(name: str, text: str) -> None:
    """Compare with tests/snapshots/<name>.txt; KERBEROS_UPDATE_SNAPSHOTS=1 rewrites it."""
    path = SNAPSHOTS / f"{name}.txt"
    if os.environ.get("KERBEROS_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        return
    assert path.exists(), f"no snapshot {path}; run with KERBEROS_UPDATE_SNAPSHOTS=1"
    expected = path.read_text(encoding="utf-8").rstrip("\n")
    assert text == expected, f"snapshot {name} differs"


@pytest.fixture
def root() -> Path:
    return ROOT

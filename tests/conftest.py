"""Test setup: the app and vendored Rich come from the repository only."""

from __future__ import annotations

import sys
from pathlib import Path

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

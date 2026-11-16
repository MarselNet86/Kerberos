"""Fixtures of the agent tests (they run on the stand VMs with pytest only, §18)."""

from __future__ import annotations

import pytest
from agent_helpers import Recorder

from kerberos import agent


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def system(tmp_path, recorder) -> agent.System:
    return agent.System(root=str(tmp_path), run=recorder, environ={})

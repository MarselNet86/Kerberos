"""A pre-hook certbot runs before every renewal and stops nginx (tech.md §9.2, §10.4, K17).

The certificate of the self-steal domain renews through nginx: with such a hook it never
renews, so the agent reports the hook and self_steal.site refuses before changing anything.
"""

import json
import os
import uuid

import pytest
from agent_helpers import call

from kerberos import agent

DOMAIN = "vpn.example.com"


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


@pytest.fixture
def node(system, recorder):
    for prefix in (["nginx"], ["systemctl"], ["certbot"], ["apt-get"], ["docker"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(
        ["ss"], agent.Result(0, 'tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=7))\n')
    )
    return system


HOOK = f"{agent.CERTBOT_PRE_HOOKS}/10-stop-nginx.sh"


@pytest.mark.parametrize(
    "path, text",
    [
        (HOOK, "#!/bin/sh\nsystemctl stop nginx\n"),
        (HOOK, "#!/bin/sh\nservice nginx stop\n"),
        (HOOK, "#!/bin/sh\nnginx -s quit\n"),
        (agent.CERTBOT_CLI, "email = admin@example.com\npre-hook = systemctl stop nginx\n"),
        (agent.CERTBOT_CLI, "pre_hook = pkill nginx\n"),
    ],
)
def test_a_hook_that_stops_nginx_is_a_fact(node, path, text):
    write(node, path, text, 0o755)
    assert agent.collect_facts(node)["certbot"]["stopsNginx"] is True


@pytest.mark.parametrize(
    "path, text",
    [
        (HOOK, "#!/bin/sh\nsystemctl reload nginx\n"),
        (HOOK, "#!/bin/sh\nsystemctl stop x-ui\n"),
        (agent.CERTBOT_CLI, "rsa-key-size = 4096\n"),
    ],
)
def test_other_hooks_are_not(node, path, text):
    write(node, path, text, 0o755)
    assert agent.collect_facts(node)["certbot"]["stopsNginx"] is False


def test_no_hooks_no_fact(node):
    assert agent.collect_facts(node)["certbot"]["stopsNginx"] is False


def test_self_steal_refuses_before_any_change(node, recorder):
    write(node, HOOK, "#!/bin/sh\nsystemctl stop nginx\n", 0o755)
    change = str(uuid.uuid4())
    params = json.dumps({"domain": DOMAIN, "siteSeed": 1}).encode()
    code, answer = call(node, ["apply", "self_steal.site", change], params)
    assert code != 0 and answer["error"]["code"] == "certbot_hook"
    assert not [c for c in recorder.calls if c[0] in ("nginx", "certbot", "apt-get")]
    assert not os.path.exists(node.path(agent.SITE_CONF))
    assert not os.path.exists(node.path(f"{agent.change_dir(change)}/rollback.json"))


def test_a_reload_hook_lets_self_steal_through(node):
    write(node, HOOK, "#!/bin/sh\nsystemctl reload nginx\n", 0o755)
    params = json.dumps({"domain": DOMAIN, "siteSeed": 1}).encode()
    code, answer = call(node, ["apply", "self_steal.site", str(uuid.uuid4())], params)
    assert code == 0, answer

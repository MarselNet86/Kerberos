"""Verified configs in templates/ (tech.md §10.9, §17).

The reference sha256 values live in tech.md §10.9: a template changes only
together with tech.md.
"""

import hashlib
import json
import re
from copy import deepcopy

from conftest import ROOT

HASH_LINE = re.compile(r"`templates/([\w.-]+\.json)`\s+`?([0-9a-f]{64})`?")


def reference_hashes() -> dict:
    text = (ROOT / "tech.md").read_text(encoding="utf-8")
    return dict(HASH_LINE.findall(text))


def test_templates_match_reference_hashes():
    refs = reference_hashes()
    files = sorted(p.name for p in (ROOT / "templates").glob("*.json"))
    assert files == sorted(refs), "every template has a reference hash in tech.md §10.9"
    for name, digest in refs.items():
        actual = hashlib.sha256((ROOT / "templates" / name).read_bytes()).hexdigest()
        assert actual == digest, f"templates/{name} differs from tech.md §10.9"


def load(name):
    return json.loads((ROOT / "templates" / name).read_text(encoding="utf-8"))


def test_single_is_reserve_without_balancer_injects_and_probes():
    reserve, single = load("subscription-reserve.json"), load("subscription-single.json")
    expected = deepcopy(reserve)
    del expected["routing"]["balancers"]
    del expected["remnawave"]["injectHosts"]
    del expected["burstObservatory"]
    rules = []
    for rule in expected["routing"]["rules"]:
        if rule.get("balancerTag") == "se-auto":
            if rule.get("network") == "tcp,udp":
                continue  # the final catch-all rule exists only with a balancer
            rule = {k: v for k, v in rule.items() if k != "balancerTag"}
            rule["outboundTag"] = "proxy"
        rules.append(rule)
    expected["routing"]["rules"] = rules
    assert single == expected


def test_profile_has_every_marker():
    text = (ROOT / "templates" / "profile.json").read_text(encoding="utf-8")
    for marker in ("__REALITY_TAG__", "__HY2_TAG__", "__REALITY_PRIVATE_KEY__",
                   "__REALITY_SHORT_ID__", "__DOMAIN__", "__SERVER_NAMES__"):
        assert marker in text
    for name in ("subscription-reserve.json", "subscription-single.json"):
        assert "__OWN_DOMAINS__" in (ROOT / "templates" / name).read_text(encoding="utf-8")

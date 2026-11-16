"""Score of tech.md §12.2."""

from hypothesis import given
from hypothesis import strategies as st

from kerberos.checks.score import level, score


def f(risk, ok):
    return {"risk": risk, "ok": ok}


def test_weights():
    assert score([f("high", True), f("medium", False)]) == 66
    assert score([f("high", False), f("low", True), f("info", False)]) == 16
    assert score([]) == 100
    assert score([f("info", False)]) == 100


def test_levels():
    assert (level(59), level(60), level(84), level(85)) == ("red", "yellow", "yellow", "green")


risks = st.sampled_from(["high", "medium", "low", "info"])


@given(st.lists(st.tuples(risks, st.booleans()), max_size=40), st.integers(0, 39))
def test_score_never_drops_when_more_checks_pass(items, index):
    findings = [f(r, ok) for r, ok in items]
    before = score(findings)
    if findings:
        findings[index % len(findings)]["ok"] = True
    assert score(findings) >= before
    assert 0 <= score(findings) <= 100

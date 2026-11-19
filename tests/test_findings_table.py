"""S6 findings as a table (tech.md §6 S6, §14.4, K22).

Found on the owner's fleet: eight nodes at one hoster gave twelve rows of the same
three problems, one per node, and «Вручную: 17» read as if little could be fixed.
"""

from rich.console import Console
from rich.text import Text

from kerberos.checks.score import score
from kerberos.copy import t
from kerberos.report.view import counts, finding_items, projected, rows
from kerberos.screens.check import check_summary
from kerberos.ui.widgets import FindingList

NAMES = {"u-a": "nl-a", "u-b": "nl-b", "u-c": "nl-c", "u-d": "de-a", "u-e": "de-b"}


def finding(check, uuid, evidence, *, topic="hosting", risk="medium", fix=None, ok=False):
    return {"checkId": check, "topic": topic, "risk": risk, "target": f"node:{uuid}",
            "ok": ok, "evidence": evidence, "fixId": fix}  # fmt: skip


def fleet():
    """nl-a, nl-b and nl-c close to each other, de-a and de-b too; one AS for both
    countries; nl-a and nl-b share a host key; two nodes allow passwords. Which nets
    are neighbours the rule decides (`with`); the row only joins them, so the nets here
    stay in the ranges for documentation."""
    nets = {"u-a": "203.0.113.0/24", "u-b": "203.0.113.0/24", "u-c": "192.0.2.0/24",
            "u-d": "198.51.100.0/24", "u-e": "198.51.100.0/24"}  # fmt: skip
    close = {"u-a": ["nl-b", "nl-c"], "u-b": ["nl-a", "nl-c"], "u-c": ["nl-a", "nl-b"],
             "u-d": ["de-b"], "u-e": ["de-a"]}  # fmt: skip
    found = [finding("fleet.same_24", u, {"net": nets[u], "with": close[u]}) for u in nets]
    nl, de = ["nl-a", "nl-b", "nl-c"], ["de-a", "de-b"]
    for uuid in ("u-a", "u-b", "u-c"):
        found.append(finding("fleet.same_asn", uuid, {"asn": 64500, "country": "NL", "nodes": nl}))
    for uuid in ("u-d", "u-e"):
        found.append(finding("fleet.same_asn", uuid, {"asn": 64500, "country": "DE", "nodes": de}))
    for uuid, other in (("u-a", "nl-b"), ("u-b", "nl-a")):
        found.append(finding("fleet.shared_hostkey", uuid, {"fingerprint": "SHA256:x",
                                                            "with": [other]},
                             fix="hostkeys.regenerate"))  # fmt: skip
    for uuid in ("u-a", "u-d"):
        found.append(finding("ssh.password", uuid, {}, topic="scanning", risk="high",
                             fix="ssh.key_only"))  # fmt: skip
    found.append(finding("ssh.password", "u-b", {}, topic="scanning", risk="high", ok=True))
    return found


def test_a_problem_of_the_fleet_is_one_row_per_group():
    items = finding_items(fleet(), NAMES)
    by_title = [(i.target, i.title) for i in items]
    assert (
        "nl-a, nl-b, nl-c",
        t("check.fleet.same_24.title", net="192.0.2.0/24, 203.0.113.0/24"),
    ) in by_title
    assert ("de-a, de-b", t("check.fleet.same_24.title", net="198.51.100.0/24")) in by_title
    assert ("nl-a, nl-b, nl-c", t("check.fleet.same_asn.title", asn=64500)) in by_title
    assert ("de-a, de-b", t("check.fleet.same_asn.title", asn=64500)) in by_title
    assert ("nl-a, nl-b", t("check.fleet.shared_hostkey.title")) in by_title
    # Problems of single nodes stay a row each.
    assert [i.target for i in items if i.extra["checkId"] == "ssh.password"] == ["nl-a", "de-a"]
    assert len(items) == len(rows(fleet(), NAMES)) == 7


def test_counts_follow_the_rows_and_the_score_stays():
    numbers = counts(fleet(), NAMES)
    assert numbers == {"problems": 7, "high": 2, "auto": 3, "manual": 4}
    before = score(fleet())
    assert score(fleet()) == before  # the table changes nothing in the model
    fixed = [dict(f, ok=True) if f["fixId"] and not f["ok"] else f for f in fleet()]
    assert projected(fleet()) == score(fixed) > before


def test_the_summary_says_what_kerberos_fixes_and_the_score_after():
    lines = check_summary(fleet(), NAMES, hint=True)
    text = " ".join(" ".join(line.plain.split()) for line in lines if isinstance(line, Text))
    assert " ".join(t("s6.summary", problems=7, high=2, auto=3, manual=4).split()) in text
    assert t("s6.after", score=projected(fleet())) in text
    assert t("s6.fix_hint") in text
    plain = check_summary(fleet(), NAMES, hint=False)
    assert all(t("s6.fix_hint") not in line.plain for line in plain if isinstance(line, Text))


def render(listing, width):
    console = Console(width=width, record=True, color_system=None, force_terminal=False)
    console.print(listing)
    return console.export_text()


def test_the_table_has_its_columns_and_one_word_todo_when_narrow():
    listing = FindingList(finding_items(fleet(), NAMES))
    wide = render(listing, 100)
    for column in ("s6.col.risk", "s6.col.where", "s6.col.what", "s6.col.todo"):
        assert t(column) in wide
    assert t("todo.fix") in wide
    narrow = render(listing, 80)
    assert t("todo.manual.short") in narrow and t("todo.fix.short") in narrow
    assert t("todo.fix") not in narrow


def test_space_opens_what_a_row_threatens_and_the_full_action():
    listing = FindingList(finding_items(fleet(), NAMES))
    assert t("check.fleet.same_24.threat") not in render(listing, 80)
    listing.handle("space")  # the first row: nl-a, nl-b, nl-c in neighbouring nets
    opened = " ".join(render(listing, 80).split())
    assert t("check.fleet.same_24.threat") in opened
    how = t("check.fleet.same_24.how")
    assert " ".join(t("action.manual", how=how).split()) in opened


def test_wrapped_cells_stay_in_their_column():
    listing = FindingList(finding_items(fleet(), NAMES))
    lines = render(listing, 80).splitlines()
    head = next(line for line in lines if t("s6.col.what") in line)
    where = head.index(t("s6.col.where"))
    topics = (t("topic.hosting"), t("topic.scanning"))
    skip = (*topics, "")
    wrapped = [
        line
        for line in lines
        if line.strip() not in skip
        and t("s6.col.what") not in line
        and not line.strip().startswith(("●", "›"))
    ]
    assert wrapped, "some cells wrap at 80 columns"
    for line in wrapped:
        assert len(line) - len(line.lstrip()) >= where, line

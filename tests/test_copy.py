"""Texts (tech.md §15): every key used in code exists; §15 keys are verbatim."""

import re

from helpers import ROOT

from kerberos.copy import TEXT

# Literal keys only: t("risk." + risk) style lookups are checked by their own tests.
KEY_USE = re.compile(r"""\bt\(\s*["']([\w.]*\w)["']\s*[,)]""")
SECTION_15_ROW = re.compile(r"^\| ([a-z_]+(?:\.[a-z_]+)+) \| (.+) \|$")


def test_every_used_key_exists():
    missing = set()
    for path in (ROOT / "src" / "kerberos").rglob("*.py"):
        for key in KEY_USE.findall(path.read_text(encoding="utf-8")):
            if key not in TEXT:
                missing.add(f"{path.name}: {key}")
    assert not missing


def test_section_15_texts_are_verbatim():
    text = (ROOT / "tech.md").read_text(encoding="utf-8")
    section = text.split("## 15. Тексты", 1)[1].split("\n## ", 1)[0]
    rows = [m.groups() for m in map(SECTION_15_ROW.match, section.splitlines()) if m]
    assert len(rows) >= 30
    for key, value in rows:
        assert TEXT.get(key) == value, key

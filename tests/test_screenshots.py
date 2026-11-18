"""README screenshots (tech.md §2.7, K9): the masked demo, nothing of a real machine."""

import importlib.util
import re

from helpers import ROOT

DOC_V4 = re.compile(r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$|0\.0\.0\.0$)")


def load_tool():
    spec = importlib.util.spec_from_file_location("screenshots", ROOT / "tools" / "screenshots.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_screens_are_masked_demo_frames(tmp_path):
    assert load_tool().main(tmp_path) == 0
    names = sorted(p.name for p in tmp_path.glob("*.svg"))
    assert names == ["s1.svg", "s6.svg", "s7.svg", "s8.svg", "s9.svg"]
    for path in tmp_path.glob("*.svg"):
        svg = path.read_text(encoding="utf-8")
        text = re.sub(r"&#160;|&#x00a0;", " ", svg)
        assert "маскировка" in text, f"{path.name}: taken without --mask"
        for address in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
            assert DOC_V4.match(address), f"{path.name}: {address}"
        assert "/Users/" not in text and "/home/" not in text and "/var/folders" not in text


def test_readme_shows_the_screens_it_has():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    shown = set(re.findall(r"docs/screens/(s\d\.svg)", readme))
    assert shown == {p.name for p in (ROOT / "docs" / "screens").glob("*.svg")}


def test_the_video_scenario_keeps_its_scores():
    """§12.4: the demo goes from 38 to 77; a new check must not move it unnoticed."""
    from kerberos.fixes.journal import RunStore

    tool = load_tool()
    app, _term = tool.app_for(tool.TO_PLAN + tool.APPLY, 40)
    app.run("fix")
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    assert (run["scoreBefore"], run["scoreAfter"]) == (38, 77)

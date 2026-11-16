"""The generated stub site (tech.md §10.4 step 1): own, readable, self-contained, stable."""

import hashlib
import json
import re
import uuid
from html.parser import HTMLParser

import pytest
from agent_helpers import call

from kerberos import agent

SEEDS = range(300)
VOID = {"meta", "link", "br", "hr", "img", "input"}


class Nesting(HTMLParser):
    """Every element closed in order; SVG shapes close themselves with "/>"."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list = []
        self.errors: list = []
        self.ids: list = []
        self.anchors: list = []
        self.urls: list = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.append(values["id"])
        for name in ("href", "src", "action"):
            if name in values:
                self.urls.append(values[name])
        if tag == "a" and values.get("href", "").startswith("#"):
            self.anchors.append(values["href"][1:])
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        for name in ("href", "src"):
            if name in dict(attrs):
                self.urls.append(dict(attrs)[name])

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> while open: {self.stack[-3:]}")
            return
        self.stack.pop()


def parsed(page: str) -> Nesting:
    parser = Nesting()
    parser.feed(page)
    parser.close()
    return parser


def test_same_seed_same_site_on_every_python():
    page = agent.site_html(20261116, "node.example.com")
    assert page == agent.site_html(20261116, "node.example.com")
    # KERBEROS and the agent may run different Pythons: the stream is sha256, not `random`.
    assert hashlib.sha256(page.encode()).hexdigest()[:16] == "54af5f06b9745ab5"


def test_sites_differ_in_markup():
    layouts = {agent.template_hash(agent.site_html(seed, "node.example.com")) for seed in SEEDS}
    assert len(layouts) >= 0.98 * len(SEEDS)


def test_sites_differ_in_name_and_colours():
    specs = [agent.site_spec(seed) for seed in SEEDS]
    assert len({s["title"] for s in specs}) > 0.6 * len(SEEDS)
    assert len({s["theme"]["accent"] for s in specs}) > 0.9 * len(SEEDS)
    assert len({s["kind"] for s in specs}) == len(agent.SITE_KINDS)


@pytest.mark.parametrize("seed", list(SEEDS)[::7])
def test_site_is_well_formed_and_self_contained(seed):
    page = agent.site_html(seed, "node.example.com")
    tree = parsed(page)
    assert tree.errors == [] and tree.stack == []
    assert len(tree.ids) == len(set(tree.ids)), "ids are unique"
    assert set(tree.anchors) <= set(tree.ids), "every menu link lands on a section"
    assert all(u.startswith(("#", "/", "data:image/svg+xml,")) for u in tree.urls), tree.urls
    lowered = page.lower()
    assert "<script" not in lowered and "@import" not in lowered and "url(" not in lowered
    assert "node.example.com" in page and len(page) < 40_000


def test_colours_keep_contrast():
    for seed in SEEDS:
        theme = agent.site_spec(seed)["theme"]
        background = theme["background"]
        for key in ("text", "muted", "accent"):
            assert agent.contrast(theme[key], background) >= 4.5, (seed, key)
        assert agent.contrast(theme["onAccent"], theme["accent"]) >= 4.5, seed


def test_title_is_escaped():
    seed = next(s for s in SEEDS if "&" in agent.site_spec(s)["title"])
    page = agent.site_html(seed, "node.example.com")
    title = agent.site_spec(seed)["title"]
    assert title.replace("&", "&amp;") in page and f"<title>{title}</title>" not in page


@pytest.fixture
def node(system, recorder):
    for prefix in (["nginx"], ["systemctl"], ["certbot"], ["apt-get"]):
        recorder.on(prefix, agent.Result(0))
    return system


@pytest.mark.parametrize("seed", [-1, agent.SITE_SEEDS, True, "3", 2.5])
def test_bad_seed(node, seed):
    params = {"domain": "node.example.com", "siteSeed": seed}
    code, answer = call(node, ["apply", "self_steal.site", str(uuid.uuid4())],
                        json.dumps(params).encode())  # fmt: skip
    assert code == 1 and answer["error"]["code"] == "bad_params"


def test_details_name_the_site(node):
    seed = agent.SITE_SEEDS - 1
    params = {"domain": "node.example.com", "siteSeed": seed}
    code, answer = call(node, ["apply", "self_steal.site", str(uuid.uuid4())],
                        json.dumps(params).encode())  # fmt: skip
    assert code == 0, answer
    spec = agent.site_spec(seed)
    assert answer["details"]["site"] == {
        "title": spec["title"],
        "kind": spec["kind"],
        "background": spec["theme"]["background"],
        "accent": spec["theme"]["accent"],
    }
    page = open(node.path(f"{agent.SITE_ROOT}/index.html"), encoding="utf-8").read()
    assert page == agent.site_html(seed, "node.example.com")
    assert re.search(r"<title>[^<]+</title>", page)

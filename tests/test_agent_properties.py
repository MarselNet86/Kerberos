"""Property tests of agent parsers (tech.md §17); here, not on the stand (needs Hypothesis)."""

from hypothesis import given
from hypothesis import strategies as st

from kerberos import agent

text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=400)


@given(text)
def test_ss_parsers_never_crash(value):
    for item in agent.parse_ss_listen(value):
        assert set(item) == {"proto", "address", "port", "process"}
    for item in agent.parse_ss_connections(value):
        assert item["received"] >= 0


@given(text)
def test_other_parsers_never_crash(value):
    agent.parse_sshd_t(value)
    agent.parse_ufw(value)
    agent.parse_nginx({"f": value})
    agent.parse_xray_log(value, 0)
    agent.parse_access_log(value, "/")
    agent.Ruleset(value).dropped("tcp")
    agent.parse_ip_addr(value)
    agent.parse_remnanode(value)
    agent.template_hash(value)

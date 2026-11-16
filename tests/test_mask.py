"""Masking (tech.md §2.7, §17): deterministic, leaves no original addresses or domains."""

import ipaddress

from hypothesis import given
from hypothesis import strategies as st

from kerberos.mask import Masker, is_doc_domain, is_doc_ip

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def real_v4():
    return st.ip_addresses(v=4).filter(
        lambda a: not is_doc_ip(str(a)) and not a.is_loopback and not a.is_unspecified
    ).map(str)


def real_v6():
    return st.ip_addresses(v=6).filter(
        lambda a: not is_doc_ip(str(a)) and not a.is_loopback and not a.is_unspecified
    ).map(str)


labels = st.from_regex(r"[a-z][a-z0-9]{1,10}", fullmatch=True)
tlds = st.sampled_from(["ru", "com", "net", "xyz"])
domains = st.builds(lambda a, b, tld: f"{a}.{b}.{tld}", labels, labels, tlds).filter(
    lambda d: not is_doc_domain(d)
)


@given(real_v4(), st.text(alphabet=" абв,:;()", max_size=5))
def test_v4_is_replaced_by_documentation_address(ip, filler):
    m = Masker(True)
    out = m(f"ssh root@{ip}{filler} -p 22")
    assert ip not in out
    masked = m.ip(ip)
    assert any(ipaddress.ip_address(masked) in net for net in DOC_NETS)
    # The host octet of the replacement is none of the original octets.
    assert masked.rsplit(".", 1)[1] not in ip.split(".")


@given(real_v6())
def test_v6_is_replaced(ip):
    m = Masker(True)
    out = m(f"[{ip}]:443")
    assert ip not in out
    assert ipaddress.ip_address(m.ip(ip)) in ipaddress.ip_network("2001:db8::/32")


@given(st.lists(real_v4(), min_size=1, max_size=20, unique=True))
def test_deterministic_and_distinct(ips):
    text = " ".join(ips)
    first, second = Masker(True)(text), Masker(True)(text)
    assert first == second
    masked = first.split(" ")
    assert len(set(masked)) == len(ips)


@given(domains)
def test_registered_and_generic_domains_are_masked(domain):
    m = Masker(True)
    m.register(domain)
    out = m(f"https://{domain}/path and {domain.upper()}.")
    assert domain not in out.lower()
    assert ".example.net" in out


def test_documentation_values_and_file_names_stay():
    m = Masker(True)
    text = (
        "203.0.113.10 nl-1.example.com 127.0.0.1:8445 report.md id_ed25519.pub kerberos.log 2.8.1"
    )
    assert m(text) == text


def test_disabled_masker_is_identity():
    assert Masker(False)("198.18.0.5 nl-1.example.com") == "198.18.0.5 nl-1.example.com"


def test_cidr_and_sentence_end():
    m = Masker(True)
    out = m("cut from 198.19.0.0/16. Next 198.19.7.9.")
    assert "198.19" not in out
    assert "/16." in out


def test_data_masks_nested_strings():
    m = Masker(True)
    data = m.data({"nodes": [{"address": "198.19.7.9", "port": 22}]})
    assert data["nodes"][0]["port"] == 22
    assert is_doc_ip(data["nodes"][0]["address"])


def test_cyrillic_domain():
    out = Masker(True)("сайт.рф")
    assert "сайт" not in out

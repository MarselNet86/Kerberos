"""SSH keys as data (tech.md §8.2): fingerprints, authorized_keys, keyscan output."""

import base64
import hashlib

from kerberos.nodes.keys import (
    PublicKey,
    demo_blob,
    fingerprint,
    kerberos_line,
    known_hosts_name,
    parse_authorized_keys,
    parse_key,
    scan_key,
)

BLOB = demo_blob("node")


def test_fingerprint_is_ssh_keygen_format():
    digest = hashlib.sha256(base64.b64decode(BLOB)).digest()
    expected = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    assert fingerprint(BLOB) == expected


def test_authorized_keys_with_options_and_comments():
    text = "\n".join(
        [
            "# comment line",
            f"ssh-ed25519 {BLOB} admin@laptop",
            kerberos_line("198.51.100.5", f"ssh-ed25519 {demo_blob('k')} kerberos@panel"),
            "ssh-ed25519 not-base64!! broken",
            "",
        ]
    )
    keys = parse_authorized_keys(text)
    assert [k.comment for k in keys] == ["admin@laptop", "kerberos@panel"]
    assert not keys[0].is_kerberos and keys[1].is_kerberos
    assert keys[1].options.startswith('from="198.51.100.5"')


def test_kerberos_line_is_restricted():
    line = kerberos_line("198.51.100.5", f"ssh-ed25519 {BLOB} kerberos@panel")
    assert line == (
        'from="198.51.100.5",command="/usr/local/sbin/kerberos-agent",restrict '
        f"ssh-ed25519 {BLOB} kerberos@panel"
    )
    assert parse_key(line).is_kerberos


def test_keyscan_output():
    out = f"# 203.0.113.10:2222 SSH-2.0-OpenSSH_9.6\n[203.0.113.10]:2222 ssh-ed25519 {BLOB}\n"
    assert scan_key(out) == PublicKey("ssh-ed25519", BLOB)
    assert scan_key("") is None
    assert scan_key(f"203.0.113.10 ssh-rsa {BLOB}\n") is None


def test_known_hosts_names():
    assert known_hosts_name("203.0.113.10", 22) == "203.0.113.10"
    assert known_hosts_name("203.0.113.10", 2222) == "[203.0.113.10]:2222"

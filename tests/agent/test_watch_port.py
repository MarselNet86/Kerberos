"""The watch counts cut connections where Xray answers from outside (tech.md §9.2, K18).

Found on a live server: on a panel server Caddy holds 443, on a CDN origin nginx does, and
Xray listens on loopback there. Cut connections of a web server are not a sign of a block.
"""

from kerberos import agent

CUT = (
    "0      0      203.0.113.10:{port}       198.51.100.7:51234\n"
    "\t cubic rto:204 bytes_sent:120 bytes_received:517 lastsnd:5000 lastrcv:5200\n"
)


def listen(*rows: str) -> agent.Result:
    return agent.Result(0, "".join(f"{row}\n" for row in rows))


def established(argv, _input):
    port = argv[-1].split(":")[1].split()[0]
    return agent.Result(0, CUT.format(port=port))


def test_a_web_server_on_443_and_xray_on_loopback_give_no_cut_share(system, recorder):
    recorder.on(["ss", "-Hlntup"], listen(
        'tcp LISTEN 0 4096 *:443 *:* users:(("caddy",pid=10,fd=7))',
        'tcp LISTEN 0 4096 127.0.0.1:24443 0.0.0.0:* users:(("xray-linux-amd6",pid=11,fd=8))',
        'tcp LISTEN 0 4096 [::1]:62789 [::]:* users:(("xray-linux-amd6",pid=11,fd=9))',
    ))  # fmt: skip
    recorder.on(["ss", "-Htin", "state", "established"], established)
    watch = agent.collect_watch(system)
    assert watch["port"] is None
    assert watch["v4"]["connections"] == 0 and watch["v6"]["connections"] == 0
    assert not [c for c in recorder.calls if c[:2] == ["ss", "-Htin"]]


def test_xray_on_other_public_ports_is_measured_on_all_of_them(system, recorder):
    recorder.on(["ss", "-Hlntup"], listen(
        'tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=10,fd=7))',
        'tcp LISTEN 0 4096 *:9443 *:* users:(("xray-linux-amd6",pid=11,fd=8))',
        'tcp LISTEN 0 4096 *:8443 *:* users:(("xray-linux-amd6",pid=11,fd=9))',
    ))  # fmt: skip
    recorder.on(["ss", "-Htin", "state", "established"], established)
    watch = agent.collect_watch(system)
    assert (watch["port"], watch["ports"]) == (8443, [8443, 9443])
    filter_ = "( sport = :8443 or sport = :9443 )"  # a quiet inbound is not judged alone
    assert ["ss", "-Htin", "state", "established", filter_] in recorder.calls


def test_xray_on_loopback_with_an_interface_is_not_public(system, recorder):
    recorder.on(["ss", "-Hlntup"], listen(
        'tcp LISTEN 0 4096 [::1]%lo:10085 [::]:* users:(("xray",pid=11,fd=8))',
        'tcp LISTEN 0 4096 127.0.0.1%lo:10086 0.0.0.0:* users:(("xray",pid=11,fd=9))',
    ))  # fmt: skip
    assert agent.collect_watch(system)["port"] is None
    assert agent.split_host_port("[::1]%lo:62789") == ("::1", 62789)
    assert agent.split_host_port("[fe80::1]%eth0:546") == ("fe80::1", 546)


def test_ipv4_clients_of_a_dual_stack_socket_count_as_ipv4(system, recorder):
    recorder.on(
        ["ss", "-Hlntup"], listen('tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=7))')
    )
    mapped = (
        "0      0      [::ffff:203.0.113.10]:443       [::ffff:198.51.100.7]:51234\n"
        "\t cubic rto:204 bytes_sent:120 bytes_received:517 lastsnd:5000 lastrcv:5200\n"
    )
    recorder.on(["ss", "-Htin", "state", "established"], agent.Result(0, mapped))
    watch = agent.collect_watch(system)
    assert watch["v4"]["connections"] == 1 and watch["v6"]["connections"] == 0
    assert watch["v4"]["cutNets"] == [{"net": "198.51.0.0/16", "count": 1}]


def test_443_wins_when_xray_holds_it(system, recorder):
    recorder.on(["ss", "-Hlntup"], listen(
        'tcp LISTEN 0 4096 *:8443 *:* users:(("rw-core",pid=11,fd=9))',
        'tcp LISTEN 0 4096 *:443 *:* users:(("rw-core",pid=11,fd=8))',
    ))  # fmt: skip
    recorder.on(["ss", "-Htin", "state", "established"], established)
    assert agent.collect_watch(system)["ports"] == [443, 8443]


def test_an_explicit_port_is_kept(system, recorder):
    recorder.on(["ss", "-Htin", "state", "established"], established)
    assert agent.collect_watch(system, 4430)["port"] == 4430

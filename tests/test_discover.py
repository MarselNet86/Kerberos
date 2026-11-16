"""Finding Remnawave on the panel server (tech.md §7.1)."""

import json

from kerberos.demo.fleet import build_host
from kerberos.host import CommandResult, FakeHost, parse_env_keys
from kerberos.panel.discover import discover


def test_demo_server_is_found_without_typing_an_address():
    location = discover(build_host())
    assert location.api == "http://127.0.0.1:3000/api"
    assert location.version == "2.8.1"
    assert location.panel_domain == "panel.example.com"


def test_no_docker_means_not_found():
    assert discover(FakeHost()) is None


def test_no_backend_container():
    host = FakeHost()
    host.on(["docker", "ps"], CommandResult(0, json.dumps({"Image": "nginx", "Names": "web"})))
    assert discover(host) is None


def test_host_network_and_version_from_image_tag():
    host = FakeHost()
    host.on(
        ["docker", "ps"],
        CommandResult(0, json.dumps({"Image": "remnawave/backend:2.8.1", "Names": "rw"})),
    )
    host.on(
        ["docker", "inspect", "rw"],
        CommandResult(
            0,
            json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {"com.docker.compose.project.working_dir": "/srv/rw/"}
                        },
                        "HostConfig": {"NetworkMode": "host"},
                        "NetworkSettings": {},
                    }
                ]
            ),
        ),
    )
    host.files["/srv/rw/.env"] = "APP_PORT=3100\n"
    location = discover(host)
    assert location.api == "http://127.0.0.1:3100/api"
    assert location.version == "2.8.1"
    assert location.panel_domain is None


def test_only_two_keys_of_env_are_read():
    text = (
        "# comment\nAPP_PORT=3000\nJWT_AUTH_SECRET=abc\nexport PANEL_DOMAIN='panel.example.com'\n"
        "POSTGRES_PASSWORD=xyz # trailing\n"
    )
    assert parse_env_keys(text, ["APP_PORT", "PANEL_DOMAIN"]) == {
        "APP_PORT": "3000",
        "PANEL_DOMAIN": "panel.example.com",
    }

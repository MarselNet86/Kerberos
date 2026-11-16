import io

import pytest

from kerberos import __version__
from kerberos.__main__ import UsageError, main, parse_args


def test_no_arguments_is_the_menu():
    opts = parse_args([], environ={})
    assert opts.command is None and opts.color


@pytest.mark.parametrize("command", ["check", "fix"])
def test_mode_commands(command):
    assert parse_args([command], environ={}).command == command


@pytest.mark.parametrize("command", ["rollback", "report", "finalize"])
def test_optional_run_id(command):
    assert parse_args([command], environ={}).arg is None
    assert parse_args([command, "20261116T123456Z-a1b2"], environ={}).arg == "20261116T123456Z-a1b2"


def test_ssh_needs_a_node():
    with pytest.raises(UsageError):
        parse_args(["ssh"], environ={})
    assert parse_args(["ssh", "nl-1"], environ={}).arg == "nl-1"


@pytest.mark.parametrize(
    "argv", [["bogus"], ["--bogus"], ["check", "extra"], ["report", "a", "b"], ["ssh", "a", "b"]]
)
def test_bad_arguments(argv):
    with pytest.raises(UsageError):
        parse_args(argv, environ={})


def test_flags():
    opts = parse_args(["--demo", "--mask", "--no-color", "check"], environ={})
    assert (opts.demo, opts.mask, opts.color, opts.command) == (True, True, False, "check")


def test_no_color_environment():
    assert not parse_args([], environ={"NO_COLOR": "1"}).color
    assert parse_args([], environ={"NO_COLOR": ""}).color


def test_main_exit_codes(capsys):
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert "Использование" in capsys.readouterr().out
    assert main(["bogus"]) == 2
    assert "Неверные аргументы" in capsys.readouterr().err


def test_without_tty_only_report_and_finalize(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO())
    assert main(["check"]) == 2
    assert "Запустите KERBEROS в терминале" in capsys.readouterr().err

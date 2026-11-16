"""K0: the app runs as `python3 -I -S` with src/ and vendor/ only (tech.md §3)."""

import subprocess
import sys

from conftest import ROOT

SCRIPT = r"""
import sys
sys.path[:0] = [sys.argv[1] + '/src', sys.argv[1] + '/vendor']
from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.mask import Masker
from kerberos.ui.terminal import FakeTerminal
term = FakeTerminal(['q', 'enter'], width=100, height=24)
code = App(Env(terminal=term, clock=FakeClock(), masker=Masker(), demo=True)).run()
import rich
assert rich.__file__.startswith(sys.argv[1] + '/vendor'), rich.__file__
leaked = sorted(m for m in sys.modules if m.split('.')[0] in ('pygments', 'markdown_it', 'mdurl'))
assert not leaked, leaked
assert 'site' not in sys.modules or not getattr(sys.modules['site'], 'ENABLE_USER_SITE', False)
print(code)
print(term.frames[0])
"""


def test_runs_without_site_packages():
    out = subprocess.run(
        [sys.executable, "-I", "-S", "-c", SCRIPT, str(ROOT)],
        capture_output=True,
        text=True,
        check=True,
        cwd="/",
    )
    code, frame = out.stdout.split("\n", 1)
    assert code == "0"
    assert "Проверка" in frame


def test_launcher_version_and_help():
    out = subprocess.run([str(ROOT / "kerberos"), "--version"], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.startswith("KERBEROS ")
    out = subprocess.run([str(ROOT / "kerberos"), "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "Использование" in out.stdout


def test_launcher_without_tty_explains():
    out = subprocess.run(
        [str(ROOT / "kerberos"), "--demo"], capture_output=True, text=True, stdin=subprocess.DEVNULL
    )
    assert out.returncode == 2
    assert "Запустите KERBEROS в терминале" in out.stderr


def test_launcher_uses_plain_sudo_and_isolated_python():
    text = (ROOT / "kerberos").read_text(encoding="utf-8")
    assert 'exec sudo -- "$0" "$@"' in text
    assert "-I -S -c" in text

#!/usr/bin/env bash
# Local checks (tech.md §18): ruff; pytest on Python 3.9 and 3.14 through uv
# (the oldest and newest Python of §3.1); a run without site-packages;
# template hashes. Run before every commit of a PR; paste the result into it.
set -euo pipefail
cd "$(dirname "$0")/.."

DEPS=(--with "pytest>=8" --with "hypothesis>=6.100")
step() { printf '\n== %s\n' "$*"; }

step "ruff"
uvx ruff@0.17.5 check .
uvx ruff@0.17.5 format --check src tests tools

for version in 3.9 3.14; do
  step "pytest, Python $version"
  uv run --no-project --python "$version" "${DEPS[@]}" python -m pytest
done

for version in 3.9 3.14; do
  step "run without site-packages, Python $version"
  uv run --no-project --python "$version" python -I -S -c \
    "import sys; sys.path[:0] = ['src', 'vendor']; import kerberos.app, kerberos.__main__; print('ok')"
done

step "template hashes"
uv run --no-project --python 3.14 "${DEPS[@]}" python -m pytest tests/test_templates.py

printf '\ncheck.sh: OK\n'

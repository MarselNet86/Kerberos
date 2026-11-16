#!/usr/bin/env bash
# Agent tests and "apply, roll back, apply again" on the five stand VMs
# (tech.md §17, §18, §22).
#
#   tools/stand.sh            run on the disposable VMs from tools/stand.env
#   tools/stand.sh --docker   only the agent pytest, in containers of the five OSes
#
# tools/stand.env is not in git. One SSH target per OS, documentation-range
# example:
#   STAND_UBUNTU_2204=root@192.0.2.21
#   STAND_UBUNTU_2404=root@192.0.2.22
#   STAND_UBUNTU_2604=root@192.0.2.23
#   STAND_DEBIAN_12=root@192.0.2.24
#   STAND_DEBIAN_13=root@192.0.2.25
# Optional domain per VM for self-steal (its A record points to the VM):
#   STAND_DEBIAN_13_DOMAIN=deb13.stand.example.com
# Stand VMs only: never production servers (CLAUDE.md, rule 9).
set -euo pipefail
cd "$(dirname "$0")/.."

NAMES=(ubuntu-22.04 ubuntu-24.04 ubuntu-26.04 debian-12 debian-13)
IMAGES=(ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:12 debian:13)
VARS=(STAND_UBUNTU_2204 STAND_UBUNTU_2404 STAND_UBUNTU_2604 STAND_DEBIAN_12 STAND_DEBIAN_13)
PAYLOAD=(src/kerberos/__init__.py src/kerberos/agent.py tests/conftest.py tests/agent tests/fixtures/agent)
# tests/stand/scenario.py changes SSH, nftables and fail2ban: stand VMs only.
[ -d tests/stand ] && PAYLOAD+=(tests/stand)

REPORT="$(mktemp "${TMPDIR:-/tmp}/kerberos-stand.XXXXXX")"
failed=0
record() { printf '%-14s %-10s %s\n' "$1" "$2" "$3" | tee -a "$REPORT"; }

run_docker() {
  local i
  for i in "${!NAMES[@]}"; do
    if docker run --rm -v "$PWD":/src:ro "${IMAGES[$i]}" sh -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq python3 python3-pytest >/dev/null
        mkdir -p /tmp/k && cd /src && tar --no-xattrs -cf - '"${PAYLOAD[*]}"' | tar xf - -C /tmp/k
        cd /tmp/k && python3 -m pytest -q -p no:cacheprovider tests/agent'; then
      record "${NAMES[$i]}" docker ok
    else
      record "${NAMES[$i]}" docker FAILED
      failed=1
    fi
  done
}

run_vms() {
  if [ ! -f tools/stand.env ]; then
    echo "tools/stand.env is missing: describe the five stand VMs there (see the header)." >&2
    exit 2
  fi
  # shellcheck disable=SC1091
  . tools/stand.env
  local i target ssh_opts
  ssh_opts=(-o BatchMode=yes -o ConnectTimeout=15)
  for i in "${!NAMES[@]}"; do
    target="${!VARS[$i]:-}"
    if [ -z "$target" ]; then
      record "${NAMES[$i]}" vm "SKIPPED: ${VARS[$i]} not set"
      failed=1
      continue
    fi
    # No extended attributes: macOS tar adds its own, GNU tar on the VM warns about them.
    tar --no-xattrs -czf - "${PAYLOAD[@]}" | ssh "${ssh_opts[@]}" "$target" \
      'rm -rf /tmp/kerberos-stand && mkdir -p /tmp/kerberos-stand && tar xzf - -C /tmp/kerberos-stand'
    domain_var="${VARS[$i]}_DOMAIN"
    if [ -n "${!domain_var:-}" ]; then
      printf '%s\n' "${!domain_var}" | ssh "${ssh_opts[@]}" "$target" 'cat > /tmp/kerberos-stand/domain'
    fi
    # A fresh VM may still run cloud-init (host keys, packages): wait for it first.
    ssh "${ssh_opts[@]}" "$target" \
      'command -v cloud-init >/dev/null 2>&1 && cloud-init status --wait >/dev/null 2>&1; true'
    # A fresh cloud image has no package lists yet: update before installing.
    if ! ssh "${ssh_opts[@]}" "$target" 'python3 -m pytest --version >/dev/null 2>&1 || {
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null && apt-get install -y -qq python3-pytest >/dev/null; }'; then
      record "${NAMES[$i]}" pytest "FAILED: python3-pytest did not install"
      failed=1
      continue
    fi
    if ssh "${ssh_opts[@]}" "$target" 'cd /tmp/kerberos-stand && python3 -m pytest -q -p no:cacheprovider tests/agent'; then
      record "${NAMES[$i]}" pytest ok
    else
      record "${NAMES[$i]}" pytest FAILED
      failed=1
    fi
    if [ -f tests/stand/scenario.py ]; then
      if ssh "${ssh_opts[@]}" "$target" 'cd /tmp/kerberos-stand && python3 tests/stand/scenario.py'; then
        record "${NAMES[$i]}" scenario ok
      else
        record "${NAMES[$i]}" scenario FAILED
        failed=1
      fi
    fi
  done
}

case "${1:-}" in
  --docker) run_docker ;;
  "") run_vms ;;
  *) echo "usage: tools/stand.sh [--docker]" >&2; exit 2 ;;
esac

printf '\nstand report: %s\n' "$REPORT"
cat "$REPORT"
exit "$failed"

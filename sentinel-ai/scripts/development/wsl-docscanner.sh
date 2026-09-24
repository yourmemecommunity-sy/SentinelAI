#!/usr/bin/env bash
# Sets up and runs the document-scanner suite inside WSL, where the REAL OCR engine and antivirus daemon are installed.
#   wsl -u root -- bash /mnt/c/.../scripts/development/wsl-docscanner.sh setup|test|real
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC="$(cd "${HERE}/../../services/document-scanner" && pwd)"
VENV=/opt/dsvenv
PY="${VENV}/bin/python"

setup() {
  apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1 || true
  [ -x "${PY}" ] || python3 -m venv "${VENV}"
  "${VENV}/bin/pip" install -q --upgrade pip
  # pillow is a test-only dependency: it renders the images the real OCR engine reads back.
  "${VENV}/bin/pip" install -q -e "${SVC}[dev]" pillow
  "${PY}" -c "import fastapi, pypdf, defusedxml, PIL; print('deps ok')"
}

run_tests() {
  cd "${SVC}"
  # Copy out of /mnt (Windows filesystem) first: the suite spawns child processes and writes temp files, which is slow there.
  rm -rf /tmp/ds && mkdir -p /tmp/ds && cp -r app tests pyproject.toml /tmp/ds/
  cd /tmp/ds
  shift || true
  CLAMD_HOST="${CLAMD_HOST:-127.0.0.1}" CLAMD_PORT="${CLAMD_PORT:-3310}" "${PY}" -m pytest -q -p no:cacheprovider "$@"
}

case "${1:-test}" in
  setup) setup ;;
  test) run_tests "$@" ;;
  real) run_tests "$@" tests/test_real_dependencies.py -v ;;
  *) echo "usage: $0 setup|test|real" >&2; exit 2 ;;
esac

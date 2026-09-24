#!/usr/bin/env bash
# Python dependency audit for every service. Run inside WSL:
#   wsl -u root -- bash scripts/security/dependency-scan.sh
# (pip-audit from Windows fails TLS verification against pypi.org on this machine; WSL's trust store works.)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
PIPAUDIT="${PIPAUDIT:-/opt/dsvenv/bin/pip-audit}"
rc=0

for svc in security-engine document-scanner token-vault; do
  req="${ROOT}/services/${svc}/requirements.txt"
  echo "=== ${svc} (${req})"
  if [ ! -f "${req}" ]; then echo "  MISSING requirements.txt"; rc=1; continue; fi
  "${PIPAUDIT}" -r "${req}" --progress-spinner off || rc=1
done

echo
echo "dependency-scan exit=${rc}"
exit "${rc}"

#!/usr/bin/env bash
# Brings the compose stack up and waits until EVERY service with a healthcheck is healthy (or times out).
#
# Waiting only for the gateway and the dashboard is not enough: ClamAV needs minutes to load its signature database, and
# probes that run while it is still loading see uploads fail closed - a correct refusal that looks like a defect.
#   bash scripts/development/docker-up.sh [extra compose args, e.g. --profile ollama]
set -uo pipefail
cd "$(dirname "$0")/../.."

[ -f .env ] || { echo "no .env - run scripts/development/docker-secrets.sh first" >&2; exit 2; }
docker compose "$@" up -d || exit 1

status() { docker compose ps -a --format '{{.Service}}={{.State}}/{{.Health}}' | tr '\n' ' '; }
# Every service that declares a healthcheck, plus the one-shot migrate job, which must have exited.
WAIT_FOR="postgres redis clamav token-vault security-engine document-scanner policy-engine api dashboard"
for _ in $(seq 1 120); do
  s="$(status)"
  ready=1
  for svc in $WAIT_FOR; do [[ "$s" == *"$svc=running/healthy"* ]] || ready=0; done
  [[ "$s" == *"migrate=exited/"* ]] || ready=0
  if [ "$ready" = 1 ]; then
    echo "READY: $s"
    exit 0
  fi
  sleep 10
done
echo "TIMEOUT: $(status)"
docker compose ps -a
exit 1

#!/usr/bin/env bash
# One-command "AI vs AI" demo: start the stack, run a short red-team round against it live, print the scoreboard.
#
#   bash scripts/demo/ai-vs-ai.sh [attacks per category, default 4]
#
# Needs: Docker (compose v2), python3, a .env made by scripts/development/docker-secrets.sh, and SENTINEL_REDTEAM_API_KEY
# in .env (a key with scan:use; evaluation:run to store the round). With ANTHROPIC_API_KEY in .env the attacker is Claude
# (claude-haiku-4-5, capped by ANTHROPIC_BUDGET_USD); without it, the labelled offline seed generator is used and the
# scoreboard says so. Never removes volumes.
set -euo pipefail
cd "$(dirname "$0")/../.."
N="${1:-4}"
[ -f .env ] || { echo "no .env: run bash scripts/development/docker-secrets.sh first"; exit 1; }
grep -q '^SENTINEL_REDTEAM_API_KEY=.\+' .env || {
  echo "no SENTINEL_REDTEAM_API_KEY in .env: create an organisation + SECURITY_ANALYST key (see docs/verification/12-ai-vs-ai.md)"; exit 1; }

echo "== starting SentinelAI (docker compose up -d; waits for every service)"
docker compose up -d >/dev/null
bash scripts/development/docker-up.sh | tail -1

GEN=offline
grep -q '^ANTHROPIC_API_KEY=.\+' .env && GEN=claude
echo "== red team: generator=$GEN, $N attacks per category, target http://127.0.0.1:4000"
python3 scripts/security/with_env.py SENTINEL_REDTEAM_API_KEY,ANTHROPIC_API_KEY,ANTHROPIC_BUDGET_USD -- \
  scripts/security/red_team.py --generator "$GEN" --per-category "$N" --post
echo
echo "Dashboard: http://127.0.0.1:3000/red-team (rounds, success rate per category, trend) and /events (why each was blocked)"

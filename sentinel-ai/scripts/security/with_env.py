"""Run a Python script with selected variables from sentinel-ai/.env in its environment, without printing them.

    python scripts/security/with_env.py SENTINEL_REDTEAM_API_KEY,ANTHROPIC_API_KEY -- scripts/security/red_team.py --post
Existing environment variables win over .env. Empty values are skipped.
"""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

ENV = Path(__file__).resolve().parents[2] / ".env"


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise SystemExit("usage: with_env.py NAME[,NAME...] -- script.py [args...]")
    wanted = set(sys.argv[1].split(","))
    if ENV.exists():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() in wanted and value.strip() and key.strip() not in os.environ:
                os.environ[key.strip()] = value.strip()
    script = sys.argv[3]
    sys.argv = [script, *sys.argv[4:]]
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main()

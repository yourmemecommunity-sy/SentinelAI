#!/usr/bin/env python3
"""Regenerate the git-root README.md (one level above sentinel-ai/) from sentinel-ai/README.md.

sentinel-ai/README.md is the source of truth. The root copy has the same content with every relative link and path
re-rooted into sentinel-ai/, a pointer line to the project folder, and `cd sentinel-ai` in the commands.

    python scripts/development/sync-root-readme.py          # write ../README.md
    python scripts/development/sync-root-readme.py --check  # exit 1 if ../README.md is out of date
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]          # sentinel-ai/
SOURCE = PROJECT / "README.md"
TARGET = PROJECT.parent / "README.md"                   # git repository root


def must_replace(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"sync-root-readme: expected exactly one occurrence of {old[:60]!r} in {SOURCE}")
    return text.replace(old, new)


def render(src: str) -> str:
    r = re.sub(r"\]\((?!https?://|#)", "](sentinel-ai/", src)                 # every relative markdown link
    r = re.sub(r"\[`(docs/[^`]*)`\]", r"[`sentinel-ai/\1`]", r)             # link texts that show a path
    r = re.sub(r"\[(docs/[^\]]*)\]\(sentinel-ai/", r"[sentinel-ai/\1](sentinel-ai/", r)
    r = re.sub(r"`!\[([^\]]*)\]\((docs/[^)]*)\)`", r"`![\1](sentinel-ai/\2)`", r)   # example image syntax in the placeholder
    r = r.replace("<!-- MEDIA-PLACEHOLDER: owner adds docs/media/", "<!-- MEDIA-PLACEHOLDER: owner adds sentinel-ai/docs/media/")
    r = must_replace(r, "reaches a model. If any security component is unavailable, the request is refused, never passed through unscanned.\n",
                     "reaches a model. If any security component is unavailable, the request is refused, never passed through unscanned.\n\n"
                     "The project lives in [`sentinel-ai/`](sentinel-ai/); this page mirrors [`sentinel-ai/README.md`](sentinel-ai/README.md).\n")
    r = must_replace(r, "```bash\nbash scripts/development/docker-secrets.sh",
                     "```bash\ncd sentinel-ai\nbash scripts/development/docker-secrets.sh")
    r = must_replace(r, "in `.env`.\nTo check the whole stack:", "in `sentinel-ai/.env`.\nTo check the whole stack (from `sentinel-ai/`):")
    r = re.sub(r"^\| `(apps|services|packages|datasets)", r"| `sentinel-ai/\1", r, flags=re.M)
    r = must_replace(r, "| `tests/`, `docs/`, `scripts/`, `infrastructure/` |", "| `sentinel-ai/{tests,docs,scripts,infrastructure}/` |")
    r = must_replace(r, "`node scripts/development/validate-structure.mjs` enforces the layout rules. CI fails if it fails.\n",
                     "`node scripts/development/validate-structure.mjs` (run inside `sentinel-ai/`) enforces the layout rules. CI fails if it\n"
                     "fails. The CI workflow is at [`.github/workflows/ci.yml`](.github/workflows/ci.yml), at the repository root.\n")
    return r


def main() -> int:
    want = render(SOURCE.read_text(encoding="utf8"))
    if "--check" in sys.argv:
        have = TARGET.read_text(encoding="utf8") if TARGET.exists() else ""
        if have.replace("\r\n", "\n") != want:
            print(f"{TARGET} is out of date: run python scripts/development/sync-root-readme.py")
            return 1
        print(f"{TARGET} is in sync with {SOURCE}")
        return 0
    TARGET.write_text(want, encoding="utf8", newline="\n")
    print(f"wrote {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
# Static type checking of every Python package with mypy (configuration: each package's pyproject.toml [tool.mypy]).
#
#   Application code: strict (every function annotated, no implicit Any, pydantic models checked with real field types).
#   Tests:            the same configuration with check_untyped_defs still on - every test body is type-checked - but
#                     test functions and fixtures are not required to carry annotations.
#
# Requires each package installed with its dev extras (pip install -e ".[dev]"), because mypy checks against the real
# third-party types. Exit status is non-zero if any package has any error.
#
#   bash scripts/development/typecheck-python.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
TEST_RELAX=(--allow-untyped-defs --allow-incomplete-defs --allow-untyped-calls --allow-untyped-decorators
            --allow-any-generics --no-warn-return-any)
FAIL=0
check() {  # <package dir> <source package> [extra flags for the tests pass]
  local dir=$1 src=$2; shift 2
  if (cd "$dir" && mypy "$src"); then echo "PASS mypy $dir/$src (strict)"; else echo "FAIL mypy $dir/$src (strict)"; FAIL=$((FAIL + 1)); fi
  if compgen -G "$dir/tests/*.py" >/dev/null || compgen -G "$dir/tests/**/*.py" >/dev/null; then
    if (cd "$dir" && mypy tests "${TEST_RELAX[@]}" "$@"); then echo "PASS mypy $dir/tests"; else echo "FAIL mypy $dir/tests"; FAIL=$((FAIL + 1)); fi
  fi
}
check services/security-engine app
check services/token-vault app
check services/document-scanner app
check services/policy-engine app
# The SDK library is checked against Python 3.9, its oldest supported version (pyproject). Its tests run on the dev
# toolchain, whose pytest itself needs 3.10+ (mypy would otherwise analyze pytest's own 3.10-only syntax), so they are
# checked at 3.12.
check packages/sdk/python sentinelai --python-version 3.12
echo
[ "$FAIL" = 0 ] && echo "PYTHON TYPE CHECK: ALL PACKAGES PASSED" || echo "PYTHON TYPE CHECK: $FAIL FAILURE(S)"
exit "$FAIL"

"""The published API contract must be machine-readable and must match what the gateway actually serves.

docs/api/openapi.yaml was invalid YAML for a long time without anyone noticing, because nothing ever parsed it: a
summary containing "[scan, ai_request, ...]" inside a flow mapping. A contract nobody can parse is not a contract, and
tools that generate clients or run security scans against it silently skip it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs" / "api" / "openapi.yaml"
ROUTES_DIR = ROOT / "apps" / "api" / "src" / "routes"

# Routes the gateway registers that are deliberately absent from the public contract.
UNDOCUMENTED_ON_PURPOSE: set[str] = set()


@pytest.fixture(scope="module")
def spec() -> dict:
    return yaml.safe_load(SPEC.read_text(encoding="utf8"))


def test_the_specification_is_parseable_yaml(spec: dict) -> None:
    assert spec["openapi"].startswith("3.")
    assert spec["paths"], "no paths in the specification"


def test_every_route_the_gateway_registers_is_documented(spec: dict) -> None:
    """app.get/post/... calls in the route files, compared with the documented paths."""
    registered: set[str] = set()
    for f in ROUTES_DIR.glob("*.ts"):
        text = f.read_text(encoding="utf8")
        for m in re.finditer(r"""app\.(get|post|put|patch|delete)(?:<[^>]*>)?\(\s*"([^"]+)"|
                                 app\.(get|post|put|patch|delete)(?:<[^>]*>)?\(\s*'([^']+)'""",
                             text, re.VERBOSE):
            path = m.group(2) or m.group(4)
            if path and path.startswith("/"):
                registered.add(path)

    documented = set(spec["paths"])
    # Fastify writes ":id", OpenAPI writes "{id}".
    normalised = {re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", p) for p in registered}
    missing = normalised - documented - UNDOCUMENTED_ON_PURPOSE
    assert not missing, f"routes served but not documented in openapi.yaml: {sorted(missing)}"


def test_management_routes_document_that_they_need_a_user_session(spec: dict) -> None:
    """These routes refuse API keys; the contract has to say so, or integrators will build against a wrong assumption."""
    for path in ("/v1/users", "/v1/invitations", "/v1/teams", "/v1/providers"):
        assert path in spec["paths"], f"{path} is not documented"
    description = spec["info"]["description"]
    assert "USER session" in description and "API key is never" in description


def test_the_invitation_token_is_documented_as_shown_once(spec: dict) -> None:
    post = spec["paths"]["/v1/invitations"]["post"]
    assert "ONCE" in post["summary"] and "HMAC" in post["summary"]
    accept = spec["paths"]["/v1/invitations/accept"]["post"]
    assert accept["security"] == [], "the accept endpoint is public: the invitee has no session yet"


def test_provider_credentials_are_documented_as_write_only_and_fail_closed(spec: dict) -> None:
    put = spec["paths"]["/v1/providers/{provider}/credential"]["put"]
    summary = put["summary"]
    assert "never returned" in summary
    assert "FAILS CLOSED" in summary
    assert "503" in put["responses"], "the no-credential-storage case must be documented"

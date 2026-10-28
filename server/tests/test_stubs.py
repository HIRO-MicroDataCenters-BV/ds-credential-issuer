"""Stub endpoints must return 501 — pins them down so a Phase 2 PR has
to delete the stub tests when it lands the real implementation (and nobody
accidentally ships a half-finished endpoint)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.rest_api.routes.credentials import router as credentials_router
from app.rest_api.routes.schemas import router as schemas_router


@pytest.fixture
def client():
    """Build an app that mounts just the route modules we want to test,
    with the lifespan-managed dependencies replaced by MagicMocks so the
    tests don't need a working KERIpy habery."""
    from fastapi import FastAPI

    from app.rest_api.depends import acdc_issuer_dep, issuer_handle_dep

    app = FastAPI()
    app.include_router(credentials_router)
    app.include_router(schemas_router)
    # Dependency overrides — the stubs raise 501 before touching these,
    # but FastAPI resolves them anyway when building the request.
    app.dependency_overrides[acdc_issuer_dep] = lambda: MagicMock()
    app.dependency_overrides[issuer_handle_dep] = lambda: MagicMock()

    return TestClient(app)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/credentials"),
        ("GET", "/credentials/ESomeSAID"),
        ("GET", "/schemas"),
        ("GET", "/schemas/ESomeSAID"),
        ("POST", "/schemas"),
    ],
)
def test_phase_2_stubs_return_501(client, method, path):
    body = {} if method == "POST" else None
    # Give schema register a well-formed body so Pydantic doesn't 422 it
    # before the stub body raises 501.
    if method == "POST" and path == "/schemas":
        body = {"said": "ESchema", "schema_body": {"type": "object"}}
    r = client.request(method, path, json=body)
    assert r.status_code == 501, (
        f"{method} {path} must return 501 Not Implemented while stubbed; "
        f"got {r.status_code} ({r.text})"
    )
    assert "ROADMAP" in r.text or "not yet implemented" in r.text.lower()


def test_present_stub_returns_501(client):
    r = client.post(
        "/credentials/ESomeSAID/present",
        json={"recipient_aid": "ERecipient"},
    )
    assert r.status_code == 501

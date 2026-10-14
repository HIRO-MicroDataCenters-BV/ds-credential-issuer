"""Permission map coverage tests.

Guards against someone adding a new mutator endpoint and forgetting to
require issuer:write / issuer:admin for it.
"""
import re

from app.rest_api.auth_config import (
    ADMIN_PERMISSION,
    PERMISSION_MAP,
    PUBLIC_PATHS,
    READ_PERMISSION,
    WRITE_PERMISSION,
)


def _entries_for(method, path):
    return [
        (m, p, perm)
        for (m, p, perm) in PERMISSION_MAP
        if m == method and re.fullmatch(p, path)
    ]


def test_mint_requires_issuer_write():
    hits = _entries_for("POST", "/credentials")
    assert hits, "POST /credentials must have a permission mapping"
    assert hits[0][2] == WRITE_PERMISSION


def test_revoke_requires_issuer_write():
    hits = _entries_for("POST", "/credentials/ESomeSAID/revoke")
    assert hits, "POST /credentials/{said}/revoke must have a mapping"
    assert hits[0][2] == WRITE_PERMISSION


def test_present_requires_issuer_write():
    hits = _entries_for("POST", "/credentials/ESomeSAID/present")
    assert hits, "POST /credentials/{said}/present must have a mapping"
    assert hits[0][2] == WRITE_PERMISSION


def test_schema_register_requires_admin():
    """Registering a schema changes what every verifier downstream will
    accept — must be admin, not write."""
    hits = _entries_for("POST", "/schemas")
    assert hits
    assert hits[0][2] == ADMIN_PERMISSION


def test_credential_reads_are_read_tier():
    for path in ["/credentials", "/credentials/ESomeSAID"]:
        hits = _entries_for("GET", path)
        assert hits, f"GET {path} must have a permission mapping"
        assert hits[0][2] == READ_PERMISSION


def test_health_and_docs_are_public():
    assert "/health-check/" in PUBLIC_PATHS
    assert "/openapi.json" in PUBLIC_PATHS
    assert "/docs" in PUBLIC_PATHS

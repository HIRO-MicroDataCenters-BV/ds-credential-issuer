"""Revocation: POST /credentials/{said}/revoke and the public
GET /credential-status. The issuer is mocked (no dkms binary); the store is
a real SQLite file in a temp dir."""
from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.dkms_bridge import DkmsBridgeError
from app.core.revocations import RevocationStore
from app.main import app
from app.rest_api.auth_config import PERMISSION_MAP, PUBLIC_PATHS, WRITE_PERMISSION
from app.rest_api.depends import acdc_issuer_dep, revocation_store_dep

SAID = "EKpR6Ps854nCtyBzwu8q-UeoP9tCKhuGzqTyaqia5zfq"
OTHER = "EOtherCredential000000000000000000000000000A"


@pytest.fixture
def env(tmp_path):
    store = RevocationStore(tmp_path / "revocations.db")
    issuer = MagicMock()
    issuer.issuer.name = "hus-issuer"
    app.dependency_overrides[acdc_issuer_dep] = lambda: issuer
    app.dependency_overrides[revocation_store_dep] = lambda: store
    yield TestClient(app), issuer, store, tmp_path
    app.dependency_overrides.clear()


def _status(client, said=SAID):
    return client.get("/credential-status", params={"said": said})


def test_not_revoked_by_default(env):
    client, *_ = env
    r = _status(client)
    assert r.status_code == 200
    assert r.json() == {"said": SAID, "status": "not_revoked", "revoked_at": None}


def test_revoke_then_status_is_revoked(env):
    client, issuer, *_ = env
    r = client.post(f"/credentials/{SAID}/revoke", json={"reason": "left the institute"},
                    headers={"X-User-AID": "EOperator"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "revoked"
    assert body["revoked_by"] == "EOperator"
    assert body["reason"] == "left the institute"
    assert body["already_revoked"] is False
    assert body["tel_anchored"] is True
    issuer.issuer.bridge.data_revoke.assert_called_once_with("hus-issuer", SAID)

    s = _status(client).json()
    assert s["status"] == "revoked"
    assert s["revoked_at"] == body["revoked_at"]
    assert _status(client, OTHER).json()["status"] == "not_revoked"


def test_revoke_without_body(env):
    client, *_ = env
    r = client.post(f"/credentials/{SAID}/revoke")
    assert r.status_code == 200
    assert r.json()["revoked_by"] == "unknown"


def test_revoking_twice_keeps_first_record(env):
    client, issuer, *_ = env
    first = client.post(f"/credentials/{SAID}/revoke", json={"reason": "one"}).json()
    again = client.post(f"/credentials/{SAID}/revoke", json={"reason": "two"}).json()
    assert again["already_revoked"] is True
    assert again["reason"] == "one"
    assert again["revoked_at"] == first["revoked_at"]
    assert issuer.issuer.bridge.data_revoke.call_count == 1


def test_list_entry_kept_when_dkms_revoke_fails(env):
    client, issuer, *_ = env
    issuer.issuer.bridge.data_revoke.side_effect = DkmsBridgeError("witness down")
    r = client.post(f"/credentials/{SAID}/revoke")
    assert r.status_code == 200
    assert r.json()["tel_anchored"] is False
    assert _status(client).json()["status"] == "revoked"


@pytest.mark.parametrize("bad", ["not-a-said", "E" + "x" * 10, "A" + "x" * 43])
def test_malformed_said_rejected(env, bad):
    client, issuer, *_ = env
    assert client.post(f"/credentials/{bad}/revoke").status_code == 422
    assert _status(client, bad).status_code == 422
    issuer.issuer.bridge.data_revoke.assert_not_called()


def test_revocations_survive_a_restart(env):
    client, _, store, tmp_path = env
    client.post(f"/credentials/{SAID}/revoke")
    reopened = RevocationStore(tmp_path / "revocations.db")
    assert reopened.get(SAID) is not None


def test_auth_mapping():
    assert "/credential-status" in PUBLIC_PATHS
    path = f"/credentials/{SAID}/revoke"
    required = next(p for m, rx, p in PERMISSION_MAP if m == "POST" and re.match(rx, path))
    assert required == WRITE_PERMISSION

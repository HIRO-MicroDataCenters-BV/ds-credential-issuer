"""POST /bootstrap/operator — one-time, token-guarded first-operator mint.

The issuer is mocked (no dkms binary or witness needed); settings are
overridden per test with a temp marker file.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.acdc_issuer import IssuedCredential
from app.core.dkms_bridge import DkmsBridgeError
from app.main import app
from app.rest_api.depends import acdc_issuer_dep, settings_dep
from app.settings import Settings

TOKEN = "t" * 40
OPERATOR = "EOperatorAID000000000000000000000000000000AA"
BODY = {"subject_aid": OPERATOR, "name": "First Operator", "email": "op@hus.example"}


def _issued() -> IssuedCredential:
    return IssuedCredential(
        acdc={"d": "ECredSAID", "i": "EIssuerAID"},
        said="ECredSAID",
        issuer_aid="EIssuerAID",
        subject_aid=OPERATOR,
        issuer_signature_qb64="A" * 88,
        cesr_stream="",
    )


@pytest.fixture
def env(tmp_path):
    """(client, issuer mock, settings) with a fresh marker path."""
    settings = Settings()
    settings.issuer.bootstrap_token = TOKEN
    settings.issuer.bootstrap_marker = tmp_path / "bootstrap-operator.done"
    issuer = MagicMock()
    issuer.issuer.name = "hus-issuer"
    issuer.issue.return_value = _issued()
    issuer.wrap_as_grant.return_value = {"acdc": {"d": "ECredSAID"}}
    app.dependency_overrides[acdc_issuer_dep] = lambda: issuer
    app.dependency_overrides[settings_dep] = lambda: settings
    yield TestClient(app), issuer, settings
    app.dependency_overrides.clear()


def _post(client, token=TOKEN, body=BODY):
    headers = {"X-Bootstrap-Token": token} if token is not None else {}
    return client.post("/bootstrap/operator", json=body, headers=headers)


def test_issues_operator_credential_once(env):
    client, issuer, settings = env
    r = _post(client)
    assert r.status_code == 200
    assert r.json()["subject_aid"] == OPERATOR
    attrs = issuer.issue.call_args.kwargs["attributes"]
    assert attrs["role"] == "operator"
    assert attrs["institute"] == "hiro"
    issuer.issuer.bridge.witness_kel.assert_called_once_with("hus-issuer", OPERATOR)
    assert settings.issuer.bootstrap_marker.exists()

    again = _post(client)
    assert again.status_code == 410
    assert issuer.issue.call_count == 1


def test_disabled_without_token(env):
    client, issuer, settings = env
    settings.issuer.bootstrap_token = ""
    assert _post(client).status_code == 404
    issuer.issue.assert_not_called()


def test_disabled_with_weak_token(env):
    client, _, settings = env
    settings.issuer.bootstrap_token = "short"
    assert _post(client, token="short").status_code == 404


@pytest.mark.parametrize("sent", [None, "", "wrong" * 10])
def test_rejects_missing_or_wrong_token(env, sent):
    client, issuer, settings = env
    assert _post(client, token=sent).status_code == 401
    issuer.issue.assert_not_called()
    assert not settings.issuer.bootstrap_marker.exists()


def test_rejects_subject_not_at_witness_and_stays_open(env):
    client, issuer, settings = env
    issuer.issuer.bridge.witness_kel.side_effect = DkmsBridgeError("no inception event")
    r = _post(client)
    assert r.status_code == 400
    assert "not anchored" in r.json()["detail"]
    issuer.issue.assert_not_called()
    assert not settings.issuer.bootstrap_marker.exists()  # can be retried


def test_issue_failure_releases_marker(env):
    client, issuer, settings = env
    issuer.wrap_as_grant.side_effect = DkmsBridgeError("witness unreachable")
    assert _post(client).status_code == 503
    assert not settings.issuer.bootstrap_marker.exists()
    issuer.wrap_as_grant.side_effect = None
    assert _post(client).status_code == 200


def test_bootstrap_path_is_public_for_ds_auth():
    from app.rest_api.auth_config import PUBLIC_PATHS

    assert "/bootstrap/operator" in PUBLIC_PATHS

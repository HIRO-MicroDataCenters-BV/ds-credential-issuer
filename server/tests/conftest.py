"""Shared test setup: the API with a mocked issuer and a real revocation store
in a temporary folder. ds-auth's identity headers are set by hand, as the
middleware would after checking the JWT."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.acdc_issuer import IssuedCredential
from app.core.revocations import RevocationStore
from app.main import app
from app.rest_api.depends import acdc_issuer_dep, revocation_store_dep, settings_dep
from app.settings import Settings

SUBJECT = "ESubjectAID0000000000000000000000000000000AA"
SCHEMA = "EA3UqX0yElhvuw-6fcAgr7gX58IOT8lK5VOqysjdR9hR"


def said_for(role: str) -> str:
    return ("E" + role.upper().replace("_", "") + "0" * 44)[:44]


@pytest.fixture
def env(tmp_path):
    settings = Settings()
    settings.auth.enabled = True     # routes check the caller's role
    settings.issuer.institute = "hus"
    store = RevocationStore(tmp_path / "revocations.db")
    issuer = MagicMock()
    issuer.issuer.name = "hus-issuer"

    def issue(subject_aid, schema_said, attributes):
        return IssuedCredential(acdc={}, said=said_for(attributes["role"]), issuer_aid="EIssuer",
                                subject_aid=subject_aid, issuer_signature_qb64="A" * 88, cesr_stream="")

    issuer.issue.side_effect = issue
    issuer.wrap_as_grant.return_value = {"acdc": {}}
    app.dependency_overrides.update({acdc_issuer_dep: lambda: issuer, settings_dep: lambda: settings,
                                     revocation_store_dep: lambda: store})
    yield TestClient(app), issuer, store
    app.dependency_overrides.clear()


def mint(client, caller_role, role, **attrs):
    body = {"subject_aid": SUBJECT, "schema_said": SCHEMA,
            "attributes": {"role": role, "name": "N", "email": "n@x", **attrs}}
    headers = {"X-User-Role": caller_role, "X-User-AID": f"E{caller_role}"} if caller_role else {}
    return client.post("/credentials", json=body, headers=headers)


def revoke(client, caller_role, said):
    return client.post(f"/credentials/{said}/revoke", json={}, headers={"X-User-Role": caller_role})

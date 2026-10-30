"""Request-schema tests — fast, no dkms-bin needed."""
import pytest
from pydantic import ValidationError

from app.rest_api.api_models import (
    IssueCredentialRequest,
    RegisterSchemaRequest,
)


def test_issue_request_rejects_missing_subject():
    with pytest.raises(ValidationError):
        IssueCredentialRequest(
            schema_said="ESchemaSAID",
            attributes={"role": "researcher"},
        )  # type: ignore[call-arg]


def test_issue_request_requires_attributes():
    with pytest.raises(ValidationError):
        IssueCredentialRequest(
            subject_aid="EUser",
            schema_said="ESchemaSAID",
        )  # type: ignore[call-arg]


def test_issue_request_accepts_arbitrary_attribute_shape():
    """The attribute block is schema-governed; we don't force a shape in
    the API — any JSON object goes through. Guards against over-coupling
    this service to one specific credential schema."""
    r = IssueCredentialRequest(
        subject_aid="EUser",
        schema_said="ESchemaSAID",
        attributes={
            "role": "researcher",
            "institute": "hus",
            "nested": {"ok": True, "levels": [1, 2, 3]},
        },
    )
    assert r.attributes["nested"]["levels"] == [1, 2, 3]


def test_register_schema_request_requires_said():
    with pytest.raises(ValidationError):
        RegisterSchemaRequest(schema_body={"type": "object"})  # type: ignore[call-arg]

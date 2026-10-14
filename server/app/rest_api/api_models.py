"""Request / response schemas for the issuer API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IssueCredentialRequest(BaseModel):
    """POST /credentials body.

    The caller specifies who the credential is being issued to
    (``subject_aid``), which schema it conforms to (``schema_said``), and
    the free-form attribute block that goes under ``a.a`` in the ACDC —
    typically role / institute / name / email for the login flow.
    """

    subject_aid: str = Field(..., description="AID the credential is bound to")
    schema_said: str = Field(..., description="SAID of a registered ACDC schema")
    attributes: dict[str, Any] = Field(
        ...,
        description=(
            "Attribute block for the ACDC's a.a field (role, institute, "
            "name, email, ...)"
        ),
    )


class IssueCredentialResponse(BaseModel):
    said: str = Field(..., description="SAID of the minted ACDC")
    issuer_aid: str
    subject_aid: str
    grant: dict[str, Any] = Field(
        ...,
        description=(
            "IPEX grant envelope the holder forwards to a verifier. "
            "Shape matches ds-login/app/core/ipex_grant.parse()."
        ),
    )


class CredentialSummary(BaseModel):
    said: str
    issuer_aid: str
    subject_aid: str
    schema_said: str
    issued_at: str
    revoked: bool


class RegisterSchemaRequest(BaseModel):
    said: str = Field(..., description="SAID of the schema being registered")
    # Name chosen to avoid shadowing BaseModel.schema; the body is a JSON
    # Schema document.
    schema_body: dict[str, Any] = Field(..., description="The JSON Schema document")


class SchemaSummary(BaseModel):
    said: str
    title: str | None = None
    registered_at: str


class PresentRequest(BaseModel):
    recipient_aid: str = Field(
        ...,
        description=(
            "AID the grant should be delivered to via mesagkesto"
        ),
    )

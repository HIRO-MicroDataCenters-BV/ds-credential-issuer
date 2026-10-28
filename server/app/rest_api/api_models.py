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


class BootstrapOperatorRequest(BaseModel):
    """POST /bootstrap/operator body: who becomes the first operator."""

    subject_aid: str = Field(..., description="Operator's AID, anchored at this site's witness")
    name: str = Field(..., description="Operator's name (credential claim)")
    email: str = Field(..., description="Operator's email (credential claim)")
    institute: str = Field("hiro", description="Institute claim; must match the policy rules")


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


SAID_PATTERN = r"^E[A-Za-z0-9_-]{43}$"


class RevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=500, description="Why it is revoked")


class RevokeResponse(BaseModel):
    said: str
    status: str = Field(description="Always `revoked`")
    revoked_at: str
    revoked_by: str
    reason: str
    already_revoked: bool = Field(description="True if it was revoked before this call")
    tel_anchored: bool = Field(
        description="Whether `dkms data revoke` also wrote the KERI TEL event"
    )


class CredentialStatusResponse(BaseModel):
    said: str
    status: str = Field(description="`revoked` or `not_revoked`")
    revoked_at: str | None = None

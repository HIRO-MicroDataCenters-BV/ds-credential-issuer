"""Credential lifecycle endpoints.

Phase 1 (this PR):
  * POST /credentials   — fully implemented, mints + wraps as IPEX grant

Phase 2 (follow-up PRs):
  * GET /credentials    — list for a subject (needs the TEL registry PR)
  * GET /credentials/{said}
  * POST /credentials/{said}/revoke
  * POST /credentials/{said}/present (deliver via mesagkesto)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from ...core.acdc_issuer import AcdcIssuer, IssueError
from ...core.dkms_bridge import DkmsBridgeError
from ..api_models import (
    CredentialSummary,
    IssueCredentialRequest,
    IssueCredentialResponse,
    PresentRequest,
)
from ..depends import acdc_issuer_dep

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credentials", tags=["credentials"])


@router.post("", response_model=IssueCredentialResponse)
def issue_credential(
    body: IssueCredentialRequest,
    issuer: AcdcIssuer = Depends(acdc_issuer_dep),
) -> IssueCredentialResponse:
    """Mint an ACDC bound to ``subject_aid`` and return it wrapped as an
    IPEX grant the holder can present to any ds-login verifier."""
    # Both issue() and wrap_as_grant() can raise DkmsBridgeError when
    # dkms-bin's state is unhealthy (watcher dropped EndRole after a
    # restart, witness unreachable, …). Wrap the whole pipeline so the
    # 503 fires for either phase instead of leaking a 500. The grant
    # won't verify at the holder's login time anyway without the
    # issuer's own KEL in it, so fail loudly here.
    try:
        issued = issuer.issue(
            subject_aid=body.subject_aid,
            schema_said=body.schema_said,
            attributes=body.attributes,
        )
        grant = issuer.wrap_as_grant(issued)
    except DkmsBridgeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except IssueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return IssueCredentialResponse(
        said=issued.said,
        issuer_aid=issued.issuer_aid,
        subject_aid=issued.subject_aid,
        grant=grant,
    )


# ─── Stubs (Phase 2 — tracked in ROADMAP) ────────────────────────────


@router.get("", response_model=list[CredentialSummary])
def list_credentials(
    subject: str | None = Query(default=None, description="Filter by subject AID"),
) -> list[CredentialSummary]:
    """List credentials issued by this issuer. **Phase 2 stub.**"""
    _ = subject
    raise HTTPException(
        status_code=501,
        detail="list_credentials not yet implemented — tracked in ROADMAP Phase 2",
    )


@router.get("/{said}", response_model=CredentialSummary)
def get_credential(said: str) -> CredentialSummary:
    """Fetch a credential's state. **Phase 2 stub.**"""
    _ = said
    raise HTTPException(
        status_code=501,
        detail="get_credential not yet implemented — tracked in ROADMAP Phase 2",
    )


@router.post("/{said}/revoke")
def revoke_credential(said: str) -> dict[str, str]:
    """Anchor a revocation event in the issuer's TEL. **Phase 2 stub.**"""
    _ = said
    raise HTTPException(
        status_code=501,
        detail=(
            "revoke_credential not yet implemented — needs TEL registry "
            "(ROADMAP Phase 2)"
        ),
    )


@router.post("/{said}/present")
def present_credential(said: str, body: PresentRequest) -> dict[str, str]:
    """Deliver the IPEX grant to ``recipient_aid`` via mesagkesto.
    **Phase 2 stub.**"""
    _ = said, body
    raise HTTPException(
        status_code=501,
        detail=(
            "present_credential not yet implemented — needs mesagkesto "
            "client (ROADMAP Phase 2)"
        ),
    )

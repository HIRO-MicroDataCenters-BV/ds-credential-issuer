"""Credential lifecycle endpoints.

Implemented:
  * POST /credentials   — mints + wraps as IPEX grant
  * POST /credentials/{said}/revoke — HIRO-side revocation list (+ dkms TEL)
  * GET /credential-status?said=… — public; ds-login asks before each login

Phase 2 (follow-up PRs):
  * GET /credentials    — list for a subject (needs the TEL registry PR)
  * GET /credentials/{said}
  * POST /credentials/{said}/present (deliver via mesagkesto)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from ...core.acdc_issuer import AcdcIssuer, IssueError
from ...core.dkms_bridge import DkmsBridgeError
from ...core.revocations import RevocationStore
from ..api_models import (
    SAID_PATTERN,
    CredentialStatusResponse,
    CredentialSummary,
    IssueCredentialRequest,
    IssueCredentialResponse,
    PresentRequest,
    RevokeRequest,
    RevokeResponse,
)
from ..depends import acdc_issuer_dep, revocation_store_dep

log = logging.getLogger(__name__)
router = APIRouter(prefix="/credentials", tags=["credentials"])
status_router = APIRouter(tags=["credentials"])

# ds-auth puts the caller's AID from the JWT here (client copies are stripped).
CALLER_AID_HEADER = "x-user-aid"


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


@router.post("/{said}/revoke", response_model=RevokeResponse)
def revoke_credential(
    request: Request,
    said: str = Path(pattern=SAID_PATTERN),
    body: RevokeRequest | None = None,
    issuer: AcdcIssuer = Depends(acdc_issuer_dep),
    revocations: RevocationStore = Depends(revocation_store_dep),
) -> RevokeResponse:
    """Revoke a credential. The HIRO-side list is authoritative (ds-login
    checks it); the KERI TEL event is written too, best effort, for when
    HCF's TEL can be read back. Revoking twice is harmless."""
    revoked_by = request.headers.get(CALLER_AID_HEADER, "unknown")
    record, newly = revocations.revoke(said, revoked_by, body.reason if body else "")

    tel_anchored = False
    if newly:
        log.warning("credential revoked: said=%s by=%s reason=%r",
                    said, revoked_by, record.reason)
        try:
            issuer.issuer.bridge.data_revoke(issuer.issuer.name, said)
            tel_anchored = True
        except DkmsBridgeError as e:
            log.warning("dkms data revoke failed for %s (list entry kept): %s", said, e)

    return RevokeResponse(
        said=said,
        status="revoked",
        revoked_at=record.revoked_at,
        revoked_by=record.revoked_by,
        reason=record.reason,
        already_revoked=not newly,
        tel_anchored=tel_anchored,
    )


@status_router.get("/credential-status", response_model=CredentialStatusResponse)
def credential_status(
    said: str = Query(pattern=SAID_PATTERN),
    revocations: RevocationStore = Depends(revocation_store_dep),
) -> CredentialStatusResponse:
    """Revoked or not, for one credential SAID. Public: verifiers ask here."""
    record = revocations.get(said)
    if record is None:
        return CredentialStatusResponse(said=said, status="not_revoked")
    return CredentialStatusResponse(said=said, status="revoked", revoked_at=record.revoked_at)


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

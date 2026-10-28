"""One-time bootstrap of the first operator.

Minting (``POST /credentials``) needs a JWT with ``issuer:write``, which
only an operator can get — so the first operator can't be minted through
the normal path. This endpoint closes that gap once:

  * Off unless ``DS__ISSUER__BOOTSTRAP_TOKEN`` is set (>= 32 chars) → 404.
  * Caller must send the token in ``X-Bootstrap-Token`` → 401 otherwise.
  * Single use: a marker file is claimed before issuing; afterwards every
    call answers 410. Issuing failures release the marker.
  * The subject AID must be anchored at this issuer's witness (ds-login
    only trusts KELs from its configured witnesses) → 400 otherwise.
  * The credential (``role=operator``) is signed by the site issuer, the
    same way ``POST /credentials`` signs, so ds-login's trusted-issuer list
    accepts it.

Remove the token from the deployment after use.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from ...core.acdc_issuer import AcdcIssuer, IssueError
from ...core.dkms_bridge import DkmsBridgeError
from ...settings import Settings
from ..api_models import BootstrapOperatorRequest, IssueCredentialResponse
from ..depends import acdc_issuer_dep, settings_dep

log = logging.getLogger(__name__)
router = APIRouter(prefix="/bootstrap", tags=["bootstrap"])

MIN_TOKEN_LENGTH = 32


@router.post("/operator", response_model=IssueCredentialResponse)
def bootstrap_operator(
    body: BootstrapOperatorRequest,
    x_bootstrap_token: str | None = Header(default=None),
    issuer: AcdcIssuer = Depends(acdc_issuer_dep),
    settings: Settings = Depends(settings_dep),
) -> IssueCredentialResponse:
    """Issue the first ``operator`` credential, once, with a secret token."""
    token = settings.issuer.bootstrap_token
    if len(token) < MIN_TOKEN_LENGTH:
        if token:
            log.error("bootstrap token shorter than %d chars; bootstrap disabled",
                      MIN_TOKEN_LENGTH)
        raise HTTPException(status_code=404, detail="Not Found")
    if not x_bootstrap_token or not hmac.compare_digest(
        x_bootstrap_token.encode(), token.encode()
    ):
        raise HTTPException(status_code=401, detail="invalid bootstrap token")

    marker = settings.issuer.bootstrap_marker
    try:
        # O_EXCL: of two concurrent calls only one can claim the marker.
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise HTTPException(
            status_code=410, detail="operator bootstrap has already been used"
        ) from None

    try:
        try:
            issuer.issuer.bridge.witness_kel(issuer.issuer.name, body.subject_aid)
        except DkmsBridgeError as e:
            raise HTTPException(
                status_code=400,
                detail=f"subject AID {body.subject_aid} is not anchored at this "
                       f"issuer's witness: {e}",
            ) from e
        try:
            issued = issuer.issue(
                subject_aid=body.subject_aid,
                schema_said="",
                attributes={
                    "role": "operator",
                    "institute": body.institute,
                    "name": body.name,
                    "email": body.email,
                },
            )
            grant = issuer.wrap_as_grant(issued)
        except DkmsBridgeError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        except IssueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    except BaseException:
        os.close(fd)
        os.unlink(marker)  # failed: allow another attempt
        raise

    record = {
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "subject_aid": issued.subject_aid,
        "credential_said": issued.said,
        "issuer_aid": issued.issuer_aid,
    }
    with os.fdopen(fd, "w") as f:
        json.dump(record, f)
    log.warning("BOOTSTRAP: operator credential %s issued to %s; bootstrap now "
                "closed — remove DS__ISSUER__BOOTSTRAP_TOKEN", issued.said,
                issued.subject_aid)
    return IssueCredentialResponse(
        said=issued.said,
        issuer_aid=issued.issuer_aid,
        subject_aid=issued.subject_aid,
        grant=grant,
    )

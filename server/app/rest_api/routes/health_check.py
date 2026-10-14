"""Liveness / readiness."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..depends import issuer_handle_dep

router = APIRouter(tags=["health"])


@router.get("/health-check/")
def health_check(issuer=Depends(issuer_handle_dep)) -> dict[str, str]:
    """Returns the issuer AID so a human can confirm the service bound to
    the AID they expected (per-site AIDs are long and easy to confuse)."""
    return {
        "status": "ok",
        "issuer_aid": issuer.aid,
        "issuer_name": issuer.name,
    }

"""Schema registry endpoints.

Full implementation lands in a follow-up PR. The scaffold defines the API
surface so ds-auth's permission map + the OpenAPI spec are stable from the
start.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..api_models import RegisterSchemaRequest, SchemaSummary

router = APIRouter(prefix="/schemas", tags=["schemas"])


@router.get("", response_model=list[SchemaSummary])
def list_schemas() -> list[SchemaSummary]:
    """List registered ACDC schemas. **Phase 2 stub.**"""
    raise HTTPException(
        status_code=501,
        detail="list_schemas not yet implemented — tracked in ROADMAP Phase 2",
    )


@router.get("/{said}", response_model=SchemaSummary)
def get_schema(said: str) -> SchemaSummary:
    """Fetch one schema. **Phase 2 stub.**"""
    _ = said
    raise HTTPException(
        status_code=501,
        detail="get_schema not yet implemented — tracked in ROADMAP Phase 2",
    )


@router.post("", response_model=SchemaSummary)
def register_schema(body: RegisterSchemaRequest) -> SchemaSummary:
    """Register a new ACDC schema in the local registry. **Phase 2 stub.**"""
    _ = body
    raise HTTPException(
        status_code=501,
        detail="register_schema not yet implemented — tracked in ROADMAP Phase 2",
    )

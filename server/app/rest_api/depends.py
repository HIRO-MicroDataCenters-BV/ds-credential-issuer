"""FastAPI dependency providers."""
from __future__ import annotations

from fastapi import Request

from ..core.acdc_issuer import AcdcIssuer
from ..core.issuer_habery import IssuerHandle
from ..settings import Settings, get_settings


def settings_dep() -> Settings:
    return get_settings()


def issuer_handle_dep(request: Request) -> IssuerHandle:
    """Return the open issuer habery handle, built once in the lifespan."""
    return request.app.state.issuer_handle  # type: ignore[no-any-return]


def acdc_issuer_dep(request: Request) -> AcdcIssuer:
    return request.app.state.acdc_issuer  # type: ignore[no-any-return]

"""ds-credential-issuer — FastAPI entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.acdc_issuer import AcdcIssuer
from .core.issuer_habery import close_habery, init_habery
from .rest_api.routes.credentials import router as credentials_router
from .rest_api.routes.health_check import router as health_router
from .rest_api.routes.schemas import router as schemas_router
from .settings import get_settings

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)

    log.info(
        "ds-credential-issuer starting · env=%s issuer_name=%s habery=%s",
        settings.environment, settings.issuer.name, settings.issuer.habery_path,
    )

    issuer_handle = init_habery(settings.issuer)
    app.state.issuer_handle = issuer_handle
    app.state.acdc_issuer = AcdcIssuer(
        issuer=issuer_handle, issuer_settings=settings.issuer
    )
    log.info("issuer ready: aid=%s", issuer_handle.aid)

    yield

    log.info("ds-credential-issuer shutting down")
    close_habery(issuer_handle)


settings = get_settings()

app = FastAPI(
    title="ds-credential-issuer",
    description=(
        "Per-node ACDC credential issuer for the Hiro dataspace. Mints "
        "verifiable credentials bound to subject AIDs, anchors them to a "
        "KERI TEL registry, and delivers IPEX grants that ds-login verifies "
        "under the open-federation trust model."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# --- CORS ---
_cors_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# --- Optional ds-auth middleware (same pattern as sibling services) ---
if settings.auth.enabled:
    if not settings.auth.jwks_url:
        raise RuntimeError(
            "DS__AUTH__ENABLED=true requires DS__AUTH__JWKS_URL to be set"
        )
    if not settings.auth.policy_engine_url:
        raise RuntimeError(
            "DS__AUTH__ENABLED=true requires DS__AUTH__POLICY_ENGINE_URL to be set"
        )

    try:
        from ds_auth import DataspaceAuthMiddleware
    except ImportError as e:
        raise RuntimeError(
            "DS__AUTH__ENABLED=true but ds-auth is not installed. "
            "Install with: poetry install --extras auth"
        ) from e

    from .rest_api.auth_config import PERMISSION_MAP, PUBLIC_PATHS

    app.add_middleware(
        DataspaceAuthMiddleware,
        jwks_url=settings.auth.jwks_url,
        issuer=settings.auth.jwt_issuer,
        audience=settings.auth.jwt_audience,
        policy_engine_url=settings.auth.policy_engine_url,
        permission_map=PERMISSION_MAP,
        public_paths=list(PUBLIC_PATHS),
    )


app.include_router(health_router)
app.include_router(credentials_router)
app.include_router(schemas_router)

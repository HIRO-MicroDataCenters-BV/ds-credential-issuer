"""ds-credential-issuer configuration.

All env vars use ``DS__`` prefix with ``__`` as the nested delimiter
(matching ds-catalog / ds-login convention)::

    DS__ENVIRONMENT=production
    DS__ISSUER__NAME=hus
    DS__ISSUER__HABERY_PATH=/var/lib/ds-credential-issuer/keystore
    DS__ISSUER__WITNESS_OOBIS=["https://dkms-witness-1.hus.nextgen.hiro-develop.nl/oobi/BxxxAid"]
    DS__ISSUER__MESAGKESTO_URL=http://ds-dkms-mesagkesto:8081
    DS__AUTH__ENABLED=true
    DS__AUTH__JWKS_URL=http://ds-login:8080/.well-known/jwks.json
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Issuer(BaseModel):
    """Issuer identity + supporting infrastructure.

    An issuer AID is derived from the keystore at ``habery_path`` (KERIpy
    LMDB). The AID is created on first boot by the ``init_habery`` helper;
    the resulting AID is logged and committed to ds-gitops so verifiers
    can allowlist / introduce via its OOBIs.
    """

    # Short name for this issuer — used as the KERIpy habitat alias and
    # the ``i`` field of minted ACDCs' chain-of-custody logs.
    name: str = Field(
        default="ds-credential-issuer",
        description="Issuer habitat alias; one issuer per site",
    )

    habery_path: Path = Field(
        default=Path("/var/lib/ds-credential-issuer/keystore"),
        description="Where KERIpy stores the issuer's LMDB keystore and TEL",
    )

    # Witnesses the issuer AID anchors to. Must be reachable from this pod
    # so inception / rotation / interaction events can be submitted.
    witness_urls: list[str] = Field(
        default_factory=list,
        description="Base URLs for KERI witnesses this issuer anchors to",
    )

    # KERI AIDs of those witnesses — KERIpy's makeHab(wits=...) wants AIDs,
    # not URLs. Must line up positionally with witness_urls. Without this
    # the issuer is minted self-sovereign (wits=[]) and no witness ever
    # stores its KEL — verifiers then cannot resolve the issuer OOBI.
    witness_aids: list[str] = Field(
        default_factory=list,
        description="AIDs of the witnesses the issuer anchors to",
    )

    # Externally-reachable OOBI base URLs the issuer embeds in outbound
    # grants. If empty, the issuer computes its own OOBIs at mint time
    # from (witness_url_external, issuer_aid) using the usual
    # keriox /oobi/<AID> convention. Set this only when the externally-
    # reachable OOBI base differs from the in-cluster witness_urls.
    witness_oobi_bases: list[str] = Field(
        default_factory=list,
        description=(
            "Externally-reachable witness base URLs for OOBI resolution. "
            "The issuer builds its own OOBI as '{base}/oobi/{issuer_aid}' "
            "per base. If empty, falls back to witness_urls."
        ),
    )

    # Legacy — explicit, pre-computed OOBI URLs. Only used when neither
    # witness_oobi_bases nor the auto-compute path is viable (e.g. a
    # custom OOBI endpoint shape).
    witness_oobis: list[str] = Field(
        default_factory=list,
        description=(
            "DEPRECATED. Explicit, pre-computed OOBI URLs. Prefer "
            "witness_oobi_bases so the issuer AID can be auto-filled."
        ),
    )

    # Mesagkesto message box used to deliver IPEX grants.
    mesagkesto_url: str = Field(
        default="",
        description="URL of the mesagkesto this issuer sends grants through",
    )

    # Signature threshold / rotation parameters — Phase 1 keeps a single
    # key; multi-sig issuance is Phase 2.
    inception_threshold: int = Field(1, description="Signing threshold at inception")

    # TTL for the schema registry cache (local SQLite copy of trusted schemas).
    schema_cache_ttl_seconds: int = Field(3600, description="Schema cache TTL")


class Auth(BaseModel):
    """Optional ds-auth integration (same shape as ds-policy-engine / ds-catalog)."""

    enabled: bool = False
    jwks_url: str = ""
    jwt_issuer: str = "ds-login"
    jwt_audience: str = "hiro-services"
    policy_engine_url: str = ""


class Settings(BaseSettings):
    """Service configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DS__",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    service_name: str = "ds-credential-issuer"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    environment: Literal["local", "dev", "staging", "production"] = "local"

    # Schema registry — SQLite by default; swap to Postgres via a DSN.
    database_url: str = "sqlite+aiosqlite:////var/lib/ds-credential-issuer/schemas.db"

    # CORS — comma-separated origins; empty disables middleware.
    cors_allowed_origins: str = ""

    # Pydantic knows every nested field has a default; mypy's view of
    # BaseModel.__init__ doesn't — ignore the generated call-arg warning.
    issuer: Issuer = Field(default_factory=lambda: Issuer())  # type: ignore[call-arg]
    auth: Auth = Field(default_factory=lambda: Auth())  # type: ignore[call-arg]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

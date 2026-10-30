"""ds-credential-issuer configuration.

All env vars use ``DS__`` prefix with ``__`` as the nested delimiter
(matching ds-catalog / ds-login convention)::

    DS__ENVIRONMENT=production
    DS__ISSUER__NAME=hus
    DS__ISSUER__DKMS_WITNESS_URL=http://ds-dkms-witness:3232
    DS__ISSUER__DKMS_WATCHER_URL=http://ds-dkms-watcher:3235
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

    The issuer AID lives in dkms-bin's store under ``dkms_home``. It is
    created on first boot by ``init_handle``; the resulting AID is logged
    and committed to ds-gitops so verifiers can allowlist / introduce via
    its OOBIs.
    """

    # Short name for this issuer — used as the dkms alias and
    # the ``i`` field of minted ACDCs' chain-of-custody logs.
    name: str = Field(
        default="ds-credential-issuer",
        description="Issuer's dkms alias; one issuer per site",
    )

    # ─── dkms-bin facade (preferred — matches HCF reference flow) ───
    # Phase 1 of the facade pivot delegates AID lifecycle + OOBI
    # publication + ACDC minting to the ``dkms`` CLI. The witness and
    # watcher URLs below are what ``dkms identifier init`` POSTs the
    # inception to and subscribes with. Only one of each per site.
    dkms_witness_url: str = Field(
        default="",
        description="URL of the witness this issuer anchors to",
    )
    dkms_watcher_url: str = Field(
        default="",
        description="URL of the watcher this issuer subscribes to",
    )
    dkms_witness_threshold: int = Field(
        default=1,
        description="Minimum number of witnesses to confirm a KEL event",
    )
    dkms_bin: Path = Field(
        default=Path("/usr/local/bin/dkms"),
        description="Where the dkms CLI binary lives in the container",
    )
    dkms_home: Path = Field(
        default=Path("/var/lib/ds-credential-issuer/dkms"),
        description="Where dkms stores its state (keystore, cached KELs)",
    )
    # OCA bundle SAID required by ``dkms data issue -b <...>``. Credentials
    # we mint all claim-shape against the same bundle for now; a per-schema
    # mapping is a follow-up PR when the schema registry lands.
    default_oca_bundle_said: str = Field(
        default="",
        description="OCA bundle SAID used for every ACDC we issue",
    )
    # One-time bootstrap of the first operator (POST /bootstrap/operator).
    # Off unless a token of at least 32 characters is set; meant to come
    # from a Kubernetes Secret and be removed after use.
    bootstrap_token: str = Field(
        default="",
        description="Secret for POST /bootstrap/operator; empty disables it",
    )
    bootstrap_marker: Path = Field(
        default=Path("/var/lib/ds-credential-issuer/bootstrap-operator.done"),
        description="Written when the operator bootstrap succeeded; blocks reuse",
    )
    # The site this issuer belongs to (hus, ki, uva; hiro on local kind). Set
    # = every credential's `institute` is this value (a different one in a
    # request is refused). Empty = the request's value is used as is.
    institute: str = Field(
        default="",
        description="Site name stamped as `institute` on every credential",
    )
    bootstrap_role: str = Field(
        default="site_admin",
        description="Role of the credential POST /bootstrap/operator issues",
    )
    revocation_db: Path = Field(
        default=Path("/var/lib/ds-credential-issuer/revocations.db"),
        description="SQLite file holding the HIRO-side revocation list",
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

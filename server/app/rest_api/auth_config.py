"""Permission map used when ds-auth is enabled on ds-credential-issuer.

Design:
  * Minting a credential (``POST /credentials``) is the most privileged
    operation this service exposes — only authorised node operators can
    do it. Gated behind ``issuer:write``.
  * Revoking a credential is same tier — ``issuer:write``.
  * Listing / fetching credentials and schemas is one tier lower:
    ``issuer:read``. Any authenticated caller with that permission can
    inspect what the issuer has done.
  * Registering a new schema is admin-tier (``issuer:admin``) because a
    rogue schema would let a bad actor change what verifiers accept.
  * Health, docs, OpenAPI, metrics stay public.
"""
from __future__ import annotations

WRITE_PERMISSION = "issuer:write"
READ_PERMISSION = "issuer:read"
ADMIN_PERMISSION = "issuer:admin"


# (METHOD, path regex, required permission). First match wins.
PERMISSION_MAP: list[tuple[str, str, str]] = [
    # Credentials — mint + lifecycle
    ("POST",   r"^/credentials/?$",                        WRITE_PERMISSION),
    ("GET",    r"^/credentials/?$",                        READ_PERMISSION),
    ("GET",    r"^/credentials/[^/]+/?$",                  READ_PERMISSION),
    ("POST",   r"^/credentials/[^/]+/revoke/?$",           WRITE_PERMISSION),
    ("POST",   r"^/credentials/[^/]+/present/?$",          WRITE_PERMISSION),
    # Schema registry
    ("GET",    r"^/schemas/?$",                            READ_PERMISSION),
    ("GET",    r"^/schemas/[^/]+/?$",                      READ_PERMISSION),
    ("POST",   r"^/schemas/?$",                            ADMIN_PERMISSION),
]


# Paths that bypass auth entirely — ops-only. The operator bootstrap is
# here because no operator JWT can exist yet; it is guarded by its own
# one-time token instead (see routes/bootstrap.py).
PUBLIC_PATHS: tuple[str, ...] = (
    "/bootstrap/operator",
    "/health-check",
    "/health-check/",
    "/metrics",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
)

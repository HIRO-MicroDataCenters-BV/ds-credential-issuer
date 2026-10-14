"""ACDC mint + IPEX grant wrapper.

The ``AcdcIssuer`` is the one place in the service that calls KERIpy's
credential primitives:

  * ``issue(subject_aid, schema_said, attributes)`` — builds an ACDC body
    with this issuer's AID in ``i``, the subject's AID in ``a.i``, the
    schema SAID in ``s``, and the caller's attributes in ``a.a``. Anchors
    an issuance event to the issuer's TEL registry so revocation state is
    on-chain. Signs the ACDC body with the issuer's current key. Returns
    the ACDC + the signature + the SAID.

  * ``wrap_as_grant(credential, subject_aid)`` — builds an IPEX grant
    envelope that ds-login's ``AcdcVerifier`` can consume: the ACDC body,
    the issuer's signature, and OOBIs the verifier needs to reach the
    issuer's witnesses.

Phase 1 (this PR): ``issue()`` returns a credential signed in-process;
``wrap_as_grant()`` emits the JSON shape ds-login expects. Full TEL
registry work and IPEX ``exn`` wrapping live in follow-up PRs so this
scaffold stays reviewable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..settings import Issuer as IssuerSettings
from .issuer_habery import IssuerHandle, KERIpyUnavailableError

log = logging.getLogger(__name__)


class IssueError(RuntimeError):
    """Credential could not be minted."""


@dataclass
class IssuedCredential:
    """Result of a successful mint."""

    said: str
    acdc: dict[str, Any]
    issuer_signature_qb64: str
    subject_aid: str
    issuer_aid: str


class AcdcIssuer:
    """Mint ACDCs and package them as IPEX grants."""

    def __init__(
        self,
        issuer: IssuerHandle,
        issuer_settings: IssuerSettings,
    ) -> None:
        self.issuer = issuer
        self.issuer_settings = issuer_settings

    # ─── Mint ────────────────────────────────────────────────────────────

    def issue(
        self,
        subject_aid: str,
        schema_said: str,
        attributes: dict[str, Any],
    ) -> IssuedCredential:
        """Mint an ACDC bound to ``subject_aid``.

        The ACDC body carries this issuer's AID in ``i``, the subject's AID
        in ``a.i``, the schema SAID in ``s``, and ``attributes`` in ``a.a``.
        SAID derivation + signing happen in-process via KERIpy.
        """
        try:
            from keri.core import coring, scheming  # noqa: F401
            from keri.vc import proving
        except Exception as e:
            raise KERIpyUnavailableError(
                f"KERIpy credential primitives unavailable: {e}"
            ) from e

        hab = self.issuer._hab
        try:
            creder = proving.credential(
                issuer=self.issuer.aid,
                schema=schema_said,
                recipient=subject_aid,
                data=attributes,
            )
            # Signature over the canonical ACDC bytes
            sig = hab.sign(ser=creder.raw, indexed=False)[0]
        except Exception as e:
            raise IssueError(f"KERIpy refused to mint credential: {e}") from e

        said = creder.said
        acdc_dict = dict(creder.crd)  # already in canonical shape

        log.info(
            "issued ACDC: said=%s subject=%s schema=%s",
            said, subject_aid, schema_said,
        )

        return IssuedCredential(
            said=said,
            acdc=acdc_dict,
            issuer_signature_qb64=sig.qb64,
            subject_aid=subject_aid,
            issuer_aid=self.issuer.aid,
        )

    # ─── Package as IPEX grant ──────────────────────────────────────────

    def wrap_as_grant(
        self,
        credential: IssuedCredential,
        registry_said: str | None = None,
    ) -> dict[str, Any]:
        """Produce the JSON grant envelope that ds-login's verifier reads.

        Shape intentionally matches ``ds-login/app/core/ipex_grant.py``.
        Full IPEX ``exn`` wrapping (so a wallet can forward the grant to
        a verifier via mesagkesto) is a follow-up PR.
        """
        return {
            "acdc": credential.acdc,
            "iss_sig": credential.issuer_signature_qb64,
            "iss_oobis": {
                "witness_urls": list(self.issuer_settings.witness_oobis),
                "witness_aids": [],  # populated when we parse the AIDs out of OOBIs
                "registry_said": registry_said,
                "tel_witness_urls": list(self.issuer_settings.witness_urls),
            },
        }

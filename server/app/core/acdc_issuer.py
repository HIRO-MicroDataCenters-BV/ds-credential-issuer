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
        # KERIpy 1.3.6: SerderACDC exposes the canonical self-addressing
        # data dict as `.sad` (not `.crd`, which was an older alias that
        # didn't survive the serdering refactor).
        acdc_dict = dict(creder.sad)

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

        ``iss_oobis.witness_urls`` carries URLs that resolve the ISSUER's
        own KEL (shape ``{witness_base}/oobi/{issuer_aid}``), not the
        witness's own OOBI. The verifier fetches those URLs, parses the
        CESR stream and extracts the issuer's current signing key — so
        they must point at the issuer, not at the witness.
        """
        issuer_oobis = self._issuer_oobi_urls()
        return {
            "acdc": credential.acdc,
            "iss_sig": credential.issuer_signature_qb64,
            "iss_oobis": {
                "witness_urls": issuer_oobis,
                "witness_aids": list(self.issuer_settings.witness_aids),
                "registry_said": registry_said,
                "tel_witness_urls": list(self.issuer_settings.witness_urls),
            },
        }

    def _issuer_oobi_urls(self) -> list[str]:
        """Compute OOBI URLs that resolve to the ISSUER's KEL.

        Resolution order:
          1. Explicit ``witness_oobis`` (legacy; usually pre-computed).
          2. ``{witness_oobi_bases[i]}/oobi/{issuer_aid}``
             (externally-reachable base per witness, if configured).
          3. ``{witness_urls[i]}/oobi/{issuer_aid}``
             (fallback to in-cluster witness URLs — only reachable from
             inside the cluster, which is fine for intra-site verifiers).
        """
        s = self.issuer_settings
        if s.witness_oobis:
            return list(s.witness_oobis)
        bases = list(s.witness_oobi_bases) or list(s.witness_urls)
        return [f"{base.rstrip('/')}/oobi/{self.issuer.aid}" for base in bases]

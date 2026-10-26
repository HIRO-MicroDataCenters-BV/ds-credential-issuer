"""ACDC mint + IPEX grant wrapper.

Delegates mint to HCF's ``dkms data issue`` via :mod:`.dkms_bridge`;
builds the IPEX grant envelope that ds-login's ``AcdcVerifier`` reads.

The ACDC JSON we hand to dkms-bin is in the HCF reference shape — claims
nested under ``a.a``, inner ``a.d`` left blank for dkms-bin to backfill.
On the ds-login side the verifier must accept both this and the KERIpy
``.a``-flat shape (see Rahul audit #8 follow-up).

Phase 1 of the facade pivot: ``issue()`` returns the signed CESR stream
from dkms-bin alongside the ACDC body; ``wrap_as_grant()`` carries the
watcher-served OOBI URLs that ``dkms identifier oobi get`` emits. TEL
registry work (``ri`` / ``registry_said``) and full IPEX ``exn`` wrapping
remain follow-up PRs.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from ..settings import Issuer as IssuerSettings
from .dkms_bridge import DkmsBridgeError
from .issuer_habery import IssuerHandle

log = logging.getLogger(__name__)


class IssueError(RuntimeError):
    """Credential could not be minted."""


@dataclass
class IssuedCredential:
    said: str
    acdc: dict[str, Any]
    """JSON body dkms-bin emitted after SAID backfill."""
    cesr_stream: str
    """Full CESR stream from dkms-bin (ACDC + signature attachments + OOBI prefix if any)."""
    issuer_signature_qb64: str
    """Qb64 signature extracted from the CESR stream, for grant.iss_sig."""
    subject_aid: str
    issuer_aid: str


class AcdcIssuer:
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
        oca_bundle_said: str | None = None,
    ) -> IssuedCredential:
        """Mint an ACDC bound to ``subject_aid`` via ``dkms data issue``."""
        bundle = oca_bundle_said or self.issuer_settings.default_oca_bundle_said
        if not bundle:
            raise IssueError(
                "no OCA bundle SAID — set issuer.default_oca_bundle_said or "
                "pass oca_bundle_said per call"
            )

        acdc = {
            "v": "ACDC10JSON000114_",
            "d": "",
            "i": self.issuer.aid,
            "ri": "",
            "s": schema_said,
            "a": {
                "d": "",
                "a": dict(attributes),
            },
        }

        try:
            cesr_stream = self.issuer.bridge.data_issue(
                alias=self.issuer.alias,
                acdc_json=acdc,
                oca_bundle_said=bundle,
                prepend_oobis=True,
            )
        except DkmsBridgeError as e:
            raise IssueError(f"dkms data issue failed: {e}") from e

        parsed = _parse_dkms_issue_output(cesr_stream)
        said = parsed.acdc.get("d", "")
        if not said:
            raise IssueError(
                f"dkms data issue returned an ACDC with no SAID (`d` empty): {parsed.acdc!r}"
            )

        log.info(
            "issued ACDC via dkms: said=%s subject=%s schema=%s",
            said, subject_aid, schema_said,
        )

        return IssuedCredential(
            said=said,
            acdc=parsed.acdc,
            cesr_stream=cesr_stream,
            issuer_signature_qb64=parsed.signature_qb64,
            subject_aid=subject_aid,
            issuer_aid=self.issuer.aid,
        )

    # ─── Package as IPEX grant ──────────────────────────────────────────

    def wrap_as_grant(
        self,
        credential: IssuedCredential,
        registry_said: str | None = None,
    ) -> dict[str, Any]:
        """Envelope the verifier reads.

        ``iss_oobis.witness_urls`` carries the watcher-served OOBI URLs
        from ``dkms identifier oobi get`` — those resolve to the ISSUER's
        KEL on a watcher the issuer subscribed with at init time.
        """
        try:
            oobis = self.issuer.bridge.identifier_oobi_get(self.issuer.alias)
        except DkmsBridgeError as e:
            log.warning("dkms identifier oobi get %r failed: %s",
                        self.issuer.alias, e)
            oobis = []

        return {
            "acdc": credential.acdc,
            "iss_sig": credential.issuer_signature_qb64,
            "iss_cesr_stream": credential.cesr_stream,
            "iss_oobis": {
                "witness_urls": oobis,
                "witness_aids": [],  # dkms-bin keeps those internal
                "registry_said": registry_said,
                "tel_witness_urls": [self.issuer.watcher_url],
            },
        }


# ─── CESR stream parsing ───────────────────────────────────────────────


@dataclass
class _DkmsIssueParsed:
    acdc: dict[str, Any]
    signature_qb64: str


_VERSION_RE = re.compile(rb'"v":"(?P<proto>ACDC|KERI)1[0-9]JSON(?P<size>[0-9a-f]{6})_"')


def _parse_dkms_issue_output(cesr_stream: str) -> _DkmsIssueParsed:
    """Pull the JSON ACDC body + the qb64 signature out of dkms' stdout.

    ``dkms data issue -o`` emits a CESR stream that looks like::

        <OOBIs (optional, when -o is passed)>
        {"v":"ACDC10JSON000...", ...}-FABE...-0AA...<sigs>...

    The JSON body is self-delimiting via its ``v`` header (``v`` carries
    the exact byte length), so we can split on it without touching the
    trailing CESR attachments.
    """
    raw = cesr_stream.encode("utf-8") if isinstance(cesr_stream, str) else cesr_stream
    m = _VERSION_RE.search(raw)
    if m is None:
        raise IssueError(
            f"dkms data issue output has no ACDC version header: {cesr_stream[:200]!r}"
        )
    size = int(m.group("size"), 16)
    # Walk back to the opening '{' of the JSON object the version header
    # belongs to (JSON parsers can't tell us where it starts).
    start = raw.rfind(b"{", 0, m.start()) if m.start() else raw.find(b"{")
    if start < 0:
        start = m.start()  # best-effort
    body_bytes = raw[start:start + size]
    try:
        import json
        acdc = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        raise IssueError(
            f"could not parse ACDC JSON out of dkms output: {e}; body={body_bytes[:200]!r}"
        ) from e

    tail = raw[start + size:].decode("utf-8", errors="replace")
    sig = _extract_signature_qb64(tail)
    return _DkmsIssueParsed(acdc=acdc, signature_qb64=sig)


def _extract_signature_qb64(tail: str) -> str:
    """Pull the first ``-AAB`` / ``-AAC`` indexed-sig attachment out of the
    CESR tail. Falls back to an empty string so a packaging bug surfaces
    as a verify-side failure rather than a mint-side crash.
    """
    i = tail.find("-AAB")
    if i < 0:
        i = tail.find("-AAC")
    if i < 0:
        return ""
    chunk = tail[i:]
    # qb64 index 'AAB'/'AAC' + 88 chars of base64url for an Ed25519 sig.
    return chunk[: 4 + 88]

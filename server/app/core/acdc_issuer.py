"""ACDC mint + IPEX grant wrapper.

Delegates mint to HCF's ``dkms data issue`` via :mod:`.dkms_bridge`;
builds the IPEX grant envelope that ds-login's ``AcdcVerifier`` reads.

Mint is a two-step dance against dkms-bin v0.8.2:

  1. ``dkms data issue -a <alias> -m <attrs>`` — dkms builds the ACDC
     envelope itself (issuer AID from the alias, schema SAID from the
     OCA bundle, ``d`` SAIDs backfilled). ``attrs`` is the user-facing
     claims dict PLUS the subject binding ``"i": subject_aid``. dkms
     wraps that whole dict as ``acdc.a.a``. The command emits the ACDC
     body only — no signature.
  2. ``dkms data sign -a <alias> -m <canonical acdc body>`` — produces
     the issuer signature CESR stream. We extract the qb64 signature
     and ship it as ``grant.iss_sig``.

ds-login's verifier reads subject + claims from ``acdc.a.a.*`` (HCF
nesting) with a fallback to the KERIpy flat ``acdc.a.*`` shape so the
old test fixtures still work.

Phase 1 of the facade pivot. TEL registry work (``ri`` / ``registry_said``)
and full IPEX ``exn`` wrapping remain follow-up PRs.
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
        schema_said: str,  # noqa: ARG002 — dkms derives schema from the OCA bundle
        attributes: dict[str, Any],
        oca_bundle_said: str | None = None,
    ) -> IssuedCredential:
        """Mint an ACDC bound to ``subject_aid`` via ``dkms data issue``.

        Two-step mint: ``data issue`` emits the ACDC body (no sig);
        ``data sign`` produces the issuer signature over that body.
        """
        bundle = oca_bundle_said or self.issuer_settings.default_oca_bundle_said
        if not bundle:
            raise IssueError(
                "no OCA bundle SAID — set issuer.default_oca_bundle_said or "
                "pass oca_bundle_said per call"
            )

        # Subject binding goes in the attribute dict as `i`; dkms wraps
        # the whole dict as `acdc.a.a` so this ends up at `acdc.a.a.i`.
        payload = {"i": subject_aid, **dict(attributes)}

        try:
            cesr_stream = self.issuer.bridge.data_issue(
                alias=self.issuer.alias,
                attributes=payload,
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

        # Sign the canonical ACDC body — the exact bytes the verifier will
        # re-serialize when checking the signature. dkms data issue emits
        # no sig of its own; this fills grant.iss_sig.
        acdc_body = parsed.acdc_bytes
        try:
            sign_output = self.issuer.bridge.data_sign(
                alias=self.issuer.alias, message=acdc_body,
            )
        except DkmsBridgeError as e:
            raise IssueError(f"dkms data sign failed: {e}") from e
        issuer_signature_qb64 = _extract_signature_qb64_from_sign(sign_output)
        if not issuer_signature_qb64:
            raise IssueError(
                f"dkms data sign returned no qb64 signature; output={sign_output[:200]!r}"
            )

        log.info(
            "issued ACDC via dkms: said=%s subject=%s sig=%s…",
            said, subject_aid, issuer_signature_qb64[:16],
        )

        return IssuedCredential(
            said=said,
            acdc=parsed.acdc,
            cesr_stream=cesr_stream,
            issuer_signature_qb64=issuer_signature_qb64,
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

        ``iss_oobis.oobi_objects`` carries the OOBI JSON objects from
        ``dkms identifier oobi get`` — a LocationScheme or EndRole per
        entry, consumed by HCF's ``mesagkesto /resolve`` endpoint.

        ``iss_kel_cesr`` carries the issuer's own KEL as a CESR stream
        (icp + witness receipts) so a KERIpy-based verifier can parse
        it in-process without an OOBI round-trip. Verifiers that trust
        inline KEL must still check the issuer AID against the KEL
        root (``i`` of the icp event).

        Legacy ``witness_urls`` is retained as stringified JSON of the
        OOBI objects for one more PR, so a transitional ds-login
        verifier can echo them back for diagnostics.
        """
        try:
            oobi_objects = self.issuer.bridge.identifier_oobi_get(self.issuer.alias)
        except DkmsBridgeError as e:
            log.warning("dkms identifier oobi get %r failed: %s",
                        self.issuer.alias, e)
            oobi_objects = []

        try:
            iss_kel_cesr = self.issuer.bridge.log_kel_find(
                self.issuer.name, self.issuer.aid,
            )
        except DkmsBridgeError as e:
            log.warning("dkms log kel find %s failed: %s",
                        self.issuer.aid, e)
            iss_kel_cesr = ""

        import json as _json
        return {
            "acdc": credential.acdc,
            "iss_sig": credential.issuer_signature_qb64,
            "iss_cesr_stream": credential.cesr_stream,
            "iss_kel_cesr": iss_kel_cesr,
            "iss_oobis": {
                # Phase 1 shape — JSON objects per dkms-bin.
                "oobi_objects": oobi_objects,
                # Legacy — kept during the migration, now stringified
                # objects rather than URLs.
                "witness_urls": [
                    _json.dumps(o, separators=(",", ":"))
                    for o in oobi_objects
                ],
                "witness_aids": [],
                "registry_said": registry_said,
                "tel_witness_urls": [self.issuer.watcher_url],
            },
        }


# ─── CESR stream parsing ───────────────────────────────────────────────


@dataclass
class _DkmsIssueParsed:
    acdc: dict[str, Any]
    acdc_bytes: bytes
    """Exact bytes of the ACDC body, as they appeared in dkms' stdout.

    These are the bytes we hand to :meth:`DkmsBridge.data_sign` so the
    signature is over the same byte string the verifier canonicalises
    from the parsed JSON — otherwise byte-level JSON drift (key order,
    whitespace, number formatting) silently invalidates every grant.
    """


_VERSION_RE = re.compile(rb'"v":"(?P<proto>ACDC|KERI)1[0-9]JSON(?P<size>[0-9a-f]{6})_"')


def _parse_dkms_issue_output(cesr_stream: str) -> _DkmsIssueParsed:
    """Pull the JSON ACDC body out of ``dkms data issue`` stdout.

    ``dkms data issue -o`` emits::

        <log noise>
        <OOBI JSON objects, one per line>
        {"v":"ACDC10JSON000...", ...<rest of ACDC body>}

    The ACDC body is self-delimiting via its ``v`` header (the size field
    is the exact byte count), so we locate the version marker and read
    exactly that many bytes. ``data issue`` emits NO signature — that's
    what ``data sign`` is for.
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

    return _DkmsIssueParsed(acdc=acdc, acdc_bytes=body_bytes)


def _extract_signature_qb64_from_sign(output: str) -> str:
    """Pull the first qb64 signature out of ``dkms data sign`` stdout.

    ``dkms data sign`` echoes the message bytes then appends CESR
    attachments. The attachments carry either an indexed sig (prefix
    ``-AAB`` / ``-AAC``, 88-char body) or an unindexed Ed25519 sig
    (code ``0B`` or ``0A``, 88 chars total including the 2-char code).

    Returns an empty string if neither shape is found — callers raise
    an IssueError so the mint fails loudly rather than ship an empty
    ``iss_sig`` that would cost a verifier-side debugging session.
    """
    # Indexed-sig CESR attachment first (what KERIpy expects for KEL events).
    for marker in ("-AAB", "-AAC"):
        i = output.find(marker)
        if i >= 0:
            # 4-char attachment code + 88-char Ed25519 sig body.
            chunk = output[i:i + 4 + 88]
            if len(chunk) == 4 + 88:
                return chunk
    # Unindexed Ed25519 (bare qb64 sig, 88 chars including the 2-char code).
    for marker in ("0B", "0A"):
        i = output.find(marker)
        while i >= 0:
            # Reject digits-prefixed hits (ACDC sizes, byte counts, etc.) —
            # a real qb64 sig code is at a word boundary.
            prev = output[i - 1] if i > 0 else ""
            if not (prev.isalnum() or prev in "_-"):
                return output[i:i + 88]
            i = output.find(marker, i + 1)
    return ""


def _extract_signature_qb64(tail: str) -> str:
    """Legacy name kept for any external callers.

    Delegates to :func:`_extract_signature_qb64_from_sign`.
    """
    i = tail.find("-AAB")
    if i < 0:
        i = tail.find("-AAC")
    if i < 0:
        return ""
    chunk = tail[i:]
    # qb64 index 'AAB'/'AAC' + 88 chars of base64url for an Ed25519 sig.
    return chunk[: 4 + 88]

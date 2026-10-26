"""Unit tests for AcdcIssuer.

The real DkmsBridge shells out to dkms-bin, which needs a live witness
and watcher — out of scope for a unit test. We mock the bridge and
assert that:
  * the attributes dict passed to ``data_issue`` carries ``i`` for the
    subject binding (so the dkms-bin output has ``acdc.a.a.i``)
  * ``data_sign`` is called with the EXACT bytes of the ACDC body dkms
    emitted (so the verifier can round-trip the serialization)
  * the qb64 signature extracted from the sign-step output lands in
    ``IssuedCredential.issuer_signature_qb64``
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.acdc_issuer import (
    AcdcIssuer,
    IssueError,
    _extract_signature_qb64_from_sign,
    _parse_dkms_issue_output,
)


@dataclass
class _FakeHandle:
    alias: str = "hus-issuer"
    aid: str = "EIssuerAID00000000000000000000000000000000AA"
    name: str = "hus-issuer"
    watcher_url: str = "http://watcher.local:3235"
    bridge: Any = field(default_factory=MagicMock)


@dataclass
class _FakeIssuerSettings:
    default_oca_bundle_said: str = "EBundleSAID0000000000000000000000000000000AA"


_FAKE_ACDC_BODY = (
    b'{"v":"ACDC10JSON00017f_",'
    b'"d":"ECredSAID0000000000000000000000000000000000AA",'
    b'"i":"EIssuerAID00000000000000000000000000000000AA",'
    b'"ri":"ERegistrySAID00000000000000000000000000000AA",'
    b'"s":"EBundleSAID0000000000000000000000000000000AA",'
    b'"a":{"d":"EAttrsSAID0000000000000000000000000000000AA",'
    b'"a":{"i":"ESubjectAID0000000000000000000000000000000AA",'
    b'"role":"researcher","institute":"hiro"}}}'
)
# version header declares exact body byte count (0x17f = 383)
assert len(_FAKE_ACDC_BODY) == 0x17f

_FAKE_EXPECTED_SIG = "-AAB" + "A" * 88
assert len(_FAKE_EXPECTED_SIG) == 92

_FAKE_SIGN_OUTPUT = _FAKE_ACDC_BODY.decode("utf-8") + _FAKE_EXPECTED_SIG


def _make_issuer() -> tuple[AcdcIssuer, MagicMock]:
    bridge = MagicMock()
    bridge.data_issue.return_value = _FAKE_ACDC_BODY.decode("utf-8")
    bridge.data_sign.return_value = _FAKE_SIGN_OUTPUT
    handle = _FakeHandle(bridge=bridge)
    return AcdcIssuer(issuer=handle, issuer_settings=_FakeIssuerSettings()), bridge


def test_issue_passes_subject_aid_into_attributes():
    issuer, bridge = _make_issuer()

    issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored-dkms-reads-from-bundle",
        attributes={"role": "researcher", "institute": "hiro"},
    )

    bridge.data_issue.assert_called_once()
    kwargs = bridge.data_issue.call_args.kwargs
    assert kwargs["alias"] == "hus-issuer"
    attrs = kwargs["attributes"]
    assert attrs["i"] == "ESubjectAID0000000000000000000000000000000AA"
    assert attrs["role"] == "researcher"
    assert attrs["institute"] == "hiro"


def test_issue_signs_the_exact_acdc_body_bytes():
    """The verifier re-serializes the parsed ACDC and verifies the sig
    against those bytes. If we sign anything other than the EXACT bytes
    dkms emitted, byte-level JSON drift (key order, whitespace, number
    formatting) silently invalidates every grant."""
    issuer, bridge = _make_issuer()

    issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )

    bridge.data_sign.assert_called_once()
    kwargs = bridge.data_sign.call_args.kwargs
    assert kwargs["alias"] == "hus-issuer"
    assert kwargs["message"] == _FAKE_ACDC_BODY


def test_issue_extracts_signature_from_sign_output():
    issuer, _ = _make_issuer()

    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )

    assert issued.issuer_signature_qb64 == _FAKE_EXPECTED_SIG
    assert issued.subject_aid == "ESubjectAID0000000000000000000000000000000AA"
    assert issued.issuer_aid == "EIssuerAID00000000000000000000000000000000AA"
    assert issued.said == "ECredSAID0000000000000000000000000000000000AA"


def test_issue_fails_loudly_when_sign_output_has_no_signature():
    issuer, bridge = _make_issuer()
    bridge.data_sign.return_value = _FAKE_ACDC_BODY.decode("utf-8")  # no attachment

    with pytest.raises(IssueError, match="data sign returned no qb64 signature"):
        issuer.issue(
            subject_aid="ESubjectAID0000000000000000000000000000000AA",
            schema_said="ignored",
            attributes={"role": "researcher"},
        )


def test_issue_fails_when_acdc_has_no_said():
    """dkms occasionally emits a body with d="" when the OCA bundle SAID
    is unknown or the attribute payload is malformed. Our mint must
    reject it loudly rather than ship a credential with no identity."""
    issuer, bridge = _make_issuer()
    # Shrink the body to exactly rewrite the SAID placeholder to empty.
    short_body = (
        b'{"v":"ACDC10JSON0000ad_",'
        b'"d":"",'
        b'"i":"EIssuerAID00000000000000000000000000000000AA",'
        b'"s":"EBundleSAID0000000000000000000000000000000AA",'
        b'"a":{"d":"","a":{"role":"researcher"}}}'
    )
    assert len(short_body) == 0xad
    bridge.data_issue.return_value = short_body.decode("utf-8")

    with pytest.raises(IssueError, match="SAID"):
        issuer.issue(
            subject_aid="ESubjectAID0000000000000000000000000000000AA",
            schema_said="ignored",
            attributes={"role": "researcher"},
        )


# ─── _parse_dkms_issue_output ────────────────────────────────────────────


def test_parse_dkms_issue_output_tolerates_oobi_prefix():
    """dkms data issue -o prepends OOBI JSON objects and log noise."""
    noise = (
        "Registering out of order escrow with timeout: 60s\n"
        '{"eid":"BEid00","scheme":"http","url":"http://w.local/"}'
        + _FAKE_ACDC_BODY.decode("utf-8")
    )
    parsed = _parse_dkms_issue_output(noise)
    assert parsed.acdc["d"] == "ECredSAID0000000000000000000000000000000000AA"
    assert parsed.acdc_bytes == _FAKE_ACDC_BODY


def test_parse_dkms_issue_output_raises_on_missing_version_header():
    with pytest.raises(IssueError, match="version header"):
        _parse_dkms_issue_output("no version marker here")


# ─── _extract_signature_qb64_from_sign ────────────────────────────────────


def test_extract_signature_prefers_indexed_sig():
    sig = "-AAB" + "A" * 88
    assert _extract_signature_qb64_from_sign("prefix " + sig + " suffix") == sig


def test_extract_signature_returns_empty_when_absent():
    assert _extract_signature_qb64_from_sign("no attachment anywhere") == ""


def test_extract_signature_skips_mid_word_matches_for_unindexed():
    """'0B' at a mid-word position (e.g. inside '00011a_B...') is not a
    real qb64 sig code — the extractor must skip it."""
    # The ACDC version '00011a_B' CAN look like a '0B' prefix at an inner
    # position; the extractor rejects anything preceded by alnum/_/-.
    body = '{"v":"ACDC10JSON00011a_"}'
    # Add a real unindexed sig at a word boundary.
    real_sig = "0B" + "A" * 86
    out = body + "\n" + real_sig
    assert _extract_signature_qb64_from_sign(out) == real_sig

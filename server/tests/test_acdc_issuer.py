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
    _build_oobi_urls,
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

_FAKE_EXPECTED_SIG = "A" * 88
assert len(_FAKE_EXPECTED_SIG) == 88
# dkms data sign emits "<message>-AAB<88-char sig body>"; the issuer
# strips the -AAB counter and ships just the 88-char body.
_FAKE_SIGN_ATTACHMENT = "-AAB" + _FAKE_EXPECTED_SIG

_FAKE_SIGN_OUTPUT = _FAKE_ACDC_BODY.decode("utf-8") + _FAKE_SIGN_ATTACHMENT


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


# ─── wrap_as_grant: fail-loud when KEL unavailable (Rahul audit #3) ─────


def _make_issuer_with_kel(kel_response, witness_kel=None):
    """Issuer whose bridge.log_kel_find behaves as `kel_response`:
    - str  → returned as-is
    - Exception subclass → raised when called
    - callable → called

    ``witness_kel`` is what bridge.witness_kel returns; by default it
    raises, so these tests exercise the watcher fallback.
    """
    from app.core.dkms_bridge import DkmsBridgeError

    bridge = MagicMock()
    bridge.data_issue.return_value = _FAKE_ACDC_BODY.decode("utf-8")
    bridge.data_sign.return_value = _FAKE_SIGN_OUTPUT
    bridge.identifier_oobi_get.return_value = []
    if witness_kel is None:
        bridge.witness_kel.side_effect = DkmsBridgeError("no witness answered")
    else:
        bridge.witness_kel.return_value = witness_kel
    if isinstance(kel_response, Exception):
        bridge.log_kel_find.side_effect = kel_response
    else:
        bridge.log_kel_find.return_value = kel_response
    handle = _FakeHandle(bridge=bridge)
    return AcdcIssuer(issuer=handle, issuer_settings=_FakeIssuerSettings()), bridge


def test_wrap_as_grant_raises_when_dkms_log_kel_find_fails():
    """Seen in HUS right after watcher restart: `dkms log kel find`
    errored with 'role Watcher missing'. Previously we logged a warning
    and shipped iss_kel_cesr="". The grant looked 200 OK to the operator
    but every holder presenting it got rejected at verify time. Now the
    exception propagates — the /credentials route maps DkmsBridgeError
    to 503, surfacing the real problem to the operator's monitoring."""
    from app.core.dkms_bridge import DkmsBridgeError

    issuer, _ = _make_issuer_with_kel(DkmsBridgeError("role Watcher missing"))
    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )
    with pytest.raises(DkmsBridgeError, match="role Watcher missing"):
        issuer.wrap_as_grant(issued)


def test_wrap_as_grant_raises_when_dkms_log_kel_find_returns_empty():
    """Guard against a future dkms-bin that returns exit 0 but an empty
    stream (dkms init already has that failure mode). Still a 503."""
    from app.core.dkms_bridge import DkmsBridgeError

    issuer, _ = _make_issuer_with_kel("")  # empty stream
    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )
    with pytest.raises(DkmsBridgeError, match="empty CESR stream"):
        issuer.wrap_as_grant(issued)


def test_wrap_as_grant_ok_when_log_kel_find_returns_stream():
    """Happy path: bridge returns a KEL stream, grant carries it as
    iss_kel_cesr. Regression against the fail-loud path being too
    aggressive."""
    issuer, _ = _make_issuer_with_kel(
        '{"v":"KERI10JSON000159_","t":"icp","d":"EN8anz...","i":"EN8anz..."}'
        '-AAB' + 'A' * 88
    )
    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )
    grant = issuer.wrap_as_grant(issued)
    assert grant["iss_kel_cesr"].startswith('{"v":"KERI10JSON')


_ICP = '{"v":"KERI10JSON000159_","t":"icp","d":"EIssuer","i":"EIssuer","s":"0"}-AAB' + "A" * 88


def test_wrap_as_grant_reads_kel_from_witness_first():
    """The witness answers even after a watcher restart, so it is asked
    first and `dkms log kel find` (via the watcher) is not needed."""
    from app.core.dkms_bridge import DkmsBridgeError

    issuer, bridge = _make_issuer_with_kel(
        DkmsBridgeError("role Watcher missing"), witness_kel=_ICP,
    )
    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )
    grant = issuer.wrap_as_grant(issued)
    assert grant["iss_kel_cesr"] == _ICP
    bridge.log_kel_find.assert_not_called()


def test_wrap_as_grant_falls_back_to_watcher_and_drops_rpy():
    """Witnesses unreachable: the watcher's KEL is used, with any non-KEL
    message (a witness rpy) removed so ds-login's KEL walker accepts it."""
    rpy = '{"v":"KERI10JSON000113_","t":"rpy","d":"EReply","r":"/loc/scheme"}-CAB' + "B" * 132
    issuer, bridge = _make_issuer_with_kel(_ICP + rpy)
    issued = issuer.issue(
        subject_aid="ESubjectAID0000000000000000000000000000000AA",
        schema_said="ignored",
        attributes={"role": "researcher"},
    )
    grant = issuer.wrap_as_grant(issued)
    assert grant["iss_kel_cesr"] == _ICP
    bridge.log_kel_find.assert_called_once()


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
    """Returns just the 88-char sig body, not the ``-AAB`` counter prefix.

    The counter is a CESR stream-framing primitive and would trip the
    verifier's ``Siger(qb64=...)`` constructor ("Unexpected count code
    start while extracting Matter"). Ship just the signature itself.
    """
    body = "A" * 88
    attachment = "-AAB" + body
    assert _extract_signature_qb64_from_sign("prefix " + attachment + " suffix") == body


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


# ─── _build_oobi_urls (Rahul audit #4) ──────────────────────────────────


_ISSUER_AID = "EDi8bCl_7IiF5Au18-adTDcVabJcaxciZuLA-6mWF0lo"
_REGISTRY_AID = "EKD3sfPYtpbDrrO4k3WAVVu3YEve1NBDUZAU9BDdE1bF"
_WITNESS_AID = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"


def test_build_oobi_urls_pairs_locationscheme_with_endrole():
    """dkms-bin emits a flat list mixing LocationScheme and EndRole
    entries. Build a real HTTP OOBI URL for each (location, endrole)
    pair that names this issuer as the controller."""
    objects = [
        {"eid": _WITNESS_AID, "scheme": "http",
         "url": "http://ds-dkms-witness-1:3232/"},
        {"cid": _ISSUER_AID, "role": "witness", "eid": _WITNESS_AID},
    ]
    urls = _build_oobi_urls(objects, _ISSUER_AID)
    assert urls == [
        f"http://ds-dkms-witness-1:3232/oobi/{_ISSUER_AID}/witness/{_WITNESS_AID}"
    ]


def test_build_oobi_urls_filters_out_registry_endrole():
    """dkms-bin includes an EndRole for the TEL registry too. The
    registry's cid is NOT the issuer AID, so it must not leak into
    the witness URL set — the previous code shipped it, Rahul
    audit #4."""
    objects = [
        {"eid": _WITNESS_AID, "scheme": "http",
         "url": "http://ds-dkms-witness-1:3232/"},
        {"cid": _ISSUER_AID,  "role": "witness", "eid": _WITNESS_AID},
        {"cid": _REGISTRY_AID, "role": "witness", "eid": _WITNESS_AID},
    ]
    urls = _build_oobi_urls(objects, _ISSUER_AID)
    assert len(urls) == 1
    assert _REGISTRY_AID not in urls[0]


def test_build_oobi_urls_skips_endrole_without_location():
    """An EndRole whose eid has no matching LocationScheme would produce
    a URL with no base — skip rather than ship a broken one."""
    objects = [
        # No LocationScheme for _WITNESS_AID.
        {"cid": _ISSUER_AID, "role": "witness", "eid": _WITNESS_AID},
    ]
    assert _build_oobi_urls(objects, _ISSUER_AID) == []


def test_build_oobi_urls_tolerates_url_without_trailing_slash():
    """Some LocationScheme emitters omit the trailing slash on url;
    make the joined URL work either way."""
    objects = [
        {"eid": _WITNESS_AID, "scheme": "http",
         "url": "http://ds-dkms-witness-1:3232"},   # no trailing /
        {"cid": _ISSUER_AID, "role": "witness", "eid": _WITNESS_AID},
    ]
    urls = _build_oobi_urls(objects, _ISSUER_AID)
    assert urls == [
        f"http://ds-dkms-witness-1:3232/oobi/{_ISSUER_AID}/witness/{_WITNESS_AID}"
    ]


def test_build_oobi_urls_handles_empty_input():
    assert _build_oobi_urls([], _ISSUER_AID) == []
    assert _build_oobi_urls([{}], _ISSUER_AID) == []
    assert _build_oobi_urls([{"junk": "data"}], _ISSUER_AID) == []

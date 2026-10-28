"""Unit tests for the witness KEL lookup in DkmsBridge.

No dkms binary or witness is needed: ``identifier_info`` and the HTTP
call are replaced. The stream shapes follow what a keriox 0.17.13
witness returns at ``/oobi/<aid>/witness/<eid>``: the KEL events, each
with its attachments, then the witness's own ``rpy`` location reply.
"""
from __future__ import annotations

import httpx
import pytest

from app.core.dkms_bridge import (
    DkmsBridge,
    DkmsBridgeError,
    IdentifierInfo,
    kel_events_only,
)

AID = "EIssuerAID00000000000000000000000000000000AA"
WITNESS = "BWitness000000000000000000000000000000000AAA"

ICP = ('{"v":"KERI10JSON000159_","t":"icp","d":"' + AID + '","i":"' + AID
       + '","s":"0","b":["' + WITNESS + '"]}-AAB' + "A" * 88 + "-CAB" + "C" * 132)
IXN = ('{"v":"KERI10JSON0000cb_","t":"ixn","d":"EIxn","i":"' + AID
       + '","s":"1"}-AAB' + "A" * 88 + "-CAB" + "C" * 132)
RPY = ('{"v":"KERI10JSON000113_","t":"rpy","d":"EReply","r":"/loc/scheme",'
       '"a":{"eid":"' + WITNESS + '"}}-CAB' + "C" * 132)


def test_kel_events_only_drops_witness_rpy():
    assert kel_events_only(ICP + IXN + RPY) == ICP + IXN


def test_kel_events_only_drops_leading_log_noise():
    noise = "Registering out of order escrow with timeout: 60s\n"
    assert kel_events_only(noise + ICP) == ICP


def test_kel_events_only_empty_when_no_kel_event():
    assert kel_events_only(RPY) == ""
    assert kel_events_only("") == ""


class _Response:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def _bridge(monkeypatch, witnesses, responses):
    """A DkmsBridge without a dkms binary; GETs answered from `responses`
    (url -> _Response or Exception)."""
    bridge = DkmsBridge.__new__(DkmsBridge)
    monkeypatch.setattr(
        bridge, "identifier_info",
        lambda alias: IdentifierInfo(alias=alias, aid=AID, witness_urls=witnesses,
                                     watcher_urls=[]),
    )
    calls = []

    def fake_get(url, timeout):
        calls.append(url)
        r = responses[url]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(httpx, "get", fake_get)
    return bridge, calls


def test_witness_kel_returns_kel_without_rpy(monkeypatch):
    url = f"http://ds-dkms-witness-1:3232/oobi/{AID}/witness/{WITNESS}"
    bridge, calls = _bridge(
        monkeypatch,
        [{"eid": WITNESS, "scheme": "http", "url": "http://ds-dkms-witness-1:3232/"}],
        {url: _Response(200, ICP + IXN + RPY)},
    )
    assert bridge.witness_kel("hus-issuer", AID) == ICP + IXN
    assert calls == [url]


def test_witness_kel_tries_next_witness(monkeypatch):
    w2 = "BWitness2" + "0" * 35
    url1 = f"http://w1:3232/oobi/{AID}/witness/{WITNESS}"
    url2 = f"http://w2:3232/oobi/{AID}/witness/{w2}"
    bridge, calls = _bridge(
        monkeypatch,
        [{"eid": WITNESS, "url": "http://w1:3232/"}, {"eid": w2, "url": "http://w2:3232"}],
        {url1: httpx.ConnectError("refused"), url2: _Response(200, ICP + RPY)},
    )
    assert bridge.witness_kel("hus-issuer", AID) == ICP
    assert calls == [url1, url2]


def test_witness_kel_rejects_kel_of_another_identifier(monkeypatch):
    url = f"http://w1:3232/oobi/{AID}/witness/{WITNESS}"
    other = ICP.replace(AID, "EOther" + "0" * 38)
    bridge, _ = _bridge(
        monkeypatch,
        [{"eid": WITNESS, "url": "http://w1:3232/"}],
        {url: _Response(200, other + RPY)},
    )
    with pytest.raises(DkmsBridgeError, match="no inception event"):
        bridge.witness_kel("hus-issuer", AID)


def test_witness_kel_raises_when_no_witness_answers(monkeypatch):
    url = f"http://w1:3232/oobi/{AID}/witness/{WITNESS}"
    bridge, _ = _bridge(
        monkeypatch,
        [{"eid": WITNESS, "url": "http://w1:3232/"}],
        {url: _Response(404, "")},
    )
    with pytest.raises(DkmsBridgeError, match="HTTP 404"):
        bridge.witness_kel("hus-issuer", AID)


def test_witness_kel_raises_without_witnesses(monkeypatch):
    bridge, _ = _bridge(monkeypatch, [], {})
    with pytest.raises(DkmsBridgeError, match="no witness URLs"):
        bridge.witness_kel("hus-issuer", AID)

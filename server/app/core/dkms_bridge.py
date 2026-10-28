"""Thin subprocess wrapper around HCF's ``dkms`` CLI binary.

Facade over the parts of KERI protocol operation that we delegate to
dkms-bin per Rahul's audit and the pivot to the facade pattern:

  * ``identifier init`` — AID enrolment with active witness receipting
    and watcher subscription (what plain KERIpy ``makeHab`` cannot do).
  * ``identifier info`` — read back the AID of a known alias.
  * ``identifier oobi get`` — the issuer's watcher-served OOBI URLs
    that we embed in outbound IPEX grants.
  * ``data issue`` — build + sign an ACDC in the HCF reference shape
    (payload under ``acdc.a.a``) and emit the CESR stream.

The issuer's own KEL is read from its witnesses over plain HTTP
(:meth:`DkmsBridge.witness_kel`), not through ``dkms log kel find``,
which goes via the watcher and fails after every watcher restart.

The ACDC verify path is intentionally NOT delegated — we keep KERIpy
in-process on the verifier side so ADR 0001's security posture holds
(the four known ``dkms-bin v0.8.2`` verify bugs stay out of our code
path). See ADR 0002 for the pivot rationale.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Start of a KERI event in a CESR stream. Attachments are qb64 text and
# never contain this, so it safely splits a stream into events.
_KERI_EVENT_START = '{"v":"KERI'
# Message types that make up a KEL. Anything else in a witness response
# (its own ``rpy`` location reply, receipts) is not part of the KEL.
_KEL_EVENT_TYPES = frozenset({"icp", "rot", "ixn", "dip", "drt"})
_EVENT_TYPE_RE = re.compile(r'"t":"(\w+)"')


class DkmsBridgeError(RuntimeError):
    """``dkms`` command failed, or its output could not be parsed."""


@dataclass
class IdentifierInfo:
    alias: str
    aid: str
    witness_urls: list[str]
    watcher_urls: list[str]


class DkmsBridge:
    """Shell to the ``dkms`` CLI, scoped to a persistent state directory.

    One instance per service process is enough; the bridge is stateless
    beyond knowing where to find the binary and where to keep its
    on-disk state. ``home_dir`` becomes ``HOME`` for every call so
    ``dkms``' own data directory (``$HOME/.dkms-dev-cli/``) lands on
    the service's PVC.
    """

    DEFAULT_BIN = Path("/usr/local/bin/dkms")

    def __init__(
        self,
        home_dir: Path,
        bin_path: Path | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.bin_path = Path(bin_path or self.DEFAULT_BIN)
        if not self.bin_path.exists():
            # Fall back to PATH lookup for local dev where the binary
            # may be installed via brew / cargo / sideloaded.
            resolved = shutil.which("dkms")
            if resolved is None:
                raise DkmsBridgeError(
                    f"dkms binary not at {self.bin_path} and not on $PATH"
                )
            self.bin_path = Path(resolved)
        self.home_dir = Path(home_dir)
        self.home_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_seconds = timeout_seconds

    # ─── low-level ─────────────────────────────────────────────────────

    def _run(
        self,
        args: list[str],
        *,
        stdin: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HOME"] = str(self.home_dir)
        try:
            r = subprocess.run(
                [str(self.bin_path), *args],
                input=stdin,
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise DkmsBridgeError(
                f"dkms {' '.join(args[:2])} timed out after {self.timeout_seconds}s"
            ) from e
        except FileNotFoundError as e:
            raise DkmsBridgeError(f"dkms binary disappeared: {e}") from e

        if check and r.returncode != 0:
            raise DkmsBridgeError(
                f"dkms {' '.join(args)} exited {r.returncode}:\n"
                f"stdout={r.stdout!r}\nstderr={r.stderr!r}"
            )
        return r

    # ─── identifier lifecycle ──────────────────────────────────────────

    def identifier_init(
        self,
        alias: str,
        witness_url: str,
        watcher_url: str,
        witness_threshold: int = 1,
    ) -> IdentifierInfo:
        """Create or re-use the identifier for ``alias``.

        ``dkms identifier init`` is NOT idempotent — a second call with
        the same alias errors out. We probe with ``identifier info``
        first so a restarted pod re-uses the AID on its persisted PVC.
        """
        existing = self.identifier_info_or_none(alias)
        if existing is not None:
            log.info(
                "dkms identifier %r already exists; reusing aid=%s",
                alias, existing.aid,
            )
            return existing

        args = [
            "identifier", "init",
            "-a", alias,
            "--witness-url", witness_url,
            "--watcher-url", watcher_url,
            "--witness-threshold", str(witness_threshold),
        ]
        log.info("dkms identifier init a=%s w=%s watcher=%s",
                 alias, witness_url, watcher_url)
        self._run(args)

        info = self.identifier_info(alias)
        log.info("dkms identifier init done: alias=%s aid=%s", alias, info.aid)
        return info

    def identifier_info(self, alias: str) -> IdentifierInfo:
        r = self._run(["identifier", "info", alias])
        return _parse_identifier_info(alias, r.stdout)

    def identifier_info_or_none(self, alias: str) -> IdentifierInfo | None:
        r = self._run(["identifier", "info", alias], check=False)
        if r.returncode != 0:
            return None
        return _parse_identifier_info(alias, r.stdout)

    def identifier_oobi_get(self, alias: str) -> list[dict[str, Any]]:
        """Return the OOBI JSON objects ``alias`` is served at.

        ``dkms identifier oobi get`` prints assorted log lines followed
        by a JSON ARRAY of OOBI objects. Each element is a dict — one
        shape is a ``LocationScheme`` (``eid``/``scheme``/``url``) for
        a backer, another is an ``EndRole`` (``cid``/``role``/``eid``)
        for a role binding. The verifier POSTs these verbatim to
        mesagkesto's ``/resolve`` endpoint per the HCF reference flow.
        """
        r = self._run(["identifier", "oobi", "get", "-a", alias])
        raw = r.stdout
        start = raw.find("[")
        if start < 0:
            raise DkmsBridgeError(
                f"dkms identifier oobi get {alias} returned no JSON array: {raw!r}"
            )
        try:
            parsed = json.loads(raw[start:])
        except json.JSONDecodeError as e:
            raise DkmsBridgeError(
                f"dkms identifier oobi get {alias} returned non-JSON "
                f"output: {raw!r}"
            ) from e
        if not isinstance(parsed, list):
            raise DkmsBridgeError(
                f"dkms identifier oobi get {alias} returned {type(parsed).__name__}, "
                "expected list"
            )
        return [dict(e) for e in parsed]

    # ─── KEL lookup (verifiers consume via inline-KEL in grants) ────────

    def log_kel_find(self, alias: str, identifier: str) -> str:
        """Return the CESR stream of ``identifier``'s KEL as known to
        ``alias``.

        ``dkms log kel find`` emits the controller's own KEL (icp +
        subsequent events, with witness receipts and signatures) as a
        CESR stream. For an issuer embedding its own KEL in outbound
        grants (so a verifier can parse it in-process without an OOBI
        round-trip), pass ``identifier == self.aid``.
        """
        r = self._run(["log", "kel", "find", "--alias", alias,
                       "--identifier", identifier])
        # dkms logs noise ('Registering out of order escrow with ...')
        # before the CESR bytes. Strip up to the first version marker.
        start = r.stdout.find("{\"v\":")
        if start < 0:
            raise DkmsBridgeError(
                f"dkms log kel find {alias}/{identifier} returned no CESR "
                f"stream: {r.stdout[:200]!r}"
            )
        return r.stdout[start:].strip()

    def witness_kel(
        self, alias: str, identifier: str, timeout_seconds: float = 5.0,
    ) -> str:
        """Return ``identifier``'s KEL as served by ``alias``'s witnesses.

        Each witness serves the KEL of the identifiers it witnesses at
        ``GET <url>oobi/<identifier>/witness/<witness-eid>``. This needs
        neither the watcher nor any registration, so it keeps working
        after a watcher restart, which drops the role ``log kel find``
        depends on ("role Watcher missing").

        The response ends with the witness's own ``rpy`` location reply;
        only the KEL events are returned. The first event must be the
        inception of ``identifier``. Raises :class:`DkmsBridgeError` if
        no witness returns one.
        """
        info = self.identifier_info(alias)
        errors: list[str] = []
        for witness in info.witness_urls:
            if not isinstance(witness, dict) or not witness.get("url") or not witness.get("eid"):
                continue
            url = f"{str(witness['url']).rstrip('/')}/oobi/{identifier}/witness/{witness['eid']}"
            try:
                resp = httpx.get(url, timeout=timeout_seconds)
            except httpx.HTTPError as e:
                errors.append(f"{url}: {e}")
                continue
            if resp.status_code != 200:
                errors.append(f"{url}: HTTP {resp.status_code}")
                continue
            kel = kel_events_only(resp.text)
            if _starts_with_inception_of(kel, identifier):
                return kel
            errors.append(f"{url}: no inception event for {identifier}")
        raise DkmsBridgeError(
            f"no witness of {alias!r} returned the KEL of {identifier}: "
            f"{'; '.join(errors) or 'no witness URLs in identifier info'}"
        )

    # ─── credential issuance ───────────────────────────────────────────

    def data_issue(
        self,
        alias: str,
        attributes: dict[str, Any],
        oca_bundle_said: str,
        prepend_oobis: bool = True,
    ) -> str:
        """Issue an ACDC with ``alias``. Returns the raw stdout CESR stream.

        ``attributes`` is the user-facing claims dict (plus any protocol
        bindings — e.g. ``i`` for the subject AID). dkms-bin wraps it as
        ``acdc.a.a`` and builds the full ACDC envelope itself (issuer AID
        from the alias, schema SAID from the OCA bundle, ``d`` SAIDs
        backfilled). We previously handed dkms-bin a full ACDC skeleton
        as ``-m``, which dkms treated as the attributes payload and
        nested a level too deep.

        ``dkms data issue`` emits the ACDC body only — no signature
        attachment. :meth:`data_sign` is called separately once the
        ACDC body is known.
        """
        args = [
            "data", "issue",
            "-a", alias,
            "-m", json.dumps(attributes, separators=(",", ":"), sort_keys=False),
            "-b", oca_bundle_said,
        ]
        if prepend_oobis:
            args.append("-o")
        r = self._run(args)
        return r.stdout.strip()

    def data_sign(self, alias: str, message: bytes | str) -> str:
        """Sign arbitrary bytes with ``alias``'s current signing key.

        ``dkms data sign`` returns a CESR stream — the message followed
        by a signature attachment. We feed it the canonical ACDC body
        we just received from :meth:`data_issue` and extract the qb64
        signature so the verifier can check it against the issuer's
        current key in the resolved KEL.
        """
        if isinstance(message, bytes):
            message = message.decode("utf-8")
        r = self._run([
            "data", "sign",
            "-a", alias,
            "-m", message,
        ])
        return r.stdout


# ─── helpers ───────────────────────────────────────────────────────────


def kel_events_only(stream: str) -> str:
    """Keep only the KEL events (and their attachments) of a CESR stream.

    A witness's OOBI response is the KEL followed by the witness's own
    ``rpy`` location reply, whose identifier is the witness. Verifiers that
    walk the stream as a KEL reject that ``rpy``, so it is dropped here.
    Anything before the first event (dkms log noise) is dropped too.
    """
    parts = stream.split(_KERI_EVENT_START)[1:]
    kept = []
    for part in parts:
        event = _KERI_EVENT_START + part
        m = _EVENT_TYPE_RE.search(event)
        if m and m.group(1) in _KEL_EVENT_TYPES:
            kept.append(event)
    return "".join(kept).strip()


def _starts_with_inception_of(kel: str, identifier: str) -> bool:
    """True if ``kel``'s first event is the inception of ``identifier``."""
    if not kel.startswith(_KERI_EVENT_START):
        return False
    first = kel.split(_KERI_EVENT_START, 2)[1]
    m = _EVENT_TYPE_RE.search(first)
    return bool(m and m.group(1) == "icp" and f'"i":"{identifier}"' in first)


def _parse_identifier_info(alias: str, raw: str) -> IdentifierInfo:
    """Pull the JSON object out of dkms' stdout.

    dkms prints assorted non-JSON log lines (``Registering out of order
    escrow with timeout: 60s``, etc.) BEFORE the JSON payload. We locate
    the first ``{`` and parse from there, which also tolerates whatever
    future log noise dkms adds.
    """
    start = raw.find("{")
    if start < 0:
        raise DkmsBridgeError(
            f"dkms identifier info {alias} returned no JSON object: {raw!r}"
        )
    try:
        data = json.loads(raw[start:])
    except json.JSONDecodeError as e:
        raise DkmsBridgeError(
            f"dkms identifier info {alias} returned non-JSON: {raw!r}"
        ) from e

    aid = data.get("id") or data.get("prefix")
    if not aid:
        raise DkmsBridgeError(
            f"dkms identifier info {alias} missing id/prefix: {data!r}"
        )
    return IdentifierInfo(
        alias=alias,
        aid=str(aid),
        witness_urls=list(data.get("witnesses", []) or []),
        watcher_urls=list(data.get("watchers", []) or []),
    )

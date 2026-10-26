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

The ACDC verify path is intentionally NOT delegated — we keep KERIpy
in-process on the verifier side so ADR 0001's security posture holds
(the four known ``dkms-bin v0.8.2`` verify bugs stay out of our code
path). See ADR 0002 for the pivot rationale.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


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

    # ─── credential issuance ───────────────────────────────────────────

    def data_issue(
        self,
        alias: str,
        acdc_json: dict[str, Any],
        oca_bundle_said: str,
        prepend_oobis: bool = True,
    ) -> str:
        """Issue (sign) an ACDC with ``alias``. Returns the CESR stream.

        The input ACDC is a JSON dict in the HCF reference shape:
            {"v": "ACDC10JSON...", "d": "", "i": issuer_aid, "ri": "",
             "s": schema_said, "a": {"d": "", "a": {<claims>}}}
        The ``d`` and ``a.d`` SAIDs are left blank — dkms-bin computes
        and backfills them.
        """
        args = [
            "data", "issue",
            "-a", alias,
            "-m", json.dumps(acdc_json, separators=(",", ":"), sort_keys=False),
            "-b", oca_bundle_said,
        ]
        if prepend_oobis:
            args.append("-o")
        r = self._run(args)
        return r.stdout.strip()


# ─── helpers ───────────────────────────────────────────────────────────


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

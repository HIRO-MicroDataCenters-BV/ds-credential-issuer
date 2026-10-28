"""HIRO-side revocation list (interim).

HCF's TEL can't be read back yet ("Tel not found" before and after
``dkms data revoke``), so verifiers can't learn from KERI whether a
credential was revoked. Until it can, the issuer keeps its own list in a
small SQLite file on its PVC and serves the status over HTTP; ds-login
asks before every login and refuses revoked credentials.

The issuer keeps no record of what it issued, so any well-formed SAID can
be revoked — that also covers credentials minted before this list existed.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS revocations (
    said       TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason     TEXT NOT NULL
)
"""


@dataclass(frozen=True)
class Revocation:
    said: str
    revoked_at: str
    revoked_by: str
    reason: str


class RevocationStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def get(self, said: str) -> Revocation | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT said, revoked_at, revoked_by, reason FROM revocations "
                "WHERE said = ?", (said,),
            ).fetchone()
        return Revocation(*row) if row else None

    def revoke(self, said: str, revoked_by: str, reason: str) -> tuple[Revocation, bool]:
        """Record the revocation. Returns (record, newly_revoked); revoking
        twice keeps the first record."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO revocations VALUES (?, ?, ?, ?)",
                (said, now, revoked_by, reason),
            )
            newly = cur.rowcount == 1
        record = self.get(said)
        assert record is not None
        return record, newly

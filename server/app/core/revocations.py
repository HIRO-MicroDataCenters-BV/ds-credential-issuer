"""HIRO-side revocation list (interim), and the role of each issued credential.

HCF's TEL can't be read back yet ("Tel not found" before and after
``dkms data revoke``), so verifiers can't learn from KERI whether a
credential was revoked. Until it can, the issuer keeps its own list in a
small SQLite file on its PVC and serves the status over HTTP; ds-login
asks before every login and refuses revoked credentials.

It also keeps what it issued (``issued``): role, holder, name, email and the
grant, so admins can list credentials and download a grant again. Rows from
before those columns existed have them empty. Any well-formed SAID can still
be revoked, including credentials minted before this list existed.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

_SCHEMA = """
CREATE TABLE IF NOT EXISTS revocations (
    said       TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issued (
    said       TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    subject    TEXT NOT NULL,
    issued_at  TEXT NOT NULL,
    issued_by  TEXT NOT NULL
)
"""

# Columns added after the first release; added to existing files on start.
_ISSUED_EXTRA_COLUMNS = ("institute", "name", "email", "grant_json")


@dataclass(frozen=True)
class IssuedRecord:
    said: str
    role: str
    subject: str
    issued_at: str
    issued_by: str
    institute: str
    name: str
    email: str
    grant: dict[str, Any] | None
    revoked_at: str | None
    revoked_by: str | None
    reason: str | None


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
            db.executescript(_SCHEMA)
            have = {row[1] for row in db.execute("PRAGMA table_info(issued)")}
            for column in _ISSUED_EXTRA_COLUMNS:
                if column not in have:
                    db.execute(f"ALTER TABLE issued ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def get(self, said: str) -> Revocation | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT said, revoked_at, revoked_by, reason FROM revocations "
                "WHERE said = ?", (said,),
            ).fetchone()
        return Revocation(*row) if row else None

    def record_issued(self, said: str, role: str, subject: str, issued_by: str, *,
                      institute: str = "", name: str = "", email: str = "",
                      grant: dict[str, Any] | None = None) -> None:
        """Remember what was issued to whom: revoking checks who may revoke
        it, and the list and download read it back."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO issued (said, role, subject, issued_at, issued_by,"
                " institute, name, email, grant_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (said, role, subject, now, issued_by, institute, name, email,
                 json.dumps(grant) if grant is not None else ""),
            )

    _ISSUED_SELECT = (
        "SELECT i.said, i.role, i.subject, i.issued_at, i.issued_by, i.institute,"
        " i.name, i.email, i.grant_json, r.revoked_at, r.revoked_by, r.reason"
        " FROM issued i LEFT JOIN revocations r ON r.said = i.said"
    )

    @staticmethod
    def _record(row: tuple[Any, ...]) -> IssuedRecord:
        (said, role, subject, issued_at, issued_by, institute, name, email,
         grant_json, revoked_at, revoked_by, reason) = row
        return IssuedRecord(
            said=said, role=role, subject=subject, issued_at=issued_at,
            issued_by=issued_by, institute=institute, name=name, email=email,
            grant=json.loads(grant_json) if grant_json else None,
            revoked_at=revoked_at, revoked_by=revoked_by, reason=reason,
        )

    def list_issued(self, subject: str | None = None) -> list[IssuedRecord]:
        """Everything this issuer recorded, newest first, with revocation state."""
        query, args = self._ISSUED_SELECT, cast(tuple[str, ...], ())
        if subject:
            query, args = query + " WHERE i.subject = ?", (subject,)
        with self._connect() as db:
            rows = db.execute(query + " ORDER BY i.issued_at DESC, i.said", args).fetchall()
        return [self._record(row) for row in rows]

    def get_issued(self, said: str) -> IssuedRecord | None:
        with self._connect() as db:
            row = db.execute(self._ISSUED_SELECT + " WHERE i.said = ?", (said,)).fetchone()
        return self._record(row) if row else None

    def issued_role(self, said: str) -> str | None:
        """Role of a credential this issuer issued; None if unknown (issued
        before roles were recorded, or not by this issuer)."""
        with self._connect() as db:
            row = db.execute("SELECT role FROM issued WHERE said = ?", (said,)).fetchone()
        return row[0] if row else None

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

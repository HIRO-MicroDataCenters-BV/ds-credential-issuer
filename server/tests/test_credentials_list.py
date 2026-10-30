"""GET /credentials and GET /credentials/{said}: what the issuer issued, with
revocation state; each caller sees what it may manage (site_admin: all;
operator: data_provider and researcher), the same rule as revoking."""
from __future__ import annotations

import sqlite3

from app.core.revocations import RevocationStore

from .conftest import SUBJECT, mint, said_for


def listing(client, caller_role, **params):
    return client.get("/credentials", params=params, headers={"X-User-Role": caller_role})


def test_list_shows_what_was_issued(env):
    client, _, _ = env
    for role in ("researcher", "data_provider", "operator", "site_admin"):
        assert mint(client, "site_admin", role, name=f"N {role}", email=f"{role}@x").status_code == 200
    r = listing(client, "site_admin")
    assert r.status_code == 200
    rows = {row["role"]: row for row in r.json()}
    assert set(rows) == {"researcher", "data_provider", "operator", "site_admin"}
    researcher = rows["researcher"]
    assert researcher["name"] == "N researcher" and researcher["email"] == "researcher@x"
    assert researcher["institute"] == "hus" and researcher["issued_by"] == "Esite_admin"
    assert researcher["status"] == "valid" and researcher["has_grant"] is True
    assert "grant" not in researcher


def test_operator_sees_only_what_it_manages(env):
    client, _, _ = env
    for role in ("researcher", "data_provider", "operator", "site_admin"):
        mint(client, "site_admin", role)
    roles = {row["role"] for row in listing(client, "operator").json()}
    assert roles == {"researcher", "data_provider"}
    assert listing(client, "researcher").json() == []


def test_revoked_shows_when_by_whom_and_why(env):
    client, _, _ = env
    mint(client, "site_admin", "researcher")
    said = said_for("researcher")
    client.post(f"/credentials/{said}/revoke", json={"reason": "left the project"},
                headers={"X-User-Role": "site_admin", "X-User-AID": "EAdmin"})
    row = listing(client, "site_admin").json()[0]
    assert row["status"] == "revoked" and row["revoke_reason"] == "left the project"
    assert row["revoked_by"] == "EAdmin" and row["revoked_at"]


def test_filter_by_holder(env):
    client, _, _ = env
    mint(client, "site_admin", "researcher")
    assert len(listing(client, "site_admin", subject="EOtherHolder").json()) == 0
    assert len(listing(client, "site_admin", subject=SUBJECT).json()) == 1


def test_get_one_with_its_grant(env):
    client, issuer, _ = env
    issuer.wrap_as_grant.return_value = {"acdc": {"d": "x"}, "iss_sig": "AA"}
    mint(client, "site_admin", "data_provider")
    said = said_for("data_provider")
    r = client.get(f"/credentials/{said}", headers={"X-User-Role": "operator"})
    assert r.status_code == 200
    assert r.json()["grant"] == {"acdc": {"d": "x"}, "iss_sig": "AA"}


def test_get_refuses_unknown_and_not_managed(env):
    client, _, _ = env
    mint(client, "site_admin", "site_admin")
    admin_said = said_for("site_admin")
    assert client.get(f"/credentials/{admin_said}", headers={"X-User-Role": "operator"}).status_code == 403
    unknown = "E" + "Z" * 43
    assert client.get(f"/credentials/{unknown}", headers={"X-User-Role": "site_admin"}).status_code == 404
    assert client.get("/credentials/not-a-said", headers={"X-User-Role": "site_admin"}).status_code == 422


def test_old_database_is_upgraded(tmp_path):
    path = tmp_path / "revocations.db"
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE issued (said TEXT PRIMARY KEY, role TEXT NOT NULL, subject TEXT NOT NULL,"
        " issued_at TEXT NOT NULL, issued_by TEXT NOT NULL);"
        "INSERT INTO issued VALUES ('EOLD', 'researcher', 'ESUB', '2026-10-29T07:00:00+00:00', 'bootstrap');"
    )
    db.commit()
    db.close()
    store = RevocationStore(path)
    old = store.list_issued()[0]
    assert (old.said, old.role, old.name, old.grant) == ("EOLD", "researcher", "", None)
    store.record_issued("ENEW", "operator", "ESUB2", "EAdmin", name="N", grant={"acdc": {}})
    assert store.get_issued("ENEW").grant == {"acdc": {}}

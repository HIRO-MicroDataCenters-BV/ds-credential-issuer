"""role@site rules: known roles only, the site's institute stamped, and who
may issue / revoke which role (site_admin: all; operator: data_provider and
researcher only). The issuer is mocked; ds-auth's identity headers are set by
hand, as the middleware would after checking the JWT."""
from __future__ import annotations

import pytest

from app.core.roles import may_manage

from app.main import app
from app.rest_api.depends import settings_dep

from .conftest import mint, revoke, said_for

@pytest.mark.parametrize("caller,target,ok", [
    ("site_admin", "site_admin", True), ("site_admin", "operator", True),
    ("site_admin", "data_provider", True), ("site_admin", "researcher", True),
    ("operator", "researcher", True), ("operator", "data_provider", True),
    ("operator", "operator", False), ("operator", "site_admin", False),
    ("researcher", "researcher", False), ("data_provider", "researcher", False),
    (None, "researcher", False), ("site_admin", None, True), ("operator", None, False),
])
def test_may_manage(caller, target, ok):
    assert may_manage(caller, target) is ok


def test_site_admin_issues_every_role(env):
    client, issuer, store = env
    for role in ("site_admin", "operator", "data_provider", "researcher"):
        r = mint(client, "site_admin", role)
        assert r.status_code == 200, (role, r.text)
        assert store.issued_role(said_for(role)) == role


@pytest.mark.parametrize("role,code", [("researcher", 200), ("data_provider", 200),
                                       ("operator", 403), ("site_admin", 403)])
def test_operator_limits(env, role, code):
    client, *_ = env
    assert mint(client, "operator", role).status_code == code


def test_operator_cannot_make_itself_admin(env):
    client, issuer, _ = env
    r = mint(client, "operator", "site_admin")
    assert r.status_code == 403 and "may not issue" in r.json()["detail"]
    issuer.issue.assert_not_called()


def test_unknown_role_rejected(env):
    client, issuer, _ = env
    assert mint(client, "site_admin", "admin").status_code == 422
    assert mint(client, "site_admin", "catalog_owner").status_code == 422
    issuer.issue.assert_not_called()


def test_institute_is_the_site(env):
    client, issuer, _ = env
    assert mint(client, "site_admin", "researcher").status_code == 200
    assert issuer.issue.call_args.kwargs["attributes"]["institute"] == "hus"   # stamped
    assert mint(client, "site_admin", "researcher", institute="hus").status_code == 200
    r = mint(client, "site_admin", "researcher", institute="ki")
    assert r.status_code == 422 and "site 'hus'" in r.json()["detail"]
    assert mint(client, "site_admin", "researcher", institute="HUS").status_code == 422


def test_revoke_limits(env):
    client, *_ = env
    for role in ("site_admin", "operator", "researcher"):
        assert mint(client, "site_admin", role).status_code == 200
    assert revoke(client, "operator", said_for("researcher")).status_code == 200
    assert revoke(client, "operator", said_for("operator")).status_code == 403
    assert revoke(client, "operator", said_for("site_admin")).status_code == 403
    assert revoke(client, "site_admin", said_for("site_admin")).status_code == 200


def test_unknown_credential_only_site_admin_revokes(env):
    client, *_ = env
    old = "EOldCredentialFromBeforeRoles00000000000000A"
    assert revoke(client, "operator", old).status_code == 403
    assert revoke(client, "site_admin", old).status_code == 200


def test_without_auth_no_caller_check(env, tmp_path):
    """Local runs without ds-auth have no caller identity; role names and the
    site are still enforced."""
    client, *_ = env
    app.dependency_overrides[settings_dep]().auth.enabled = False
    assert mint(client, None, "site_admin").status_code == 200
    assert mint(client, None, "admin").status_code == 422

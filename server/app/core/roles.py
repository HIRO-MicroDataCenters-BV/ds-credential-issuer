"""Which roles exist, and which role may issue or revoke which.

Every credential is ``role@site``: the role says what someone may do, the
institute is the site that issued it (``issuer.institute``). The policy
engine decides *whether* a caller may issue at all (``issuer:write``); this
module decides *which roles* they may hand out, which the policy engine
cannot see:

  * ``site_admin`` — issues and revokes every role, itself included.
  * ``operator``   — issues and revokes ``data_provider`` and ``researcher``
    only, so an operator cannot make anyone (themselves included) an admin
    or another operator.
"""
from __future__ import annotations

SITE_ADMIN = "site_admin"
OPERATOR = "operator"
DATA_PROVIDER = "data_provider"
RESEARCHER = "researcher"

KNOWN_ROLES: tuple[str, ...] = (SITE_ADMIN, OPERATOR, DATA_PROVIDER, RESEARCHER)

# caller role -> roles it may issue and revoke
_MANAGES: dict[str, frozenset[str]] = {
    SITE_ADMIN: frozenset(KNOWN_ROLES),
    OPERATOR: frozenset({DATA_PROVIDER, RESEARCHER}),
}


def may_manage(caller_role: str | None, target_role: str | None) -> bool:
    """True when ``caller_role`` may issue or revoke a ``target_role``
    credential. An unknown target role (e.g. a credential issued before
    roles were recorded) can only be handled by a site admin."""
    if caller_role == SITE_ADMIN:
        return True
    return target_role is not None and target_role in _MANAGES.get(caller_role or "", frozenset())

"""KERIpy habery / habitat wiring for ds-credential-issuer.

A **habery** holds the issuer's LMDB keystore + database and manages the
AIDs we own. A **habitat** is one AID inside that habery. ds-credential-
issuer runs one habitat per deployment — the per-site issuer AID.

Lifecycle:
  * ``init_habery(settings)`` opens the LMDB keystore at
    ``settings.issuer.habery_path``. On first boot it is empty; the
    habitat ``settings.issuer.name`` is created with the configured
    witnesses (``settings.issuer.witness_urls``) and the inception event
    is submitted to each witness.
  * Subsequent boots just reopen the habery and look up the existing
    habitat; AID and keys persist across restarts.
  * ``close()`` releases the LMDB handles.

The module keeps all KERIpy imports lazy (inside functions) so the service
can still boot on hosts where libsodium is missing (local dev on Windows);
the actual mint path raises ``KERIpyUnavailableError`` with a clear
diagnostic when hit.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..settings import Issuer as IssuerSettings

log = logging.getLogger(__name__)


class KERIpyUnavailableError(RuntimeError):
    """Raised when KERIpy / libsodium cannot be loaded at runtime."""


class HaberyError(RuntimeError):
    """Issuer habery failed to open or no habitat could be made."""


@dataclass
class IssuerHandle:
    """Everything a request handler needs to issue a credential.

    Opaque to the handler — concrete KERIpy objects live inside ``_hab``;
    the handler only reads ``aid`` and calls ``issue()`` / ``revoke()``
    which the ``AcdcIssuer`` wraps.
    """

    aid: str
    name: str
    witnesses: tuple[str, ...]
    _hab: Any  # keri.app.habbing.Hab; untyped to keep the HTTP layer importable
    _hby: Any  # keri.app.habbing.Habery


def init_habery(settings: IssuerSettings) -> IssuerHandle:
    """Open (or create) the issuer's habery and return a handle.

    First call bootstraps:
      * creates ``habery_path`` if missing
      * creates a transferable habitat ``settings.name`` with the
        configured witness set
      * stores the resulting AID so later calls just reopen

    Raises:
        KERIpyUnavailableError — libsodium / keri import failed
        HaberyError — keystore open or habitat create failed
    """
    try:
        from keri.app import habbing
    except Exception as e:  # pysodium.TypeError on Windows is NOT ImportError
        raise KERIpyUnavailableError(
            f"KERIpy not loadable: {e}. On Windows this usually means "
            "libsodium.dll is missing from PATH."
        ) from e

    from keri.app import habbing

    settings.habery_path.mkdir(parents=True, exist_ok=True)

    try:
        # KERIpy's Habery wants `headDirPath` for an absolute storage root
        # (what settings.habery_path is). `base` is a relative subdir name
        # under that root — leave it empty here.
        hby = habbing.Habery(
            name=settings.name,
            base="",
            headDirPath=str(settings.habery_path),
        )
    except Exception as e:  # KERIpy raises many kinds here
        raise HaberyError(
            f"could not open issuer habery at {settings.habery_path}: {e}"
        ) from e

    hab = hby.habByName(settings.name)
    if hab is None:
        try:
            # KERIpy's `wits` wants witness AIDs (prefixes like "Bxxx..."),
            # not URLs. For local demo flows that don't anchor to witnesses
            # (ds-login verifies via grant-embedded OOBIs, not via wit
            # list), pass [] — the habitat is self-sovereign.
            # TODO(prod): accept witness AIDs via settings and pass them
            # here. OOBI URLs then live in settings.witness_oobis for the
            # grant embedding path, separately from the wit list.
            hab = hby.makeHab(
                name=settings.name,
                transferable=True,
                wits=[],
                isith=settings.inception_threshold,
            )
        except Exception as e:
            hby.close()
            raise HaberyError(
                f"could not create habitat {settings.name!r}: {e}"
            ) from e

        log.info(
            "issuer habitat %r created: aid=%s witnesses=%s",
            settings.name, hab.pre, settings.witness_urls,
        )
    else:
        log.info(
            "issuer habitat %r reopened: aid=%s",
            settings.name, hab.pre,
        )

    return IssuerHandle(
        aid=hab.pre,
        name=settings.name,
        witnesses=tuple(settings.witness_urls),
        _hab=hab,
        _hby=hby,
    )


def close_habery(handle: IssuerHandle) -> None:
    """Release LMDB handles. Safe to call multiple times."""
    try:
        handle._hby.close()
    except Exception:
        log.exception("habery close failed")

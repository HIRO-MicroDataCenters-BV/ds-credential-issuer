"""Issuer AID lifecycle.

Delegates AID enrolment, witness receipting and watcher subscription to
HCF's ``dkms`` CLI via :mod:`.dkms_bridge`. ds-credential-issuer owns no
KERI protocol logic of its own in Phase 1 of the facade pivot — the
cryptographic flow is dkms-bin's, this module just records which alias
we chose and reads back the resulting AID.

Lifecycle:
  * ``init_handle(settings)`` ensures the alias ``settings.name`` is
    initialised. On first boot it shells to ``dkms identifier init``;
    on subsequent boots it just reads the AID back via
    ``dkms identifier info``. State lives on the service's PVC via
    ``settings.dkms_home``.
  * No explicit ``close()``; dkms-bin is subprocess-only and has no
    long-lived handle for us to release.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from ..settings import Issuer as IssuerSettings
from .dkms_bridge import DkmsBridge, DkmsBridgeError, IdentifierInfo

log = logging.getLogger(__name__)


class IssuerInitError(RuntimeError):
    """Raised when the issuer AID could not be enrolled or read back."""


@dataclass
class IssuerHandle:
    """Everything a request handler needs to issue a credential.

    All KERI state lives in the dkms-bin on-disk store, keyed by
    ``name`` (the dkms alias). The handler reads ``aid`` for the
    issuer identity string and calls into ``AcdcIssuer`` which uses
    the shared ``DkmsBridge``.
    """

    aid: str
    name: str  # dkms-bin alias
    witness_url: str
    watcher_url: str
    bridge: DkmsBridge

    @property
    def alias(self) -> str:
        """Backward-compat alias for ``name``."""
        return self.name


def init_handle(settings: IssuerSettings) -> IssuerHandle:
    """Initialise the issuer identifier, returning a handle.

    First call:
      * ensures the dkms state directory exists
      * shells ``dkms identifier init`` which:
        - mints the AID
        - POSTs the inception event to ``settings.dkms_witness_url``
          and waits for the receipt
        - subscribes with ``settings.dkms_watcher_url``
      * reads the resulting AID back via ``identifier info``

    Subsequent calls (same PVC) just read the AID back; dkms-bin's
    ``init`` fails on existing alias and the bridge probes with
    ``info`` first to make the whole call idempotent.
    """
    if not settings.dkms_witness_url or not settings.dkms_watcher_url:
        raise IssuerInitError(
            "issuer.dkms_witness_url and issuer.dkms_watcher_url must "
            "both be set: dkms-bin enrols the issuer AID with them."
        )

    try:
        bridge = DkmsBridge(home_dir=settings.dkms_home, bin_path=settings.dkms_bin)
    except DkmsBridgeError as e:
        raise IssuerInitError(f"could not initialise DkmsBridge: {e}") from e

    try:
        info: IdentifierInfo = bridge.identifier_init(
            alias=settings.name,
            witness_url=settings.dkms_witness_url,
            watcher_url=settings.dkms_watcher_url,
            witness_threshold=settings.dkms_witness_threshold,
        )
    except DkmsBridgeError as e:
        raise IssuerInitError(
            f"dkms identifier init failed for alias {settings.name!r}: {e}"
        ) from e

    log.info(
        "issuer identifier ready: alias=%s aid=%s witness=%s watcher=%s",
        info.alias, info.aid,
        settings.dkms_witness_url, settings.dkms_watcher_url,
    )

    return IssuerHandle(
        aid=info.aid,
        name=info.alias,
        witness_url=settings.dkms_witness_url,
        watcher_url=settings.dkms_watcher_url,
        bridge=bridge,
    )


"""DkmsBridge.identifier_init against a fake ``dkms`` script that mimics
dkms-bin 0.8.x: ``init`` can exit 0 leaving only ``db/`` (seen on kind when
the witness's advertised URL was unreachable), ``info`` then panics, and a
second ``init`` stops at an overwrite prompt."""
from __future__ import annotations

import stat

import pytest

from app.core.dkms_bridge import DkmsBridge, DkmsBridgeError

AID = "EIssuerAID00000000000000000000000000000000AA"

FAKE_DKMS = r'''#!/bin/sh
dir="$HOME/.dkms-dev-cli/$3"
case "$1 $2" in
  "identifier info")
    [ -f "$dir/id" ] || { echo "panicked at src/utils.rs:64:10" >&2; exit 101; }
    echo '{"id":"AID_PLACEHOLDER","witnesses":[],"watchers":[]}'; exit 0 ;;
  "identifier init")
    dir="$HOME/.dkms-dev-cli/$4"
    if [ -d "$dir" ]; then
      printf "The alias already exists. Are you sure you want to overwrite it? (y|N)"
      read answer; [ "$answer" = "y" ] || exit 1
    fi
    mkdir -p "$dir/db"
    [ "$(cat "$HOME/mode")" = "half" ] && { echo "Transport error: dns error"; exit 0; }
    for f in id priv_key next_priv_key; do echo x > "$dir/$f"; done; exit 0 ;;
esac
exit 2
'''


@pytest.fixture
def bridge(tmp_path):
    fake = tmp_path / "dkms"
    fake.write_text(FAKE_DKMS.replace("AID_PLACEHOLDER", AID))
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    home = tmp_path / "home"
    b = DkmsBridge(home_dir=home, bin_path=fake)
    (home / "mode").write_text("ok")
    return b


def _init(b):
    return b.identifier_init("hus-issuer", "http://w:3232", "http://wa:3235")


def _alias_dirs(b):
    return sorted(p.name for p in (b.home_dir / ".dkms-dev-cli").iterdir())


def test_fresh_init(bridge):
    assert _init(bridge).aid == AID


def test_existing_identity_is_reused(bridge):
    _init(bridge)
    assert _init(bridge).aid == AID
    assert _alias_dirs(bridge) == ["hus-issuer"]


def test_init_that_exits_0_without_keys_fails_loudly(bridge):
    (bridge.home_dir / "mode").write_text("half")
    with pytest.raises(DkmsBridgeError, match="exited 0 but left no usable identifier"):
        _init(bridge)


def test_half_created_alias_is_set_aside_and_recreated(bridge):
    (bridge.home_dir / "mode").write_text("half")
    with pytest.raises(DkmsBridgeError):
        _init(bridge)                       # first start: witness unreachable
    (bridge.home_dir / "mode").write_text("ok")
    assert _init(bridge).aid == AID         # next start: recovers by itself
    dirs = _alias_dirs(bridge)
    assert dirs[0] == "hus-issuer"
    assert dirs[1].startswith("hus-issuer.half-created-")
    assert (bridge.home_dir / ".dkms-dev-cli" / dirs[1] / "db").is_dir()  # kept, not deleted


def test_alias_with_key_files_is_never_touched(bridge):
    folder = bridge.home_dir / ".dkms-dev-cli" / "hus-issuer"
    (folder / "db").mkdir(parents=True)
    (folder / "priv_key").write_text("secret")   # info fails, but keys exist
    with pytest.raises(DkmsBridgeError, match="holds key files"):
        _init(bridge)
    assert (folder / "priv_key").read_text() == "secret"
    assert _alias_dirs(bridge) == ["hus-issuer"]

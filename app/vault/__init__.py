# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The encrypted secrets vault — AES-256-GCM credential storage for collectors.

Layers, mirroring the shape `app/cim/` uses:
  * :mod:`app.vault.crypto`  — seal/open, key loading, fingerprints (pure, no DB)
  * :mod:`app.vault.resolve` — where a credential comes from (vault, then environment)
  * :func:`app.db.put_secret` and friends — ciphertext storage, key-free by design

This module is the public API the routes call: :func:`set_secret`, :func:`rotate_key`,
:func:`status`.

Roadmap context (docs/SPLUNK_TRANSFORMATION_ROADMAP.md, Phase 2): the vault is
deliberately sequenced BEFORE the collector wave. Phase 2 adds CrowdStrike, Defender XDR,
AWS breadth and Cortex Data Lake — a dozen integrations holding high-value credentials —
and retrofitting encryption across all of them later is strictly harder than having it in
place first.
"""
from __future__ import annotations

import logging

from . import crypto, resolve
from .crypto import VaultError, generate_key, key_id, masked
from .resolve import get, invalidate, sealed_available, status

log = logging.getLogger("logocean")

__all__ = ["crypto", "resolve", "VaultError", "generate_key", "key_id", "masked",
           "get", "invalidate", "sealed_available", "status",
           "set_secret", "delete_secret", "rotate_key", "RotationResult"]


def set_secret(integration: str, name: str, value: str, updated_by: str = "") -> None:
    """Seal `value` into the (integration, name) slot and invalidate any cached copy.

    Raises `VaultError` when the vault is not usable — a caller must never be able to
    "save" a credential that silently went nowhere, so this refuses rather than degrades.
    That is the one place in the vault where failing loudly beats falling back.
    """
    from .. import db
    key = resolve._key()
    if key is None:
        raise VaultError(
            "the vault is not usable: set VAULT_ENABLED=true, provide a valid VAULT_KEY, "
            "and install the 'cryptography' package")
    if not integration or not name:
        raise VaultError("a secret needs both an integration and a name")
    if "\x00" in integration or "\x00" in name:
        # The AAD joins these with a NUL; a NUL inside either would let two different
        # slots produce the same AAD and defeat the slot binding.
        raise VaultError("integration and name may not contain a NUL byte")
    ct, nonce = crypto.seal(key, integration, name, value)
    db.put_secret(integration, name, ct, nonce, crypto.key_id(key), updated_by)
    invalidate(integration, name)


def delete_secret(integration: str, name: str) -> bool:
    """Remove a slot. Resolution then falls back to the environment variable, if any."""
    from .. import db
    removed = db.delete_secret(integration, name)
    invalidate(integration, name)
    return removed


class RotationResult:
    """What a rotation did, for the audit log and the admin page."""

    def __init__(self, rotated: int, from_key_ids: list[str], to_key_id: str):
        self.rotated = rotated
        self.from_key_ids = from_key_ids
        self.to_key_id = to_key_id

    def as_dict(self) -> dict:
        return {"rotated": self.rotated, "from_key_ids": self.from_key_ids,
                "to_key_id": self.to_key_id}


def rotate_key(new_key_b64: str) -> RotationResult:
    """Re-seal every secret under a new master key.

    ORDERING MATTERS AND IS THE WHOLE RISK. Every row is opened with the CURRENT key and
    re-sealed with the new one IN MEMORY first; only then is the batch written in a single
    transaction (`db.reseal_secrets`). If any row fails to open — a slot sealed under a
    third key, a tampered row — nothing is written at all. The alternative (update as you
    go) can leave the store split across two keys, and since the operator is about to
    retire the old one, that is how credentials become permanently unrecoverable.

    The caller is responsible for actually putting the new key in VAULT_KEY afterwards;
    this cannot do that, so the returned `to_key_id` is what the operator checks against
    the admin page after restarting.
    """
    from .. import db
    old = resolve._key()
    if old is None:
        raise VaultError("cannot rotate: the vault is not currently usable")
    new = crypto.load_key(new_key_b64)
    new_id = crypto.key_id(new)
    if new_id == crypto.key_id(old):
        raise VaultError("the new key is identical to the current one")

    rows = db.all_secret_rows()
    resealed, seen_ids = [], []
    for r in rows:
        # Opened with the CURRENT key: a row under any other key aborts the rotation
        # rather than being skipped, so "rotated 4 of 6" can never silently happen.
        value = crypto.open_(old, r["integration"], r["name"],
                             r["ciphertext"], r["nonce"])
        ct, nonce = crypto.seal(new, r["integration"], r["name"], value)
        resealed.append((r["integration"], r["name"], ct, nonce, new_id))
        if r["key_id"] not in seen_ids:
            seen_ids.append(r["key_id"])

    n = db.reseal_secrets(resealed)
    invalidate()
    log.warning("vault: rotated %d secret(s) to key_id=%s - update VAULT_KEY and restart",
                n, new_id)
    return RotationResult(n, seen_ids, new_id)

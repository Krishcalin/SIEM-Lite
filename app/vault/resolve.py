# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Credential resolution: where a collector's secret actually comes from.

THE ORDER IS VAULT, THEN ENVIRONMENT, and the fallback is the whole reason this module
exists. Every collector in this repo reads its credentials straight off `settings`
(plaintext env vars), and eleven of them shipped that way. If the vault simply replaced
that, upgrading would break every existing deployment on restart — so instead the vault
takes precedence when a slot is filled, and anything not in the vault keeps working
exactly as before. An operator migrates one integration at a time, verifies it, and moves
on; nobody has a flag day.

The fallback is also what keeps the optional dependency honest. With `cryptography`
absent, `sealed_available()` is False, no slot ever resolves from the vault, and the app
runs precisely as it did before Phase 2 — degraded, loudly logged, but working.

RESOLUTION IS CACHED PER PROCESS. Collectors are constructed once at startup by
`runner.build_collectors`, so this is not a hot path, but a cache still matters: without
one, a scheduler that rebuilt collectors would decrypt every credential on every cycle,
and each decryption is a database round-trip plus an AEAD open. `invalidate()` is called
whenever a secret is written or rotated, so the cache can never serve a stale credential
after an operator changes one.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from . import crypto
from ..config import settings

log = logging.getLogger("logocean")

# (integration, name) -> plaintext. Guarded because collectors are built from a
# threadpool and the scheduler can rebuild concurrently with an admin write.
_cache: dict[tuple[str, str], str] = {}
_lock = threading.Lock()
_warned = False


def _key() -> Optional[bytes]:
    """The master key, or None when the vault is not configured/available.

    Never raises: a misconfigured vault must degrade to environment variables, not stop
    the app from booting. The one-time warning is deliberate — an operator who set
    VAULT_KEY but installed no backend needs to know their secrets are NOT being sealed.
    """
    global _warned
    if not settings.vault_enabled:
        return None
    if not crypto.is_available():
        if not _warned:
            log.warning("vault: VAULT_ENABLED is set but the 'cryptography' package is "
                        "not installed - credentials fall back to environment variables "
                        "and NOTHING is encrypted (pip install cryptography)")
            _warned = True
        return None
    try:
        return crypto.load_key(settings.vault_key)
    except crypto.VaultError as e:
        if not _warned:
            log.warning("vault: %s - credentials fall back to environment variables", e)
            _warned = True
        return None


def sealed_available() -> bool:
    """True when the vault can actually seal and open secrets right now."""
    return _key() is not None


def status() -> dict:
    """What /health and the admin page report. Never includes key material."""
    key = _key()
    return {
        "enabled": bool(settings.vault_enabled),
        "backend": crypto.is_available(),
        "usable": key is not None,
        "key_id": crypto.key_id(key) if key else None,
    }


def invalidate(integration: str = "", name: str = "") -> None:
    """Drop cached plaintext — the whole cache, or one slot."""
    with _lock:
        if integration and name:
            _cache.pop((integration, name), None)
        else:
            _cache.clear()


def get(integration: str, name: str, env_fallback: str = "") -> str:
    """Resolve one credential: vault first, then the plaintext env-var value.

    `env_fallback` is the value the caller would have used before the vault existed
    (typically `settings.okta_token`), passed in rather than looked up here so this module
    never has to know the mapping from a slot to a settings attribute.
    """
    ck = (integration, name)
    with _lock:
        if ck in _cache:
            return _cache[ck]

    key = _key()
    if key is not None:
        from .. import db
        try:
            row = db.get_secret_row(integration, name)
        except Exception as e:      # noqa: BLE001 — DB down must not kill collector build
            log.warning("vault: could not read %s/%s (%s); using the environment",
                        integration, name, e)
            row = None
        if row:
            try:
                value = crypto.open_(key, integration, name,
                                     row["ciphertext"], row["nonce"])
                with _lock:
                    _cache[ck] = value
                return value
            except crypto.VaultError as e:
                # A sealed row that will not open is a real problem — a rotated key, a
                # tampered row - and silently using the env var would hide it. Log loudly,
                # then still fall back, because a collector that stops running is worse.
                log.error("vault: %s", e)

    return env_fallback or ""

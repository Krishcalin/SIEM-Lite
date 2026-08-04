# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The vault's cryptography: AES-256-GCM seal/open over a master key.

WHY AN OPTIONAL DEPENDENCY. The charter is pure-Python with no heavy dependencies, and
everything else this project needs from cryptography it hand-rolls: SigV4 (HMAC-SHA256),
OAuth2, RS256 (`pow(m, d, n)` over a hand-parsed DER key), pbkdf2 password hashing. All of
those are built from `hashlib`/`hmac`, which the stdlib provides. **AES is not.** There is
no block cipher anywhere in the standard library, so "AES-GCM at rest" cannot be built
from what is already there.

Hand-rolling AEAD is where that reasoning stops being reasonable: GHASH is subtly easy to
get wrong, a pure-Python implementation cannot be constant-time, and a mistake here is
silent — it produces ciphertext that looks fine and protects nothing. So this module takes
the one dependency that is genuinely worth it, and takes it OPTIONALLY, exactly as
`app/copilot/client.py` takes `anthropic`: imported lazily, feature-gated by
:func:`is_available`, commented in requirements.txt, and the app runs without it.

WHAT THIS PROTECTS. Credentials at rest in the database — a backup, a read replica, a
stolen dump, an SQL-injection read. It does NOT protect against host compromise: the
master key is read from the environment, so anything that can read the process can read
the key. That is the same guarantee Splunk's SOAR credential store gives, and it is worth
having, but it must not be oversold in the docs.

DESIGN NOTES:
  * AES-256-GCM with a random 96-bit nonce per seal. 96 bits is the GCM-native size (no
    re-hashing of the IV) and random is safe here because a fresh nonce is drawn on every
    write — secrets are written by hand, not in a loop, so the birthday bound is a
    non-issue at any plausible number of rotations.
  * The AAD binds each ciphertext to its OWN (integration, name) slot. Without it, a
    database writer could MOVE a row — copy the `okta/token` ciphertext into the
    `crowdstrike/client_secret` slot — and the vault would happily decrypt it into the
    wrong integration. GCM authenticates the AAD, so a moved row fails to open.
  * `key_id` is a non-secret fingerprint of the master key, stored beside the ciphertext,
    so rotation can find exactly which rows are still under the old key without trying to
    decrypt everything. It is a truncated SHA-256 of a domain-separated hash of the key —
    never the key itself.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional, Tuple

KEY_BYTES = 32          # AES-256
NONCE_BYTES = 12        # 96-bit GCM nonce
_KEY_ID_PREFIX = b"logocean-vault-key-id-v1"


class VaultError(Exception):
    """Raised for a missing/malformed key, an unavailable backend, or a failed open."""


def is_available() -> bool:
    """True when the AES-GCM backend can actually be imported.

    Checked before the vault claims to be usable, so a deployment without the optional
    dependency degrades loudly at startup rather than at the first secret write.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except Exception:       # noqa: BLE001 — any import failure means "not available"
        return False
    return True


def generate_key() -> str:
    """A fresh base64 master key, for `VAULT_KEY`. Printed by the admin UI / docs."""
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def load_key(raw: str) -> bytes:
    """Decode and validate a base64 master key.

    Strict on length: a short key is the one configuration mistake that silently weakens
    every secret in the store, so it is refused rather than stretched into something that
    looks like a 256-bit key.
    """
    if not raw:
        raise VaultError("no vault key configured (set VAULT_KEY)")
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except Exception as e:  # noqa: BLE001
        raise VaultError("VAULT_KEY is not valid base64") from e
    if len(key) != KEY_BYTES:
        raise VaultError(
            f"VAULT_KEY must decode to exactly {KEY_BYTES} bytes (got {len(key)}); "
            "generate one with app.vault.crypto.generate_key()")
    return key


def key_id(key: bytes) -> str:
    """A short, non-secret fingerprint of the master key.

    Domain-separated and truncated: it identifies which key sealed a row (so rotation can
    select the stale ones) and must never be usable to recover the key. Truncating a
    SHA-256 of a prefixed input gives a stable 16-hex-char label with no preimage value.
    """
    return hashlib.sha256(_KEY_ID_PREFIX + key).hexdigest()[:16]


def _aad(integration: str, name: str) -> bytes:
    """Additional authenticated data binding a ciphertext to its slot.

    The separator is a NUL because neither an integration nor a secret name may contain
    one, so ("ab", "c") and ("a", "bc") cannot collide into the same AAD.
    """
    return f"{integration}\x00{name}".encode("utf-8")


def seal(key: bytes, integration: str, name: str, plaintext: str) -> Tuple[bytes, bytes]:
    """Encrypt `plaintext` for the (integration, name) slot -> (ciphertext, nonce)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:  # noqa: BLE001
        raise VaultError(
            "the secrets vault needs the 'cryptography' package "
            "(pip install cryptography); see docs/VAULT.md") from e
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"),
                             _aad(integration, name))
    return ct, nonce


def open_(key: bytes, integration: str, name: str,
          ciphertext: bytes, nonce: bytes) -> str:
    """Decrypt a sealed secret. Raises `VaultError` on a wrong key, a tampered row, or a
    row moved into a different slot (the AAD no longer matches)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:  # noqa: BLE001
        raise VaultError(
            "the secrets vault needs the 'cryptography' package "
            "(pip install cryptography); see docs/VAULT.md") from e
    try:
        pt = AESGCM(key).decrypt(bytes(nonce), bytes(ciphertext),
                                 _aad(integration, name))
    except Exception as e:  # noqa: BLE001 — InvalidTag and friends
        raise VaultError(
            f"could not decrypt {integration}/{name}: wrong VAULT_KEY, a tampered row, "
            "or a secret copied from another slot") from e
    return pt.decode("utf-8")


def masked(value: Optional[str]) -> str:
    """A display form that reveals nothing useful — for the admin UI and audit log.

    Short values are fully hidden rather than partially: showing 2 of 4 characters of a
    short token is a real leak, and "is it set?" is all the UI needs to convey.
    """
    if not value:
        return "(not set)"
    return "•" * 8 if len(value) < 12 else f"{value[:2]}{'•' * 8}{value[-2:]}"

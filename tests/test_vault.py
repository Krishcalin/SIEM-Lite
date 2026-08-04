# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Secrets vault: key handling, AEAD sealing, slot binding, and resolution policy.

DB-free except where marked `integration`. The crypto tests below are the ones that
matter most: an encryption bug is silent by construction — it produces ciphertext that
looks perfectly fine and protects nothing — so each test here is written to fail for one
specific, named reason.
"""
from __future__ import annotations

import base64
import os

import pytest

from app.vault import crypto

pytestmark = []

_HAVE_AES = crypto.is_available()
needs_aes = pytest.mark.skipif(not _HAVE_AES, reason="cryptography not installed")


# ── keys ──────────────────────────────────────────────────────────────────────
def test_generate_key_is_a_32_byte_base64_key():
    k = crypto.generate_key()
    assert len(base64.b64decode(k, validate=True)) == crypto.KEY_BYTES


def test_generate_key_is_not_deterministic():
    # A generator that returned a constant would pass every other test in this file.
    assert crypto.generate_key() != crypto.generate_key()


def test_load_key_round_trips_a_generated_key():
    raw = crypto.generate_key()
    assert crypto.load_key(raw) == base64.b64decode(raw)


def test_load_key_tolerates_surrounding_whitespace():
    raw = crypto.generate_key()
    assert crypto.load_key(f"  {raw}\n") == base64.b64decode(raw)


@pytest.mark.parametrize("bad", ["", "   "])
def test_load_key_refuses_an_absent_key(bad):
    with pytest.raises(crypto.VaultError):
        crypto.load_key(bad)


def test_load_key_refuses_non_base64():
    with pytest.raises(crypto.VaultError):
        crypto.load_key("not base64 !!!")


@pytest.mark.parametrize("nbytes", [1, 16, 31, 33, 64])
def test_load_key_refuses_a_key_that_is_not_exactly_32_bytes(nbytes):
    # The one configuration mistake that silently weakens every secret in the store:
    # a short key must be refused, never stretched into something 256-bit-shaped.
    raw = base64.b64encode(os.urandom(nbytes)).decode()
    with pytest.raises(crypto.VaultError):
        crypto.load_key(raw)


def test_key_id_is_stable_distinct_and_leaks_no_key_material():
    a, b = os.urandom(32), os.urandom(32)
    assert crypto.key_id(a) == crypto.key_id(a)          # stable
    assert crypto.key_id(a) != crypto.key_id(b)          # distinguishing
    assert len(crypto.key_id(a)) == 16
    # the fingerprint must not contain the key, in any encoding we could plausibly slip
    for enc in (a.hex(), base64.b64encode(a).decode()):
        assert enc not in crypto.key_id(a)


# ── sealing ───────────────────────────────────────────────────────────────────
@needs_aes
def test_seal_then_open_round_trips():
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "okta", "token", "s3cr3t-value")
    assert crypto.open_(k, "okta", "token", ct, nonce) == "s3cr3t-value"


@needs_aes
def test_the_plaintext_never_appears_in_the_ciphertext():
    k = crypto.load_key(crypto.generate_key())
    secret = "AKIAIOSFODNN7EXAMPLE-plaintext-marker"
    ct, _ = crypto.seal(k, "aws", "access_key_id", secret)
    assert secret.encode() not in ct
    assert secret not in ct.hex()


@needs_aes
def test_sealing_the_same_value_twice_gives_different_ciphertext():
    # A fresh nonce per write. Identical ciphertext for identical input would leak that
    # two slots hold the same credential.
    k = crypto.load_key(crypto.generate_key())
    a, na = crypto.seal(k, "okta", "token", "same")
    b, nb = crypto.seal(k, "okta", "token", "same")
    assert na != nb and a != b


@needs_aes
def test_nonce_is_the_gcm_native_96_bits():
    k = crypto.load_key(crypto.generate_key())
    _, nonce = crypto.seal(k, "okta", "token", "x")
    assert len(nonce) == 12


@needs_aes
def test_a_secret_moved_to_another_slot_will_not_open():
    """The AAD binding — the property a plain 'encrypt this string' would not have.

    Without it, anyone able to write the table could copy the okta token ciphertext into
    the crowdstrike client_secret slot and the vault would decrypt it into the wrong
    integration, silently sending one vendor's credential to another vendor's API.
    """
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "okta", "token", "okta-token-value")
    with pytest.raises(crypto.VaultError):
        crypto.open_(k, "crowdstrike", "client_secret", ct, nonce)
    with pytest.raises(crypto.VaultError):
        crypto.open_(k, "okta", "refresh_token", ct, nonce)   # same integration, new name


@needs_aes
def test_the_aad_separator_cannot_be_confused_across_slot_boundaries():
    # ("ab","c") and ("a","bc") must not produce the same AAD.
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "ab", "c", "v")
    with pytest.raises(crypto.VaultError):
        crypto.open_(k, "a", "bc", ct, nonce)


@needs_aes
def test_a_wrong_key_will_not_open():
    k1 = crypto.load_key(crypto.generate_key())
    k2 = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k1, "okta", "token", "v")
    with pytest.raises(crypto.VaultError):
        crypto.open_(k2, "okta", "token", ct, nonce)


@needs_aes
@pytest.mark.parametrize("flip", [0, 5, -1])
def test_a_tampered_ciphertext_will_not_open(flip):
    """GCM authenticates: a flipped bit must be detected, not silently decrypted."""
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "okta", "token", "value-to-tamper-with")
    b = bytearray(ct)
    b[flip] ^= 0x01
    with pytest.raises(crypto.VaultError):
        crypto.open_(k, "okta", "token", bytes(b), nonce)


@needs_aes
def test_a_tampered_nonce_will_not_open():
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "okta", "token", "value")
    b = bytearray(nonce)
    b[0] ^= 0x01
    with pytest.raises(crypto.VaultError):
        crypto.open_(k, "okta", "token", ct, bytes(b))


@needs_aes
@pytest.mark.parametrize("value", ["", "x", "unicode-ключ-🔐", "a" * 8192,
                                  "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END-----\n"])
def test_round_trip_survives_awkward_values(value):
    # Empty, huge, multi-line PEM and non-ASCII all appear in real credentials.
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "gcp", "private_key", value)
    assert crypto.open_(k, "gcp", "private_key", ct, nonce) == value


@needs_aes
def test_open_accepts_memoryview_as_psycopg_returns_bytea():
    # psycopg hands back `memoryview` for bytea; open_ must not choke on it.
    k = crypto.load_key(crypto.generate_key())
    ct, nonce = crypto.seal(k, "okta", "token", "v")
    assert crypto.open_(k, "okta", "token", memoryview(ct), memoryview(nonce)) == "v"


# ── masking ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["", None])
def test_masked_reports_absence(value):
    assert crypto.masked(value) == "(not set)"


@pytest.mark.parametrize("value", ["abc", "short", "0123456789a"])
def test_masked_hides_short_values_entirely(value):
    # Showing 2 of 4 characters of a short token is a real leak.
    out = crypto.masked(value)
    assert out == "•" * 8 and value not in out


def test_masked_keeps_only_the_edges_of_a_long_value():
    out = crypto.masked("AKIAIOSFODNN7EXAMPLE")
    assert out.startswith("AK") and out.endswith("LE") and "IOSFODNN" not in out

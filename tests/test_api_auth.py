"""Unit tests for the API-key auth helpers (no database required)."""
from app.util import extract_api_key, hash_api_key


def test_hash_api_key_is_stable_sha256_hex():
    h = hash_api_key("lo_secret")
    assert h == hash_api_key("lo_secret")          # deterministic
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert hash_api_key("lo_other") != h           # different key -> different hash


def test_extract_api_key_from_x_api_key_header():
    assert extract_api_key("lo_abc", None) == "lo_abc"
    assert extract_api_key("  lo_abc  ", None) == "lo_abc"   # trimmed


def test_extract_api_key_from_bearer_header():
    assert extract_api_key(None, "Bearer lo_xyz") == "lo_xyz"
    assert extract_api_key(None, "bearer lo_xyz") == "lo_xyz"  # case-insensitive scheme


def test_extract_api_key_precedence_and_absence():
    # X-API-Key wins when both are present
    assert extract_api_key("lo_header", "Bearer lo_bearer") == "lo_header"
    # nothing usable
    assert extract_api_key(None, None) is None
    assert extract_api_key("", "") is None
    assert extract_api_key(None, "Basic abc123") is None      # wrong scheme

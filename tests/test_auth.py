"""Unit tests for auth: password hashing, role ranking, the RBAC dependency."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.auth as auth
from app.auth import hash_password, require_role, role_at_least, verify_password


def test_password_hash_roundtrip():
    h = hash_password("s3cret!")
    assert h.startswith("pbkdf2_sha256$") and h.count("$") == 3
    assert verify_password("s3cret!", h)
    assert not verify_password("wrong", h)
    assert hash_password("s3cret!") != h          # random salt -> different each time


def test_verify_password_rejects_garbage():
    assert not verify_password("x", "")
    assert not verify_password("x", "not$a$valid$hash")
    assert not verify_password("x", "bcrypt$1$2$3")   # unsupported algo


def test_role_ranking():
    assert role_at_least("admin", "viewer") and role_at_least("admin", "admin")
    assert role_at_least("analyst", "viewer") and not role_at_least("analyst", "admin")
    assert not role_at_least("viewer", "analyst")
    assert not role_at_least("bogus", "viewer")


class _Req:
    def __init__(self, user):
        self.state = type("S", (), {"user": user})()


def test_require_role_disabled_is_noop(monkeypatch):
    # frozen settings can't be mutated; replace the module reference instead
    monkeypatch.setattr(auth, "settings", SimpleNamespace(auth_enabled=False))
    assert require_role("admin")(_Req(None)) is None    # no enforcement when off


def test_require_role_enforces_when_enabled(monkeypatch):
    monkeypatch.setattr(auth, "settings", SimpleNamespace(auth_enabled=True))
    dep = require_role("admin")
    assert dep(_Req({"role": "admin"}))["role"] == "admin"
    with pytest.raises(HTTPException) as e1:
        dep(_Req({"role": "analyst"}))               # insufficient role -> 403
    assert e1.value.status_code == 403
    with pytest.raises(HTTPException) as e2:
        dep(_Req(None))                              # unauthenticated -> 401
    assert e2.value.status_code == 401

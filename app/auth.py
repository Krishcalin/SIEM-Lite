"""Authentication helpers: password hashing (pbkdf2, stdlib), roles, and the
RBAC dependency. Session storage lives in `db`; route wiring lives in `main`.

Passwords are stored as ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`` —
no third-party crypto dependency. Roles are ranked viewer < analyst < admin.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request

from .config import settings

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 200_000

ROLES = ("viewer", "analyst", "admin")
_RANK = {r: i for i, r in enumerate(ROLES)}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            bytes.fromhex(salt), _ITERATIONS).hex()
    return f"{_ALGO}${_ITERATIONS}${salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, expected = stored.split("$")
        if algo != _ALGO:
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                   bytes.fromhex(salt), int(iterations)).hex()
        return hmac.compare_digest(calc, expected)
    except (ValueError, AttributeError):
        return False


def role_at_least(user_role: str, required: str) -> bool:
    return _RANK.get(user_role, -1) >= _RANK.get(required, 99)


def require_role(required: str):
    """FastAPI dependency factory: ensure the request's user has >= `required`
    role. A no-op when AUTH_ENABLED is false (preserves the unauthenticated
    deployment mode). The auth middleware has already populated request.state.user."""
    def dependency(request: Request) -> dict | None:
        if not settings.auth_enabled:
            return None
        user = getattr(request.state, "user", None)
        if user is None:
            raise HTTPException(status_code=401, detail="authentication required")
        if not role_at_least(user.get("role", ""), required):
            raise HTTPException(status_code=403, detail="insufficient role")
        return user
    return dependency

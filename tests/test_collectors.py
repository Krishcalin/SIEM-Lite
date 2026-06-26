"""Unit tests for collectors: URL building, cursor advancement, run glue (mocked)."""
import app.collectors.runner as runner
from app.collectors.base import FetchResult, json_records, max_time_iso
from app.collectors.cloud import (AwsCloudTrailCollector, EntraSignInCollector,
                                  M365AuditCollector, cloudtrail_body,
                                  cloudtrail_records, content_uris, graph_signin_url,
                                  mgmt_content_url, ms_access_token, ms_token_form,
                                  ms_token_url, sigv4_headers)
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
    # Microsoft Graph wraps records under "value"; key= unwraps it
    assert json_records('{"value":[{"a":1}]}', key="value") == [{"a": 1}]
    assert json_records('{"value":[{"a":1}]}') == []        # no key -> nothing
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


# --------------------------------------------------------------------------- #
#  Cloud / identity collectors (SigV4 + Microsoft OAuth)                       #
# --------------------------------------------------------------------------- #
def test_sigv4_headers_deterministic_and_well_formed():
    h = sigv4_headers("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                      "us-east-1", "cloudtrail",
                      "cloudtrail.us-east-1.amazonaws.com",
                      "com.amazonaws.cloudtrail...LookupEvents", '{"MaxResults":50}',
                      "20260625T000000Z", "20260625")
    assert h["X-Amz-Date"] == "20260625T000000Z"
    assert h["Authorization"].startswith(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260625/us-east-1/cloudtrail/aws4_request")
    assert "SignedHeaders=content-type;host;x-amz-date;x-amz-target" in h["Authorization"]
    # deterministic for the same inputs
    h2 = sigv4_headers("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                       "us-east-1", "cloudtrail",
                       "cloudtrail.us-east-1.amazonaws.com",
                       "com.amazonaws.cloudtrail...LookupEvents", '{"MaxResults":50}',
                       "20260625T000000Z", "20260625")
    assert h == h2
    # a session token adds the security-token header into the signature
    h3 = sigv4_headers("AKIDEXAMPLE", "secret", "us-east-1", "cloudtrail", "host",
                       "tgt", "{}", "20260625T000000Z", "20260625", session_token="ST")
    assert h3["X-Amz-Security-Token"] == "ST"
    assert "x-amz-security-token" in h3["Authorization"]


def test_cloudtrail_body_and_record_unwrap():
    assert cloudtrail_body(100, 200) == '{"StartTime": 100, "EndTime": 200, "MaxResults": 50}'
    assert '"NextToken": "tok"' in cloudtrail_body(100, 200, "tok")
    resp = ('{"Events":[{"CloudTrailEvent":"{\\"eventName\\":\\"RunInstances\\",'
            '\\"eventTime\\":\\"2026-06-25T10:00:00Z\\"}"}],"NextToken":"NT"}')
    recs, token = cloudtrail_records(resp)
    assert token == "NT"
    assert recs == [{"eventName": "RunInstances", "eventTime": "2026-06-25T10:00:00Z"}]
    assert cloudtrail_records("nope") == ([], None)


def test_microsoft_oauth_helpers():
    assert ms_token_url("tid") == "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
    form = ms_token_form("cid", "secret", "https://graph.microsoft.com/.default")
    assert "grant_type=client_credentials" in form and "client_id=cid" in form
    assert ms_access_token('{"access_token":"AT","expires_in":3600}') == "AT"
    assert ms_access_token("not json") is None


def test_graph_and_mgmt_urls_and_content_uris():
    u = graph_signin_url("2026-06-25T00:00:00Z")
    assert u.startswith("https://graph.microsoft.com/v1.0/auditLogs/signIns")
    assert "createdDateTime%20gt%202026-06-25T00%3A00%3A00Z" in u
    m = mgmt_content_url("tid", "Audit.General", "2026-06-25T00:00:00", "2026-06-25T01:00:00")
    assert "manage.office.com/api/v1.0/tid/activity/feed/subscriptions/content" in m
    assert "contentType=Audit.General" in m
    listing = '[{"contentUri":"https://manage.office.com/blob/1"},{"x":1}]'
    assert content_uris(listing) == ["https://manage.office.com/blob/1"]


def test_cloud_collector_configured_flags():
    assert AwsCloudTrailCollector("us-east-1", "AK", "SK", "", 24).configured()
    assert not AwsCloudTrailCollector("", "AK", "SK", "", 24).configured()
    assert not AwsCloudTrailCollector("us-east-1", "AK", "", "", 24).configured()
    assert EntraSignInCollector("tid", "cid", "sec", 24).configured()
    assert not EntraSignInCollector("tid", "", "sec", 24).configured()
    assert M365AuditCollector("tid", "cid", "sec", "Audit.General", 24).configured()
    assert not M365AuditCollector("", "cid", "sec", "Audit.General", 24).configured()


def test_entra_fetch_feeds_graph_value(monkeypatch):
    c = EntraSignInCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    body = '{"value":[{"createdDateTime":"2026-06-25T10:00:00Z"},' \
           '{"createdDateTime":"2026-06-25T12:00:00Z"}]}'
    monkeypatch.setattr(c, "_http_get", lambda url, headers: body)
    res = c.fetch("2026-06-25T00:00:00Z")
    assert res.count == 2 and res.content == body          # fed straight to parser
    assert res.cursor.startswith("2026-06-25T12:00:00")    # advanced to newest


def test_aws_fetch_unwraps_to_records(monkeypatch):
    c = AwsCloudTrailCollector("us-east-1", "AK", "SK", "", 24)
    page = ('{"Events":[{"CloudTrailEvent":"{\\"eventName\\":\\"ConsoleLogin\\",'
            '\\"eventTime\\":\\"2026-06-25T09:00:00Z\\"}"}]}')   # no NextToken -> one page
    monkeypatch.setattr(c, "_post", lambda body: page)
    res = c.fetch(None)
    assert res.count == 1
    assert '"Records"' in res.content and "ConsoleLogin" in res.content

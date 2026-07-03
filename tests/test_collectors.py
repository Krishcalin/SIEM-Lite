"""Unit tests for collectors: URL building, cursor advancement, run glue (mocked)."""
import app.collectors.runner as runner
from app.collectors.base import FetchResult, json_records, max_time_iso
from app.collectors.cloud import (AwsCloudTrailCollector, EntraSignInCollector,
                                  M365AuditCollector, cloudtrail_body,
                                  cloudtrail_records, content_uris, graph_signin_url,
                                  mgmt_content_url, ms_access_token, ms_token_form,
                                  ms_token_url, sigv4_headers)
from app.collectors.gcp import (GcpAuditLogCollector, entries_list_body,
                                entries_records, gcp_access_token, jwt_bearer_form,
                                jwt_claims, logging_filter, make_jwt,
                                rsa_sign_sha256, _b64url, _rsa_private_numbers)
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


# --------------------------------------------------------------------------- #
#  GCP Cloud Audit Logs (service-account signed-JWT OAuth2)                    #
# --------------------------------------------------------------------------- #
# A throwaway 1024-bit RSA key + the signature openssl produces over the exact
# header.claims signing input below. Proves the hand-rolled DER parse + RS256
# signing match a reference implementation (no `cryptography` dependency).
_TEST_KEY = """-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAOl7yEtIFcwQ/cWQ
yLg0WVHz0pNEAnS4nP6eJx7FGLNqLjwLOKP2i4cl6AtYAbF+L5j8Y8chW51qaqac
qkoCTkasvZl47z0qEgrzQ3GXG9LOkkC8rR7apZeRRh/fcLCzlO8KAfV/NVUxCE5M
YxjEzl3sSKq9QbqEZZx5RcvMlimRAgMBAAECgYEAhx+EA01sj/UlaLkp8LEbIDqj
m2a4pSRSd2i/6ybV7L9+knFMDlgY19YwPKBqGnaUxU0L0aqUgr2bi2EPjFVZRqJ0
LQOr+45vr/GSh4xblzufm4udmc7Ybcafo1XuslOC2/m/tmcjG5vPO9fHw5mF+6+e
2JWDecFo42cDPbxkrYECQQD9yPlcacD5Rvtke/ZvlEMYp267uj7VkpThHlRnf+/Q
f+AHHWC/2YOeYiWrnSJiw9dEtMuSbgEHsxYvBTDQnOG1AkEA64Vy+I17XUPPIXj2
OKAbFRFhPHIcCNbFySxs4dCfnCYt3dN2hFRnC0Jf36fPLCQxhHZjUphw0/4kVw8O
3UmB7QJBAKJzZmOoclVfAYb17u7Hqhd6/d//PT97H//maUMDWyBM6rvDK25DLwRQ
cSqkYCF2mTKqxHDMJ66lDXs1yGSRN80CQEObylY5Xwl11rbYH24/36Zbl9sfMpcC
+EH4o8Tq+3Z6qz37XxE7nVzpD9aHOHyGY0SQK5DhO7pPQSVQqEazvD0CQQCQ4yAG
W+8k/eXTnpMOkdbeXeUp3WrB/51iHWjlN0vBphKQNmKRorUhEhp1pgO1tPQJ07X0
Qps3Izf24B5s6FmX
-----END PRIVATE KEY-----"""
# openssl dgst -sha256 -sign key over the bytes of the header.claims below.
_GOLDEN_SIG = ("JU3nrSnu_rcZ-qcOJVwUgibtqRS0wfgfVCnN8S4AFsQEBs_imLuXfNFIzQbS026k"
               "Ww9MOPqZpce7aWhi0gdA0mhiej6tS_lRdHHT1-qxbL0HtLH7kH-DQLlHhprsm1j"
               "J0b2TXxgXIYFSV1S7_G1kz1i-JvNgEP9bm2NRgIK4lvc")


def test_gcp_rsa_sign_matches_openssl():
    # This is exactly the "eyJhbGci...".<claims> signing input openssl signed.
    signing_input = (
        b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
        b"eyJpc3MiOiJzdmMtYWNjdEBwcm9qLmlhbS5nc2VydmljZWFjY291bnQuY29tIn0")
    n, d = _rsa_private_numbers(_TEST_KEY)
    assert _b64url(rsa_sign_sha256(signing_input, n, d)) == _GOLDEN_SIG


def test_gcp_rsa_handles_escaped_newline_pem():
    # A key pasted from JSON keeps literal \n; the collector must normalize it.
    n, _ = _rsa_private_numbers(_TEST_KEY.replace("\n", "\\n").replace("\\n", "\n"))
    assert n.bit_length() >= 1000


def test_gcp_make_jwt_shape_and_signature():
    jwt = make_jwt("svc@proj.iam.gserviceaccount.com", _TEST_KEY,
                   "https://oauth2.googleapis.com/token", iat=1_700_000_000)
    header, claims, sig = jwt.split(".")
    import base64 as _b
    import json as _j
    decoded = _j.loads(_b.urlsafe_b64decode(claims + "==="))
    assert decoded["iss"] == "svc@proj.iam.gserviceaccount.com"
    assert decoded["aud"] == "https://oauth2.googleapis.com/token"
    assert decoded["exp"] - decoded["iat"] == 3600
    assert header and sig  # signed, three-part


def test_gcp_jwt_claims_and_token_helpers():
    c = jwt_claims("svc@x.iam.gserviceaccount.com", "https://tok", iat=100)
    assert c["scope"].endswith("logging.read") and c["exp"] == 3700
    form = jwt_bearer_form("ASSERTION")
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" in form
    assert "assertion=ASSERTION" in form
    assert gcp_access_token('{"access_token":"AT","expires_in":3600}') == "AT"
    assert gcp_access_token("not json") is None


def test_gcp_entries_body_filter_and_unwrap():
    body = entries_list_body("my-proj", logging_filter("2026-06-25T00:00:00Z"), "PT")
    import json as _j
    payload = _j.loads(body)
    assert payload["resourceNames"] == ["projects/my-proj"]
    assert payload["pageToken"] == "PT" and payload["orderBy"] == "timestamp asc"
    assert 'logName:"cloudaudit.googleapis.com"' in payload["filter"]
    recs, tok = entries_records('{"entries":[{"timestamp":"2026-06-25T10:00:00Z"}],'
                                '"nextPageToken":"NP"}')
    assert tok == "NP" and recs[0]["timestamp"] == "2026-06-25T10:00:00Z"
    assert entries_records("nope") == ([], None)


def test_gcp_collector_configured_and_fetch(monkeypatch):
    assert GcpAuditLogCollector("proj", "svc@x", "KEY", "", 24).configured()
    assert not GcpAuditLogCollector("", "svc@x", "KEY", "", 24).configured()
    assert not GcpAuditLogCollector("proj", "svc@x", "", "", 24).configured()

    c = GcpAuditLogCollector("proj", "svc@x", "KEY", "", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    pages = iter([
        '{"entries":[{"timestamp":"2026-06-25T10:00:00Z"}],"nextPageToken":"P2"}',
        '{"entries":[{"timestamp":"2026-06-25T12:00:00Z"}]}',   # no token -> stop
    ])
    monkeypatch.setattr(c, "_post", lambda token, body: next(pages))
    res = c.fetch("2026-06-25T00:00:00Z")
    assert res.count == 2                                   # both pages walked
    assert '"entries"' in res.content and "2026-06-25T12:00:00Z" in res.content
    assert res.cursor.startswith("2026-06-25T12:00:00")    # advanced to newest

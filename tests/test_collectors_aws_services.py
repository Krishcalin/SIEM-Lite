# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the AWS security-service collectors + the GuardDuty / ASFF parsers.

DB-free and network-free: every signer, URL builder, body builder and response
unwrapper is a pure function called with a fixture string, and the three thin
network methods (`_get` / `_post` / `_http_post`) are patched on the INSTANCE.
"""
import json
from pathlib import Path

import pytest

from app.cim import match
from app.collectors.base import parse_cursor
from app.collectors.aws_services import (AwsConfigComplianceCollector,
                                         AwsGuardDutyCollector,
                                         AwsRoute53ResolverCollector,
                                         AwsSecurityHubCollector,
                                         asff_time, canonical_path, canonical_query,
                                         canonicalize_route53, detector_ids,
                                         filter_log_events_body, finding_ids,
                                         get_findings_body, get_findings_path,
                                         guardduty_findings, list_findings_body,
                                         list_findings_path, newest_updated_at,
                                         route53_records, securityhub_body,
                                         securityhub_filters, securityhub_findings,
                                         sigv4_rest_headers)
from app.collectors.cloud import sigv4_headers
from app.parsers import PARSERS, aws_guardduty, aws_securityhub, generic_json
from app.parsers.aws_guardduty import _severity as gd_severity
from app.parsers.cef import _sev_name as cef_sev_name

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def sample(name: str) -> str:
    """A shipped sample, wherever it currently lives.

    The AWS samples are staged in ``samples/pending/`` until the WIRE phase registers
    the parsers in ``app/parsers/__init__.py`` and ``app/detect.py`` and moves them up
    (dropping an undetectable file into ``samples/`` breaks the CIM corpus test)."""
    for path in (SAMPLES / name, SAMPLES / "pending" / name):
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise AssertionError(f"missing sample: {name}")


# --------------------------------------------------------------------------- #
#  SigV4 for REST-style AWS APIs                                               #
# --------------------------------------------------------------------------- #
def test_sigv4_rest_headers_matches_the_aws_published_test_vector():
    """AWS' own `get-vanilla` SigV4 test case, signature pinned verbatim.

    This is the only thing that proves the hand-built canonical request (method,
    path, query, header folding, payload hash) is the one AWS computes."""
    h = sigv4_rest_headers("AKIDEXAMPLE",
                           "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                           "us-east-1", "service", "example.amazonaws.com",
                           "GET", "/", None, "", "20150830T123600Z", "20150830")
    assert h["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")
    assert h["X-Amz-Date"] == "20150830T123600Z"
    assert "Content-Type" not in h          # a GET with no body signs no content-type


def test_sigv4_rest_headers_generalizes_the_shipped_json_signer():
    """The REST signer must be a strict generalization of `cloud.py:sigv4_headers`.

    Two signers for one algorithm can drift silently; for the POST-to-`/` case they
    have to agree byte-for-byte, and that is asserted rather than assumed."""
    args = ("AKIDEXAMPLE", "SECRET", "us-east-1", "cloudtrail",
            "cloudtrail.us-east-1.amazonaws.com")
    shipped = sigv4_headers(*args, "com.amazonaws.cloudtrail.LookupEvents",
                            '{"MaxResults":50}', "20260625T000000Z", "20260625")
    general = sigv4_rest_headers(*args, "POST", "/", None, '{"MaxResults":50}',
                                 "20260625T000000Z", "20260625",
                                 content_type="application/x-amz-json-1.1",
                                 target="com.amazonaws.cloudtrail.LookupEvents")
    assert general == shipped
    # ... and with a session token, which both signers must fold into the signature.
    shipped_st = sigv4_headers(*args, "TGT", "{}", "20260625T000000Z", "20260625",
                               session_token="ST")
    general_st = sigv4_rest_headers(*args, "POST", "/", None, "{}",
                                    "20260625T000000Z", "20260625",
                                    content_type="application/x-amz-json-1.1",
                                    session_token="ST", target="TGT")
    assert general_st == shipped_st


def test_sigv4_rest_headers_bind_the_path_and_the_query_string():
    """The whole reason this signer exists: the shipped one cannot sign a resource
    path or a query string, so both must actually change the signature."""
    base = ("AK", "SK", "us-east-1", "guardduty", "guardduty.us-east-1.amazonaws.com")
    stamps = ("20260625T000000Z", "20260625")
    root = sigv4_rest_headers(*base, "POST", "/", None, "{}", *stamps,
                              content_type="application/json")
    nested = sigv4_rest_headers(*base, "POST", "/detector/D1/findings", None, "{}",
                                *stamps, content_type="application/json")
    queried = sigv4_rest_headers(*base, "POST", "/detector/D1/findings",
                                 {"maxResults": 50}, "{}", *stamps,
                                 content_type="application/json")
    assert root["Authorization"] != nested["Authorization"]
    assert nested["Authorization"] != queried["Authorization"]
    # deterministic for identical inputs
    assert nested == sigv4_rest_headers(*base, "POST", "/detector/D1/findings", None,
                                        "{}", *stamps, content_type="application/json")


def test_canonical_path_and_query_encode_and_sort():
    assert canonical_path("/detector/D1/findings/get") == "/detector/D1/findings/get"
    assert canonical_path("") == "/"
    assert canonical_path("/a b/c~d") == "/a%20b/c~d"
    assert canonical_query(None) == "" and canonical_query({}) == ""
    # sorted by key, both sides percent-encoded
    assert canonical_query({"b": "2", "a": "1"}) == "a=1&b=2"
    assert canonical_query({"t": "2026-06-25T00:00:00+00:00"}) == \
        "t=2026-06-25T00%3A00%3A00%2B00%3A00"


# --------------------------------------------------------------------------- #
#  GuardDuty collector                                                         #
# --------------------------------------------------------------------------- #
def test_guardduty_paths_and_bodies():
    assert list_findings_path("D1") == "/detector/D1/findings"
    assert get_findings_path("D1") == "/detector/D1/findings/get"
    body = list_findings_body(1_780_000_000_000)
    assert '"greaterThanOrEqual": 1780000000000' in body      # epoch MILLIseconds
    assert '"orderBy": "ASC"' in body and '"maxResults": 50' in body
    assert '"nextToken": "P2"' in list_findings_body(1, "P2")
    assert '"nextToken"' not in body
    assert get_findings_body(["f1", "f2"]).startswith('{"findingIds": ["f1", "f2"]')


def test_guardduty_response_unwrappers_tolerate_both_key_cases():
    assert detector_ids('{"detectorIds":["D9"]}') == ["D9"]
    assert detector_ids('{"DetectorIds":["D9"]}') == ["D9"]
    assert detector_ids("nope") == [] and detector_ids("[]") == []
    assert finding_ids('{"findingIds":["f1"],"nextToken":"NT"}') == (["f1"], "NT")
    assert finding_ids('{"findingIds":["f1"]}') == (["f1"], None)
    assert finding_ids("nope") == ([], None)
    assert guardduty_findings('{"findings":[{"Id":"f1"},3]}') == [{"Id": "f1"}]
    assert guardduty_findings('{"Findings":[{"Id":"f1"}]}') == [{"Id": "f1"}]
    assert guardduty_findings("nope") == []


def test_guardduty_fetch_walks_list_then_get_and_advances_the_cursor(monkeypatch):
    c = AwsGuardDutyCollector("us-east-1", "AK", "SK", "", "DET", 24)
    seen: list = []
    lists = iter(['{"findingIds":["f1"],"nextToken":"P2"}', '{"findingIds":["f2"]}'])
    gets = iter([
        '{"findings":[{"Id":"f1","UpdatedAt":"2026-06-25T10:00:00Z","Severity":2}]}',
        '{"findings":[{"Id":"f2","UpdatedAt":"2026-06-25T12:00:00Z","Severity":8}]}',
    ])

    def fake_post(path, body):
        seen.append((path, body))
        return next(gets) if path.endswith("/get") else next(lists)

    monkeypatch.setattr(c, "_post", fake_post)
    res = c.fetch("2026-06-25T00:00:00Z")

    assert res.count == 2                                   # both pages walked
    assert '"Findings"' in res.content and '"f2"' in res.content
    assert res.cursor.startswith("2026-06-25T12:00:00")     # newest UpdatedAt
    assert [p for p, _ in seen] == ["/detector/DET/findings", "/detector/DET/findings/get",
                                    "/detector/DET/findings", "/detector/DET/findings/get"]
    assert '"nextToken": "P2"' in seen[2][1]                # the token was carried


def test_guardduty_fetch_with_nothing_new_returns_empty_and_keeps_the_cursor(monkeypatch):
    """`run_collector` gates ingest on non-blank content, so an idle poll must return
    "" — `{"Findings": []}` would re-ingest an identical zero-row batch every cycle.
    The cursor must survive: a None cursor is written as SQL NULL and resets history."""
    c = AwsGuardDutyCollector("us-east-1", "AK", "SK", "", "DET", 24)
    monkeypatch.setattr(c, "_post", lambda path, body: '{"findingIds":[]}')
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.content == "" and res.count == 0
    assert res.cursor == "2026-06-25T00:00:00.000Z"


def test_guardduty_discovers_its_detector_once_and_raises_when_there_is_none(monkeypatch):
    c = AwsGuardDutyCollector("us-east-1", "AK", "SK", "", "", 24)
    gets = iter(['{"detectorIds":["D9"]}'])        # exhausted after ONE discovery
    monkeypatch.setattr(c, "_get", lambda path: next(gets))
    monkeypatch.setattr(c, "_post", lambda path, body: '{"findingIds":[]}')
    c.fetch(None)
    c.fetch(None)                                   # cached — no second ListDetectors
    assert c.detector_id == "D9"

    empty = AwsGuardDutyCollector("us-east-1", "AK", "SK", "", "", 24)
    monkeypatch.setattr(empty, "_get", lambda path: '{"detectorIds":[]}')
    with pytest.raises(RuntimeError):               # must propagate, never be swallowed
        empty.fetch(None)


def test_newest_updated_at_tolerates_key_case_and_never_drops_the_cursor():
    recs = [{"UpdatedAt": "2026-06-25T10:00:00Z"}, {"updatedAt": "2026-06-25T12:00:00Z"}]
    assert newest_updated_at(recs, "KEEP").startswith("2026-06-25T12:00:00")
    assert newest_updated_at([{"CreatedAt": "2026-06-25T09:00:00Z"}], "KEEP").startswith(
        "2026-06-25T09:00:00")
    assert newest_updated_at([], "KEEP") == "KEEP"
    assert newest_updated_at([{"nope": 1}, 7], "KEEP") == "KEEP"


# --------------------------------------------------------------------------- #
#  Security Hub + AWS Config compliance collectors                             #
# --------------------------------------------------------------------------- #
def test_asff_time_normalizes_both_cursor_shapes():
    """Cursors are MIXED-FORMAT in one column: `iso_lookback` writes `...000Z` and
    `max_time_iso` writes `...+00:00`. A builder tested only against the Z form
    passes while every poll after the first is silently wrong."""
    assert asff_time("2026-06-25T11:30:00.000Z") == "2026-06-25T11:30:00.000Z"
    assert asff_time("2026-06-25T11:30:00+00:00") == "2026-06-25T11:30:00.000Z"
    assert asff_time("2026-06-25T17:00:00+05:30") == "2026-06-25T11:30:00.000Z"
    assert asff_time("garbage").endswith("Z")       # falls back to now, never crashes


def test_securityhub_filters_and_body():
    flt = securityhub_filters("2026-06-25T00:00:00.000Z", "2026-06-25T12:00:00.000Z")
    assert flt["UpdatedAt"] == [{"Start": "2026-06-25T00:00:00.000Z",
                                 "End": "2026-06-25T12:00:00.000Z"}]
    assert flt["RecordState"] == [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
    assert "ProductName" not in flt                  # unfiltered = every integration
    assert securityhub_filters("a", "b", "Config")["ProductName"] == \
        [{"Value": "Config", "Comparison": "EQUALS"}]
    body = securityhub_body("a", "b", "NT", "Config")
    assert '"NextToken": "NT"' in body and '"MaxResults": 100' in body
    assert '"Field": "UpdatedAt"' in body and '"SortOrder": "asc"' in body
    assert '"NextToken"' not in securityhub_body("a", "b")


def test_securityhub_findings_unwrap():
    assert securityhub_findings('{"Findings":[{"Id":"a"}],"NextToken":"NT"}') == \
        ([{"Id": "a"}], "NT")
    assert securityhub_findings('{"findings":[{"Id":"a"}]}') == ([{"Id": "a"}], None)
    assert securityhub_findings("nope") == ([], None)
    assert securityhub_findings('{"Findings":"x"}') == ([], None)


def test_securityhub_fetch_pages_and_advances_the_cursor(monkeypatch):
    c = AwsSecurityHubCollector("us-east-1", "AK", "SK", "", 24)
    bodies: list = []
    pages = iter([
        '{"Findings":[{"Id":"a","UpdatedAt":"2026-06-25T10:00:00Z"}],"NextToken":"P2"}',
        '{"Findings":[{"Id":"b","UpdatedAt":"2026-06-25T12:00:00Z"}]}',
    ])

    def fake_post(body):
        bodies.append(body)
        return next(pages)

    monkeypatch.setattr(c, "_post", fake_post)
    res = c.fetch("2026-06-25T00:00:00+00:00")
    assert res.count == 2 and '"Findings"' in res.content
    assert res.cursor.startswith("2026-06-25T12:00:00")
    assert '"Start": "2026-06-25T00:00:00.000Z"' in bodies[0]     # cursor normalized
    assert '"NextToken": "P2"' in bodies[1]

    idle = AwsSecurityHubCollector("us-east-1", "AK", "SK", "", 24)
    monkeypatch.setattr(idle, "_post", lambda body: '{"Findings":[]}')
    empty = idle.fetch("2026-06-25T00:00:00.000Z")
    assert empty.content == "" and empty.cursor == "2026-06-25T00:00:00.000Z"


def test_config_compliance_is_security_hub_narrowed_to_the_config_integration(monkeypatch):
    c = AwsConfigComplianceCollector("us-east-1", "AK", "SK", "", 24)
    assert c.name == "aws_config_compliance" and c.fmt == "aws_securityhub"
    bodies: list = []
    monkeypatch.setattr(c, "_post",
                        lambda body: bodies.append(body) or '{"Findings":[]}')
    c.fetch("2026-06-25T00:00:00.000Z")
    assert '"ProductName": [{"Value": "Config"' in bodies[0]


def test_rest_request_signs_and_addresses_the_right_endpoint(monkeypatch):
    c = AwsSecurityHubCollector("us-east-1", "AK", "SK", "ST", 24)
    seen: dict = {}
    monkeypatch.setattr(c, "_http_post",
                        lambda url, headers, data: seen.update(
                            url=url, headers=headers, data=data) or "{}")
    c._post('{"MaxResults": 100}')
    assert seen["url"] == "https://securityhub.us-east-1.amazonaws.com/findings"
    assert seen["data"] == b'{"MaxResults": 100}'
    auth = seen["headers"]["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AK/")
    assert "/us-east-1/securityhub/aws4_request" in auth
    assert "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token" in auth
    assert seen["headers"]["X-Amz-Security-Token"] == "ST"


# --------------------------------------------------------------------------- #
#  Route 53 Resolver query logs (CloudWatch Logs)                              #
# --------------------------------------------------------------------------- #
_R53_RECORD = ('{\\"version\\":\\"1.100000\\",\\"account_id\\":\\"111122223333\\",'
               '\\"region\\":\\"us-east-1\\",\\"vpc_id\\":\\"vpc-0abc\\",'
               '\\"query_timestamp\\":\\"2026-06-25T10:30:41Z\\",'
               '\\"query_name\\":\\"guzzcuhx.example.\\",\\"query_type\\":\\"A\\",'
               '\\"query_class\\":\\"IN\\",\\"rcode\\":\\"NOERROR\\",'
               '\\"answers\\":[{\\"Rdata\\":\\"203.0.113.9\\",\\"Type\\":\\"A\\"}],'
               '\\"srcaddr\\":\\"10.0.12.44\\",\\"srcport\\":\\"52239\\",'
               '\\"transport\\":\\"UDP\\",\\"srcids\\":{\\"instance\\":\\"i-0a1b\\"}}')
_R53_PAGE = ('{"events":[{"logStreamName":"vpc-0abc","timestamp":1782643841000,'
             f'"message":"{_R53_RECORD}"}}],"searchedLogStreams":[]}}')


def test_filter_log_events_body():
    body = filter_log_events_body("/aws/route53/vpc-0abc", 1000, 2000)
    assert '"logGroupName": "/aws/route53/vpc-0abc"' in body
    assert '"startTime": 1000' in body and '"endTime": 2000' in body
    assert '"limit": 1000' in body       # bounded by the API, not by the 64 MB cap
    assert '"nextToken": "NT"' in filter_log_events_body("g", 1, 2, "NT")
    assert '"nextToken"' not in body


def test_canonicalize_route53_aliases_without_overwriting():
    rec = {"query_timestamp": "2026-06-25T10:30:41Z", "srcaddr": "10.0.12.44",
           "srcport": "52239", "query_name": "a.example.", "query_type": "A",
           "transport": "UDP"}
    out = canonicalize_route53(rec, 1782643841000)
    assert out["vendor"] == "aws" and out["product"] == "route53-resolver"
    assert out["type"] == "dns"                       # the generic_json log_type handle
    assert out["timestamp"] == "2026-06-25T10:30:41Z"  # the QUERY time, not ingestion
    assert out["src_ip"] == "10.0.12.44" and out["src_port"] == "52239"
    assert out["query"] == "a.example." and out["qtype_name"] == "A"
    assert out["srcaddr"] == "10.0.12.44"             # nothing is dropped
    assert rec == {"query_timestamp": "2026-06-25T10:30:41Z", "srcaddr": "10.0.12.44",
                   "srcport": "52239", "query_name": "a.example.", "query_type": "A",
                   "transport": "UDP"}                # the input is not mutated
    # no query_timestamp -> the CloudWatch event time is the fallback
    assert canonicalize_route53({"srcaddr": "1.2.3.4"}, 1782643841000)["timestamp"] == \
        1782643841000
    # a value already present is authoritative
    assert canonicalize_route53({"vendor": "custom", "type": "x"})["vendor"] == "custom"


def test_route53_records_unwrap_the_cloudwatch_message_envelope():
    recs, token = route53_records(_R53_PAGE)
    assert token is None and len(recs) == 1
    assert recs[0]["query_name"] == "guzzcuhx.example." and recs[0]["type"] == "dns"
    assert route53_records("nope") == ([], None)
    assert route53_records('{"events":[{"message":"not json"},{"x":1},7]}') == ([], None)
    assert route53_records('{"events":[],"nextToken":"NT"}') == ([], "NT")


def test_route53_fetch_emits_a_bare_array_and_lands_in_the_cim_dns_model(monkeypatch):
    c = AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/aws/route53", 24)
    pages = iter([_R53_PAGE])
    monkeypatch.setattr(c, "_post", lambda body: next(pages))
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.count == 1
    assert res.content.startswith("[")            # what generic_json expects
    assert parse_cursor(res.cursor)["since"].startswith("2026-06-25T10:30:41")

    events = list(generic_json.parse(res.content))
    assert len(events) == 1
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("aws", "route53-resolver", "dns")
    assert e.src_ip == "10.0.12.44" and e.src_port == 52239 and e.protocol == "udp"
    assert e.event_time.isoformat().startswith("2026-06-25T10:30:41")
    assert match.tags_for(e) == ["dns"]           # the whole point of the aliasing
    assert e.raw["query"] == "guzzcuhx.example."  # CIM DNS `query` reads this key

    idle = AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/g", 24)
    monkeypatch.setattr(idle, "_post", lambda body: '{"events":[]}')
    empty = idle.fetch("2026-06-25T00:00:00.000Z")
    assert empty.content == ""
    assert parse_cursor(empty.cursor) == {"since": "2026-06-25T00:00:00.000Z"}


def test_a_truncated_route53_walk_parks_its_token_and_holds_the_watermark(monkeypatch):
    """FilterLogEvents has no sort parameter and interleaves one log STREAM per
    resolver endpoint, so a paged result set is not globally timestamp-ordered. Taking
    the maximum over the pages read therefore set `startTime` past queries sitting on
    later pages — here page 0 is the chatty endpoint at the END of the window and the
    remaining pages are everyone else from the start, so advancing drops them for good.
    """
    c = AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/aws/route53", 24)
    bodies, n = [], iter(range(100))

    def _post(body):
        bodies.append(json.loads(body))
        i = next(n)
        stamp = 1782643200000 if i == 0 else 1782636060000 + i * 60000
        return json.dumps({
            "events": [{"timestamp": stamp,
                        "message": json.dumps({"srcaddr": "10.0.0.1",
                                               "query_name": "x.example.",
                                               "query_timestamp": stamp})}],
            "nextToken": f"NT{i}"})

    monkeypatch.setattr(c, "_post", _post)
    res = c.fetch("2026-06-25T00:00:00.000Z")

    state = parse_cursor(res.cursor)
    assert state["since"] == "2026-06-25T00:00:00.000Z"     # HELD, not advanced
    assert state["next"] == "NT19"                          # last live token parked
    # The window end is parked with it: a nextToken is only valid for the identical
    # request, so replaying it against a freshly-computed endTime would be rejected.
    assert state["window_end"] == bodies[0]["endTime"]
    assert all(b["endTime"] == bodies[0]["endTime"] for b in bodies)


def test_a_parked_route53_token_replays_against_its_original_window(monkeypatch):
    c = AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/aws/route53", 24)
    bodies = []
    monkeypatch.setattr(c, "_post",
                        lambda body: bodies.append(json.loads(body)) or '{"events":[]}')
    c.fetch('{"since": "2026-06-25T00:00:00.000Z", "next": "NT9",'
            ' "window_end": 1782643200000}')
    assert bodies[0]["nextToken"] == "NT9"
    assert bodies[0]["endTime"] == 1782643200000

    # A parked token with no stored window is unusable — restart rather than replay it
    # against the wrong request. `since` is unchanged, so that re-reads, never skips.
    bodies.clear()
    c.fetch('{"since": "2026-06-25T00:00:00.000Z", "next": "NT9"}')
    assert not bodies[0].get("nextToken")


def test_route53_uses_the_shipped_json_signer_for_cloudwatch_logs(monkeypatch):
    """CloudWatch Logs is an x-amz-json-1.1 POST to "/" — the one AWS API here that
    `cloud.py:sigv4_headers` signs as-is, so it must not be re-derived."""
    c = AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/g", 24)
    seen: dict = {}
    monkeypatch.setattr(c, "_http_post",
                        lambda url, headers, data: seen.update(
                            url=url, headers=headers) or '{"events":[]}')
    c._post("{}")
    assert seen["url"] == "https://logs.us-east-1.amazonaws.com/"
    assert seen["headers"]["X-Amz-Target"] == "Logs_20140328.FilterLogEvents"
    assert seen["headers"]["Content-Type"] == "application/x-amz-json-1.1"
    assert "/us-east-1/logs/aws4_request" in seen["headers"]["Authorization"]


# --------------------------------------------------------------------------- #
#  Registration surface + configured() truth table                             #
# --------------------------------------------------------------------------- #
def test_collector_identities_are_stable():
    assert (AwsGuardDutyCollector.name, AwsGuardDutyCollector.fmt) == \
        ("aws_guardduty", "aws_guardduty")
    assert (AwsSecurityHubCollector.name, AwsSecurityHubCollector.fmt) == \
        ("aws_securityhub", "aws_securityhub")
    assert (AwsConfigComplianceCollector.name, AwsConfigComplianceCollector.fmt) == \
        ("aws_config_compliance", "aws_securityhub")
    assert AwsConfigComplianceCollector.product_name == "Config"
    assert AwsSecurityHubCollector.product_name == ""
    assert (AwsRoute53ResolverCollector.name, AwsRoute53ResolverCollector.fmt) == \
        ("aws_route53_resolver", "generic_json")
    # Route 53 rides an ALREADY-registered format, so it works the moment it is built.
    # `aws_guardduty` / `aws_securityhub` need the WIRE phase to add PARSERS entries;
    # until then `pipeline.parse_events` would raise "unknown format".
    assert AwsRoute53ResolverCollector.fmt in PARSERS


def test_aws_service_collectors_configured_flags():
    assert AwsGuardDutyCollector("us-east-1", "AK", "SK", "", "", 24).configured()
    assert not AwsGuardDutyCollector("", "AK", "SK", "", "", 24).configured()
    assert not AwsGuardDutyCollector("us-east-1", "", "SK", "", "", 24).configured()
    assert not AwsGuardDutyCollector("us-east-1", "AK", "", "", "", 24).configured()
    assert AwsSecurityHubCollector("us-east-1", "AK", "SK", "", 24).configured()
    assert not AwsSecurityHubCollector("us-east-1", "AK", "", "", 24).configured()
    assert AwsConfigComplianceCollector("us-east-1", "AK", "SK", "", 24).configured()
    # the log group is a REQUIRED, non-secret setting — no group, no collector
    assert AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "/g", 24).configured()
    assert not AwsRoute53ResolverCollector("us-east-1", "AK", "SK", "", "", 24).configured()


# --------------------------------------------------------------------------- #
#  GuardDuty parser                                                            #
# --------------------------------------------------------------------------- #
def test_guardduty_severity_reuses_the_repo_zero_to_ten_scale():
    """GuardDuty scores 0-10. `cef.py:_sev_name` is this repo's existing mapping for a
    0-10 vendor scale, so the two must agree on every whole score — that is what
    "match the vocabulary, do not invent a scale" means, asserted rather than claimed."""
    for n in range(11):
        assert gd_severity(n) == cef_sev_name(str(n)), n
    # AWS' own fractional band edges resolve to the same four words
    assert (gd_severity(3.9), gd_severity(4.0)) == ("low", "medium")
    assert (gd_severity(6.9), gd_severity(7.0)) == ("medium", "high")
    assert (gd_severity(8.9), gd_severity(9.0)) == ("high", "very-high")
    assert gd_severity("HIGH") == "high"            # a word export passes through
    assert gd_severity(None) is None and gd_severity("") is None


def test_guardduty_parser_normalizes_a_network_connection_finding():
    events = list(aws_guardduty.parse(sample("aws_guardduty.json")))
    assert len(events) == 3
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("aws", "guardduty", "threat")
    assert e.severity == "medium" and e.action == "allowed"     # Blocked: false
    # INBOUND: the observed peer is the source, the resource is the destination
    assert (e.src_ip, e.src_port) == ("198.51.100.24", 52344)
    assert (e.dst_ip, e.dst_port) == ("10.0.12.44", 22)
    assert e.protocol == "tcp" and e.app == "ssh"
    assert e.host_name == "i-0a1b2c3d4e5f60718"
    assert e.rule_name == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert e.event_time.isoformat().startswith("2026-06-25T10:05:44")   # UpdatedAt


def test_guardduty_parser_handles_dns_and_api_call_actions():
    dns, api = list(aws_guardduty.parse(sample("aws_guardduty.json")))[1:]
    # A DNS request has no ConnectionDirection and is outbound by definition: the
    # instance is the querier, so it is the SOURCE (dst stays null — there is no peer IP).
    assert (dns.src_ip, dns.dst_ip) == ("10.0.12.44", None)
    assert dns.action == "blocked" and dns.severity == "high"
    assert dns.protocol == "udp" and dns.raw["domain"] == "guzzcuhx.example"
    # An API call carries no Blocked flag, so the action falls back to the action type.
    assert api.action == "aws-api-call" and api.severity == "low"
    assert api.src_ip == "203.0.113.99" and api.dst_ip is None
    assert api.user_name == "root" and api.app == "sts"
    assert api.host_name == "111122223333"      # no instance -> the account is the asset
    assert api.raw["api"] == "GetCallerIdentity"


def test_guardduty_parser_lifts_cim_keys_and_lands_in_the_ids_model():
    events = list(aws_guardduty.parse(sample("aws_guardduty.json")))
    e = events[0]
    # CIM reads jsonb byte-exact and never descends into an array, so the values the
    # IDS model needs have to exist as scalars at top-level keys.
    assert e.raw["category"] == "UnauthorizedAccess"       # IDS `category`
    assert e.raw["threat_purpose"] == "UnauthorizedAccess"
    assert e.raw["severity_score"] == 5
    assert e.raw["account_id"] == "111122223333" and e.raw["region"] == "us-east-1"
    assert e.raw["detector_id"] == "6ab6e6ee0c4a8a0e0e3b1f6d3d9d9f11"
    assert e.raw["resource_type"] == "Instance" and e.raw["blocked"] is False
    assert e.raw["Type"] == "UnauthorizedAccess:EC2/SSHBruteForce"   # original kept
    assert [match.tags_for(x) for x in events] == [["ids"]] * 3


def test_guardduty_parser_is_indifferent_to_key_case_and_survives_garbage():
    lower = ('{"findings":[{"id":"f1","type":"Recon:EC2/PortProbeUnprotectedPort",'
             '"severity":2,"updatedAt":"2026-06-25T10:00:00Z",'
             '"service":{"action":{"actionType":"PORT_PROBE","portProbeAction":'
             '{"blocked":true,"portProbeDetails":[{"localPortDetails":{"port":3389,'
             '"portName":"RDP"},"remoteIpDetails":{"ipAddressV4":"198.51.100.7"}}]}}}}]}')
    e = next(iter(aws_guardduty.parse(lower)))
    assert e.rule_name == "Recon:EC2/PortProbeUnprotectedPort" and e.severity == "low"
    # PORT_PROBE nests its endpoints under portProbeDetails[0] — they must be flattened
    assert (e.src_ip, e.dst_port, e.app) == ("198.51.100.7", 3389, "rdp")
    assert e.action == "blocked"
    assert list(aws_guardduty.parse("")) == []
    assert list(aws_guardduty.parse("not json at all")) == []
    assert list(aws_guardduty.parse('{"Findings":[{}]}'))[0].vendor == "aws"


# --------------------------------------------------------------------------- #
#  Security Hub / ASFF parser                                                  #
# --------------------------------------------------------------------------- #
def test_asff_parser_routes_each_finding_class_to_its_own_log_type():
    control, vuln, threat = list(aws_securityhub.parse(sample("aws_securityhub.json")))
    assert [e.log_type for e in (control, vuln, threat)] == \
        ["config", "vulnerability", "threat"]
    assert all(e.vendor == "aws" and e.product == "securityhub"
               for e in (control, vuln, threat))
    assert (control.severity, vuln.severity, threat.severity) == \
        ("medium", "high", "medium")
    assert control.action == "failed"          # Compliance.Status wins
    assert threat.action == "new"              # no compliance -> the workflow status
    assert control.rule_name == "S3.4"                    # the control id
    assert vuln.rule_name == "CVE-2026-21894 - openssl"   # the plugin name
    # a threat Title embeds the offending IP, so the ASFF type is the stable signature
    assert threat.rule_name == "TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce"


def test_asff_parser_lifts_nested_and_array_values_to_scalar_raw_keys():
    control, vuln, threat = list(aws_securityhub.parse(sample("aws_securityhub.json")))
    # Change reads raw:status and raw:object — both live inside nested ASFF objects.
    assert control.raw["status"] == "FAILED"
    assert control.raw["object"] == "arn:aws:s3:::logocean-archive-prod"
    assert control.raw["control_id"] == "S3.4"
    assert control.raw["category"] == "Software and Configuration Checks"
    assert control.raw["remediation"].startswith("Enable default server-side")
    # Vulnerability reads raw:cve — buried at Vulnerabilities[0].Id, which the CIM
    # evaluator can never reach, so the parser lifts it.
    assert vuln.raw["cve"] == "CVE-2026-21894"
    assert vuln.raw["severity_label"] == "HIGH" and vuln.raw["severity_score"] == 70
    assert "cve" not in control.raw and "status" not in threat.raw
    assert threat.raw["product_name"] == "GuardDuty"
    assert control.raw["Compliance"]["Status"] == "FAILED"     # original untouched


def test_asff_parser_normalizes_the_network_tuple_and_the_affected_resource():
    threat = list(aws_securityhub.parse(sample("aws_securityhub.json")))[2]
    assert (threat.src_ip, threat.src_port) == ("198.51.100.24", 52344)
    assert (threat.dst_ip, threat.dst_port) == ("10.0.12.44", 22)
    assert threat.protocol == "tcp"
    assert threat.host_name == \
        "arn:aws:ec2:us-east-1:111122223333:instance/i-0a1b2c3d4e5f60718"
    assert threat.event_time.isoformat().startswith("2026-06-25T10:06:30")


def test_asff_severity_falls_back_to_the_normalized_score():
    """No Label at all: AWS' documented 0-100 Normalized bands, not an invented scale."""
    def sev(payload):
        return next(iter(aws_securityhub.parse(
            '{"Findings":[{"Id":"x","Severity":%s}]}' % payload))).severity

    assert sev('{"Normalized":0}') == "informational"
    assert sev('{"Normalized":39}') == "low"
    assert sev('{"Normalized":40}') == "medium"
    assert sev('{"Normalized":69}') == "medium"
    assert sev('{"Normalized":70}') == "high"
    assert sev('{"Normalized":89}') == "high"
    assert sev('{"Normalized":90}') == "critical"
    assert sev('{"Label":"CRITICAL","Normalized":40}') == "critical"   # label wins
    assert sev("{}") is None
    # FindingProviderFields is the provider's own severity, AWS' preferred fallback
    assert next(iter(aws_securityhub.parse(
        '{"Findings":[{"Id":"x","FindingProviderFields":'
        '{"Severity":{"Label":"LOW"}}}]}'))).severity == "low"


def test_asff_compliance_findings_reach_the_change_model():
    control, vuln, threat = list(aws_securityhub.parse(sample("aws_securityhub.json")))
    assert match.tags_for(control) == ["change"]
    assert match.tags_for(threat) == ["ids"]
    # The WIRE phase added `{vendor: [aws], product: [securityhub, inspector],
    # log_type: [vulnerability]}` to the Vulnerability model, so the AWS Inspector
    # finding this assertion used to pin at UNTAGGED is now a member. It stays
    # vendor+product qualified for the same reason the scanner clause is: only a
    # scanner finding may land here, never the ASFF threat finding above.
    assert match.tags_for(vuln) == ["vulnerability"]


def test_asff_parser_survives_garbage_and_partial_findings():
    assert list(aws_securityhub.parse("")) == []
    assert list(aws_securityhub.parse("not json at all")) == []
    bare = next(iter(aws_securityhub.parse('{"Findings":[{"Id":"x"}]}')))
    assert bare.vendor == "aws" and bare.log_type == "threat"
    assert bare.severity is None and bare.action is None
    # Resources / Vulnerabilities present but useless must not raise
    odd = next(iter(aws_securityhub.parse(
        '{"Findings":[{"Id":"x","Resources":["nope"],"Vulnerabilities":[],'
        '"Types":[7],"Network":{"SourceIpV4":"bogus"}}]}')))
    assert odd.host_name is None and odd.src_ip is None and odd.log_type == "threat"

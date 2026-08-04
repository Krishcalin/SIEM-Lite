# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the three CrowdStrike Falcon collectors.

DB-free and network-free: every signer, URL builder, body builder and response
unwrapper is a pure function called with a fixture string, and the thin network
methods (`_sqs` / `_s3_get` / `_http_get` / `_http_post` / `_read_stream`) are
patched on the INSTANCE.

WHY THIS FILE EXISTS
--------------------
`app/collectors/crowdstrike.py` shipped with no tests at all — 810 lines, three
registered collectors, 25% statement coverage against 83-100% for every sibling in
the same wave. An adversarial review injected eight independent defects and all
eight survived the full suite, including replacing the SigV4 derived key with the
raw secret (every FDR request would 403 and the queue would grow without bound) and
inverting the Event Streams offset comparison (every poll re-ingests the same
records forever). The module docstring also claimed the signer was "pinned to
AWS-published test vectors in the unit tests" when nothing called it.

Each test below therefore names the specific defect it kills, and the eight the
review found are all covered: the SigV4 derived key, the canonical query, the offset
walk, the receipt-handle cursor, the NDJSON split, the S3 reference extraction, the
gzip branch, and the incident reshape.
"""
from __future__ import annotations

import gzip
import hashlib
import json

import pytest

from app.collectors.crowdstrike import (CrowdStrikeFdrCollector,
                                        CrowdStrikeIncidentCollector,
                                        CrowdStrikeStreamCollector,
                                        canonical_query, canonical_request,
                                        datafeed_streams, datafeed_url,
                                        falcon_token, falcon_token_form,
                                        fdr_cursor, fdr_file_refs,
                                        fdr_pending_handles, feed_key, fql_time,
                                        gunzip_ndjson, incident_detail_body,
                                        incident_ids, incident_query_url,
                                        incident_records, incident_status,
                                        max_offset, s3_canonical_path, s3_host,
                                        shape_incident, sigv4_authorization,
                                        sigv4_signed_headers, sqs_delete_batch_body,
                                        sqs_host, sqs_messages, sqs_receive_body,
                                        stream_cursor, stream_offsets,
                                        stream_records, stream_url_with_offset)

_EMPTY_SHA = hashlib.sha256(b"").hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
#  SigV4 — pinned to AWS's own published vectors
# ══════════════════════════════════════════════════════════════════════════════
def test_sigv4_reproduces_the_aws_published_get_vanilla_vector():
    """The claim the module docstring already made, now actually made true.

    This is hand-rolled crypto that the project charter singles out as needing
    verification, and its twin in `aws_s3.py` IS pinned to a published vector while
    this copy was not. Mutation: `hmac.new(_signing_key(secret, date, region,
    service), ...)` -> `hmac.new(secret_key.encode("utf-8"), ...)`, i.e. sign with
    the raw secret instead of the four-step derived key. Every SQS ReceiveMessage
    and every S3 GetObject then returns 403 SignatureDoesNotMatch: the FDR feed
    ingests nothing while the SQS queue grows without bound.
    """
    auth = sigv4_authorization(
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1", service="service", method="GET", uri_path="/", query="",
        headers={"host": "example.amazonaws.com",
                 "x-amz-date": "20150830T123600Z"},
        payload_hash=_EMPTY_SHA,
        amz_date="20150830T123600Z", datestamp="20150830")
    assert auth == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


def test_sigv4_signs_the_query_string(monkeypatch):
    """Mutation: drop `query` from the canonical request. Two requests differing
    ONLY in their query string would then carry the same signature — which AWS
    rejects, and which would silently mis-sign every parameterised GET."""
    def sign(query):
        return sigv4_authorization(
            access_key="AK", secret_key="SK", region="us-east-1", service="s3",
            method="GET", uri_path="/", query=query,
            headers={"host": "h", "x-amz-date": "20260625T000000Z"},
            payload_hash=_EMPTY_SHA,
            amz_date="20260625T000000Z", datestamp="20260625")

    assert sign("a=1") != sign("a=2")
    assert sign("") != sign("a=1")


def test_canonical_request_has_the_documented_shape():
    creq = canonical_request(
        "get", "/", "b=2&a=1",
        {"Host": "example.com", "X-Amz-Date": "  20260625T000000Z  "}, _EMPTY_SHA)
    lines = creq.split("\n")
    assert lines[0] == "GET"                       # method upper-cased
    assert lines[1] == "/" and lines[2] == "b=2&a=1"
    assert lines[3] == "host:example.com"          # lower-cased name
    assert lines[4] == "x-amz-date:20260625T000000Z"    # value whitespace-collapsed
    assert lines[6] == "host;x-amz-date"           # signed-header list, sorted
    assert lines[7] == _EMPTY_SHA


def test_canonical_query_is_sorted_and_rfc3986_encoded():
    assert canonical_query({"b": "2", "a": "1"}) == "a=1&b=2"
    assert canonical_query({}) == ""
    # a space is %20, never '+', and the unreserved set is left alone
    assert canonical_query({"k": "a b"}) == "k=a%20b"
    assert canonical_query({"k": "a-_.~"}) == "k=a-_.~"


def test_signed_headers_omit_host_but_still_sign_it():
    """urllib derives `Host` from the URL; returning a second one that disagreed
    would break the signature."""
    headers = sigv4_signed_headers(
        access_key="AK", secret_key="SK", region="eu-west-1", service="sqs",
        method="POST", host="sqs.eu-west-1.amazonaws.com", uri_path="/", params={},
        payload=b"{}", amz_date="20260625T000000Z", datestamp="20260625",
        session_token="ST", extra_headers={"X-Amz-Target": "AmazonSQS.ReceiveMessage"})
    assert "host" not in headers
    assert "host" in headers["authorization"]              # ...but it IS signed
    assert headers["x-amz-security-token"] == "ST"
    assert "x-amz-security-token" in headers["authorization"]
    assert headers["x-amz-target"] == "AmazonSQS.ReceiveMessage"


def test_s3_and_sqs_endpoints_and_key_encoding():
    assert sqs_host("us-east-2") == "sqs.us-east-2.amazonaws.com"
    # regional virtual-hosted style everywhere, us-east-1 included: one signing path
    assert s3_host("bkt", "us-east-1") == "bkt.s3.us-east-1.amazonaws.com"
    # single-encoded; '/' stays a separator because S3 does not double-encode
    assert s3_canonical_path("a/b c/d.gz") == "/a/b%20c/d.gz"
    assert s3_canonical_path("/leading") == "/leading"


# ══════════════════════════════════════════════════════════════════════════════
#  FDR — SQS notifications -> gzip-NDJSON objects in S3
# ══════════════════════════════════════════════════════════════════════════════
def test_sqs_receive_body_clamps_every_bound():
    body = json.loads(sqs_receive_body("https://q", max_messages=99,
                                       wait_seconds=999, visibility_timeout=5))
    assert body["MaxNumberOfMessages"] == 10       # SQS hard maximum
    assert body["WaitTimeSeconds"] == 20           # long-poll maximum, < the 30s timeout
    assert body["VisibilityTimeout"] == 30         # floor: must outlive a poll interval
    low = json.loads(sqs_receive_body("https://q", max_messages=0, wait_seconds=-1))
    assert low["MaxNumberOfMessages"] == 1 and low["WaitTimeSeconds"] == 0


def test_sqs_messages_parses_the_json_string_body():
    body = json.dumps({"Messages": [
        {"ReceiptHandle": "h1", "Body": json.dumps({"bucket": "b", "files": []})},
        {"ReceiptHandle": "h2", "Body": "not json"},      # kept, so it gets ACKED
        {"ReceiptHandle": "", "Body": "{}"},              # no handle -> unusable
        {"Body": "{}"},
        "not a dict",
    ]})
    msgs = sqs_messages(body)
    assert [m["handle"] for m in msgs] == ["h1", "h2"]
    assert msgs[0]["body"] == {"bucket": "b", "files": []}
    # An unparseable body must still come back, or SQS redelivers it forever.
    assert msgs[1]["body"] is None
    assert sqs_messages("nope") == [] and sqs_messages("[]") == []


def test_fdr_file_refs_reads_both_notification_shapes():
    """Mutation: `return []`. The collector then acks every SQS message without
    fetching a single object — the whole feed is deleted, unread, and the batch
    reports success."""
    fdr = {"bucket": "cs-bucket", "files": [{"path": "d/1.gz"}, {"key": "d/2.gz"},
                                            "d/3.gz", 7]}
    assert fdr_file_refs(fdr) == [("cs-bucket", "d/1.gz"), ("cs-bucket", "d/2.gz"),
                                  ("cs-bucket", "d/3.gz")]
    # the plain S3 event shape, whose keys are URL-encoded on the wire
    s3_event = {"Records": [{"s3": {"bucket": {"name": "b2"},
                                    "object": {"key": "a+b/c%20d.gz"}}}]}
    assert fdr_file_refs(s3_event) == [("b2", "a b/c d.gz")]
    # a notification with no bucket of its own falls back to the configured one
    assert fdr_file_refs({"files": ["x.gz"]}, "fallback") == [("fallback", "x.gz")]
    assert fdr_file_refs({"files": ["x.gz"]}) == []       # ...and without one, nothing
    assert fdr_file_refs(None) == [] and fdr_file_refs({}) == []


def test_gunzip_ndjson_handles_gzip_and_plain_and_raises_on_corruption():
    """Mutation: disable the gzip-magic branch. Every FDR object then decodes as
    replacement characters and yields zero parseable events, while the message is
    acked as read."""
    lines = '{"a":1}\n\n{"b":2}\n'
    assert gunzip_ndjson(gzip.compress(lines.encode())) == ['{"a":1}', '{"b":2}']
    assert gunzip_ndjson(lines.encode()) == ['{"a":1}', '{"b":2}']    # already plain
    # Corrupt gzip must RAISE: the fetch fails, nothing is acked, SQS redelivers.
    with pytest.raises(Exception):
        gunzip_ndjson(b"\x1f\x8b" + b"garbage that is not a gzip stream")


def test_fdr_cursor_round_trips_the_receipt_handles():
    """Mutation: `fdr_pending_handles` -> `return []`. No receipt handle is ever
    acked, so every message redelivers on its visibility timeout and the collector
    re-ingests the same objects forever."""
    assert fdr_pending_handles(fdr_cursor(["h1", "h2"])) == ["h1", "h2"]
    assert fdr_pending_handles(None) == []
    assert fdr_pending_handles("") == []
    assert fdr_pending_handles("not json") == []          # tolerant, never raises
    assert fdr_pending_handles('{"ack": "h1"}') == []      # not a list
    assert fdr_pending_handles('{"ack": ["h1", 7, ""]}') == ["h1"]


def _fdr(**kw) -> CrowdStrikeFdrCollector:
    opts = dict(queue_url="https://sqs/q", region="us-east-1", access_key="AK",
                secret_key="SK", session_token="", bucket="cs-bucket")
    opts.update(kw)
    return CrowdStrikeFdrCollector(**opts)


def test_fdr_configured_requires_the_queue_and_the_credentials():
    assert _fdr().configured()
    assert not _fdr(queue_url="").configured()
    assert not _fdr(access_key="").configured()
    assert not _fdr(secret_key="").configured()
    assert not _fdr(region="").configured()


def test_fdr_fetch_acks_the_PREVIOUS_batch_then_reads_the_next(monkeypatch):
    """The deferred-ack protocol, which is the whole point of the FDR cursor.

    A message is acked on the NEXT poll, after its events have been ingested and the
    cursor persisted — never in the same poll that read it. Acking early would delete
    the notification before the data behind it was safely stored.
    """
    c = _fdr()
    calls: list[tuple[str, dict]] = []

    def _sqs(target, body):
        calls.append((target, json.loads(body)))
        if target.endswith("DeleteMessageBatch"):
            return "{}"
        return json.dumps({"Messages": [
            {"ReceiptHandle": "new-1",
             "Body": json.dumps({"bucket": "cs-bucket", "files": [{"path": "a.gz"}]})}]})

    monkeypatch.setattr(c, "_sqs", _sqs)
    monkeypatch.setattr(c, "_s3_get",
                        lambda bucket, key: gzip.compress(b'{"event_simpleName":"X"}\n'))

    res = c.fetch(fdr_cursor(["old-1", "old-2"]))

    assert calls[0][0] == "AmazonSQS.DeleteMessageBatch"          # ack FIRST
    assert [e["ReceiptHandle"] for e in calls[0][1]["Entries"]] == ["old-1", "old-2"]
    assert calls[1][0] == "AmazonSQS.ReceiveMessage"              # then receive
    assert res.count == 1 and '"event_simpleName": "X"' in res.content.replace('":"', '": "')
    # the handle just read is parked, NOT acked in this poll
    assert fdr_pending_handles(res.cursor) == ["new-1"]


def test_fdr_fetch_fetches_every_object_a_notification_names(monkeypatch):
    c = _fdr()
    fetched: list[tuple[str, str]] = []
    monkeypatch.setattr(c, "_sqs", lambda target, body: json.dumps({"Messages": [
        {"ReceiptHandle": "h", "Body": json.dumps(
            {"bucket": "cs-bucket", "files": [{"path": "1.gz"}, {"path": "2.gz"}]})}]}))

    def _s3_get(bucket, key):
        fetched.append((bucket, key))
        return gzip.compress(f'{{"k":"{key}"}}\n'.encode())

    monkeypatch.setattr(c, "_s3_get", _s3_get)
    res = c.fetch(None)
    assert fetched == [("cs-bucket", "1.gz"), ("cs-bucket", "2.gz")]
    assert res.count == 2 and len(res.content.splitlines()) == 2


def test_a_failed_ack_is_logged_and_never_wedges_the_collector(monkeypatch):
    """A receipt handle dies with its visibility timeout, and a failed delete only
    means SQS redelivers — which the event dedup absorbs. Letting it raise would be
    the opposite of safe: the cursor carrying those handles would never advance, so
    every future poll would retry the same doomed delete forever."""
    c = _fdr()

    def _sqs(target, body):
        if target.endswith("DeleteMessageBatch"):
            raise RuntimeError("AWS.SimpleQueueService.InvalidReceiptHandle")
        return json.dumps({"Messages": []})

    monkeypatch.setattr(c, "_sqs", _sqs)
    res = c.fetch(fdr_cursor(["dead-handle"]))        # must NOT raise
    assert res.count == 0
    assert fdr_pending_handles(res.cursor) == []      # and the doomed handle is released


def test_fdr_object_budget_never_starves_the_first_message(monkeypatch):
    """The budget stops runaway polls, but a single notification bigger than the
    whole budget must still make progress or the queue wedges permanently."""
    from app.collectors import crowdstrike as cs

    monkeypatch.setattr(cs, "_MAX_OBJECTS", 2)
    c = _fdr()
    big = {"bucket": "b", "files": [{"path": f"{i}.gz"} for i in range(5)]}
    monkeypatch.setattr(c, "_sqs", lambda target, body: json.dumps({"Messages": [
        {"ReceiptHandle": "h1", "Body": json.dumps(big)},
        {"ReceiptHandle": "h2", "Body": json.dumps(big)}]}))
    monkeypatch.setattr(c, "_s3_get", lambda bucket, key: b'{"x":1}\n')

    res = c.fetch(None)
    assert res.count == 5                             # the first message is read WHOLE
    assert fdr_pending_handles(res.cursor) == ["h1"]  # the second waits for the next poll


# ══════════════════════════════════════════════════════════════════════════════
#  Falcon OAuth2 (shared by Streams + Incidents)
# ══════════════════════════════════════════════════════════════════════════════
def test_falcon_token_form_is_client_credentials():
    form = falcon_token_form("cid", "s3cr3t")
    assert "client_id=cid" in form and "client_secret=s3cr3t" in form


def test_falcon_token_treats_an_unknown_lifetime_as_already_stale():
    assert falcon_token('{"access_token":"AT","expires_in":1799}') == ("AT", 1799)
    # Re-authenticating is always safe; caching a token of unknown lifetime is not.
    assert falcon_token('{"access_token":"AT"}') == ("AT", 0)
    assert falcon_token('{"access_token":"AT","expires_in":"soon"}') == ("AT", 0)
    assert falcon_token("nope") == (None, 0)
    assert falcon_token('{"errors":[{"message":"denied"}]}') == (None, 0)


def test_the_token_is_cached_until_it_nears_expiry_then_refetched(monkeypatch):
    from app.collectors import crowdstrike as cs

    clock = [1000.0]
    monkeypatch.setattr(cs, "_monotonic", lambda: clock[0])
    c = CrowdStrikeIncidentCollector("https://api", "cid", "sec", 24)
    posts: list[str] = []
    monkeypatch.setattr(c, "_http_post", lambda url, headers, body: posts.append(url) or
                        '{"access_token":"AT","expires_in":1800}')

    assert c._token() == "AT" and len(posts) == 1
    clock[0] += 60
    assert c._token() == "AT" and len(posts) == 1        # served from cache
    clock[0] += 1800
    assert c._token() == "AT" and len(posts) == 2        # past the skew -> refetched


def test_a_token_response_without_a_token_raises(monkeypatch):
    c = CrowdStrikeIncidentCollector("https://api", "cid", "sec", 24)
    monkeypatch.setattr(c, "_http_post", lambda url, headers, body: '{"errors":[]}')
    with pytest.raises(RuntimeError, match="access_token"):
        c._token()


# ══════════════════════════════════════════════════════════════════════════════
#  Event Streams — offset resume
# ══════════════════════════════════════════════════════════════════════════════
def test_datafeed_streams_drops_a_partition_missing_either_half():
    body = json.dumps({"resources": [
        {"dataFeedURL": "https://f/1", "sessionToken": {"token": "T1"}},
        {"datafeedURL": "https://f/2", "sessionToken": {"token": "T2"}},   # alt spelling
        {"dataFeedURL": "https://f/3"},                                     # no token
        {"sessionToken": {"token": "T4"}},                                  # no url
        {"dataFeedURL": "https://f/5", "sessionToken": "T5"},               # not a dict
        "junk",
    ]})
    assert datafeed_streams(body) == [{"url": "https://f/1", "token": "T1"},
                                      {"url": "https://f/2", "token": "T2"}]
    assert datafeed_streams("nope") == []


def test_feed_key_ignores_the_query_because_the_offset_lives_there():
    """The offset changes every poll. Keying on the full URL would mint a new
    partition key each time and restart the stream from scratch, forever."""
    a = "https://firehose.crowdstrike.com/sensors/entities/datafeed/v2?appId=x&offset=1"
    b = "https://firehose.crowdstrike.com/sensors/entities/datafeed/v2?appId=x&offset=99"
    assert feed_key(a) == feed_key(b)
    assert feed_key(a) == "firehose.crowdstrike.com/sensors/entities/datafeed/v2"


def test_stream_url_with_offset_replaces_rather_than_appends():
    url = "https://f/v2?appId=logocean&offset=10"
    out = stream_url_with_offset(url, "42")
    assert "offset=42" in out and "offset=10" not in out
    assert "appId=logocean" in out                   # the rest is preserved
    assert stream_url_with_offset(url, None) == url  # no offset -> untouched
    assert stream_url_with_offset(url, "") == url


def test_stream_records_drops_the_partial_trailing_line():
    """Mutation: `return []`. Every poll then ingests nothing while its offsets still
    advance past the records it never read.

    A firehose batch is cut at an arbitrary byte boundary, so the last line can be a
    truncated object. It is dropped, and because the cursor comes from the records
    that DID parse, that offset is simply re-read next poll.
    """
    text = ('{"metadata":{"offset":1}}\n'
            '\n'
            '{"metadata":{"offset":2}}\n'
            '{"metadata":{"offse')            # cut mid-object
    recs = stream_records(text)
    assert [r["metadata"]["offset"] for r in recs] == [1, 2]
    assert stream_records("") == []
    assert stream_records("[1,2]") == []      # a top-level array is not a record


def test_max_offset_takes_the_HIGHEST_offset():
    """Mutation: `offset > best` -> `offset < best`. The checkpoint then walks
    BACKWARDS, so every poll re-reads the same records and the collector never
    makes progress."""
    recs = [{"metadata": {"offset": 5}}, {"metadata": {"offset": 99}},
            {"metadata": {"offset": 7}}]
    assert max_offset(recs, None) == "99"
    assert max_offset([{"offset": 3}], None) == "3"          # bare-offset shape
    # an empty or unusable batch must never NULL the checkpoint
    assert max_offset([], "42") == "42"
    assert max_offset([{"metadata": {"offset": "abc"}}, "junk"], "42") == "42"


def test_stream_offsets_round_trip_and_tolerate_a_garbled_cursor():
    assert stream_offsets(stream_cursor({"k": "42"})) == {"k": "42"}
    assert stream_offsets(None) == {} and stream_offsets("nope") == {}
    assert stream_offsets("[1]") == {}
    assert stream_offsets('{"k": 42}') == {"k": "42"}        # coerced to str


def test_stream_fetch_resumes_each_partition_at_its_own_offset(monkeypatch):
    """Two partitions, independent offsets. A single shared offset would replay one
    partition and skip the other."""
    c = CrowdStrikeStreamCollector("https://api", "cid", "sec", "app1", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_http_get", lambda url, headers: json.dumps({"resources": [
        {"dataFeedURL": "https://f/p1?appId=app1", "sessionToken": {"token": "T1"}},
        {"dataFeedURL": "https://f/p2?appId=app1", "sessionToken": {"token": "T2"}}]}))

    seen: list[str] = []

    def _read(url, headers):
        seen.append(url)
        n = 10 if "/p1" in url else 20
        assert headers["Authorization"].startswith("Token T")
        return json.dumps({"metadata": {"offset": n}})

    monkeypatch.setattr(c, "_read_stream", _read)

    res = c.fetch(stream_cursor({"f/p1": "7"}))
    assert "offset=7" in seen[0]                  # p1 resumed at its stored offset
    assert "offset" not in seen[1]                # p2 has none yet -> from the start
    assert res.count == 2
    assert stream_offsets(res.cursor) == {"f/p1": "10", "f/p2": "20"}


def test_datafeed_url_carries_the_app_id():
    assert "appId=logocean" in datafeed_url("https://api/", "logocean")
    # A shared appId makes two consumers steal each other's offsets, so it defaults
    # to something explicit rather than empty.
    c = CrowdStrikeStreamCollector("https://api", "c", "s", "", 24)
    assert c.app_id == "logocean"


# ══════════════════════════════════════════════════════════════════════════════
#  Incidents — id query, pagination, entity fetch
# ══════════════════════════════════════════════════════════════════════════════
def test_fql_time_normalizes_both_cursor_spellings():
    """Both spellings live in one column — `iso_lookback` writes `...T00:00:00.000Z`
    and `max_time_iso` writes `...+00:00`. An unescaped `+` in a query string decodes
    as a space and silently shifts the window."""
    assert fql_time("2026-06-25T00:00:00.000Z") == "2026-06-25T00:00:00Z"
    assert fql_time("2026-06-25T02:00:00+02:00") == "2026-06-25T00:00:00Z"
    assert fql_time("nonsense") == "nonsense"       # passed through, never guessed at


def test_incident_query_url_sorts_ascending_and_urlencodes_the_filter():
    url = incident_query_url("https://api/", "2026-06-25T00:00:00.000Z")
    # ASCENDING is what makes max-over-what-was-read a valid watermark under a page cap
    assert "sort=modified_timestamp.asc" in url
    assert "modified_timestamp" in url and "%3A" in url    # the filter is encoded
    assert "+00%3A00" not in url                            # no raw offset survived
    assert "offset" not in url                              # omitted on the first page
    assert "offset=50" in incident_query_url("https://api", "2026-06-25T00:00:00Z", 50)


def test_incident_ids_stops_paginating_at_the_total():
    page1 = json.dumps({"resources": ["a", "b"],
                        "meta": {"pagination": {"offset": 0, "total": 5}}})
    assert incident_ids(page1) == (["a", "b"], 2)
    last = json.dumps({"resources": ["e"],
                       "meta": {"pagination": {"offset": 4, "total": 5}}})
    assert incident_ids(last) == (["e"], None)
    # One page is a safe under-read; an infinite loop is not — so anything unexpected
    # in the pagination block ends the walk.
    assert incident_ids(json.dumps({"resources": ["a"]})) == (["a"], None)
    assert incident_ids(json.dumps({"resources": ["a"], "meta": {"pagination": {
        "offset": "next-token", "total": 9}}})) == (["a"], None)
    assert incident_ids("nope") == ([], None)


def test_incident_status_maps_the_numeric_codes():
    assert incident_status(20) == "New" and incident_status(40) == "Closed"
    assert incident_status("Closed") == "Closed"     # already text
    assert incident_status(None) is None and incident_status(999) is None


def test_shape_incident_lifts_the_nested_lists_to_readable_scalars():
    """Mutation: `return dict(inc)`. Neither `crowdstrike_json._g` nor
    `cim.match._raw_value` can reach into a list — a container yields nothing — so
    every incident would store with host, user, tactic and technique all null."""
    inc = {
        "incident_id": "inc:1", "modified_timestamp": "2026-06-25T10:00:00Z",
        "status": 30,
        "hosts": [{"hostname": "WKS-01", "device_id": "aid-1",
                   "local_ip": "10.0.0.5", "external_ip": "203.0.113.9"}],
        "tactics": ["Credential Access"], "techniques": ["Credential Dumping"],
        "users": ["jdoe"],
    }
    out = shape_incident(inc)
    assert out["hostname"] == "WKS-01" and out["aid"] == "aid-1"
    assert out["local_ip"] == "10.0.0.5" and out["external_ip"] == "203.0.113.9"
    assert out["tactic"] == "Credential Access"
    assert out["technique"] == "Credential Dumping"
    assert out["user_name"] == "jdoe"
    assert out["action"] == "In Progress"           # 30 -> text, not the raw int
    assert out["timestamp"] == "2026-06-25T10:00:00Z"
    # nothing is removed: the originals survive for a later case import
    assert out["incident_id"] == "inc:1" and out["hosts"] == inc["hosts"]


def test_shape_incident_never_clobbers_a_value_the_vendor_already_sent():
    out = shape_incident({"hostname": "vendor-sent", "user_name": "vendor-user",
                          "hosts": [{"hostname": "lifted"}], "users": ["lifted"]})
    assert out["hostname"] == "vendor-sent" and out["user_name"] == "vendor-user"


def test_shape_incident_reads_a_dict_entry_in_a_list_field():
    out = shape_incident({"tactics": [{"name": "Defense Evasion"}]})
    assert out["tactic"] == "Defense Evasion"


def test_incident_records_unwraps_and_shapes():
    body = json.dumps({"resources": [{"incident_id": "i1", "users": ["u"]}, "junk"]})
    recs = incident_records(body)
    assert len(recs) == 1 and recs[0]["user_name"] == "u"
    assert incident_records("nope") == []


def test_incident_fetch_pages_then_emits_the_shape_the_parser_unwraps(monkeypatch):
    c = CrowdStrikeIncidentCollector("https://api", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    listings = iter([
        json.dumps({"resources": ["a", "b"],
                    "meta": {"pagination": {"offset": 0, "total": 3}}}),
        json.dumps({"resources": ["c"],
                    "meta": {"pagination": {"offset": 2, "total": 3}}}),
    ])
    posted: list[dict] = []
    monkeypatch.setattr(c, "_http_get", lambda url, headers: next(listings))

    def _post(url, headers, body):
        ids = json.loads(body)["ids"]
        posted.append(ids)
        assert headers["Content-Type"] == "application/json"
        return json.dumps({"resources": [
            {"incident_id": i, "modified_timestamp": f"2026-06-25T10:0{n}:00Z"}
            for n, i in enumerate(ids)]})

    monkeypatch.setattr(c, "_http_post", _post)

    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert posted == [["a", "b"], ["c"]]           # both pages fetched in batches
    assert res.count == 3
    # {"resources": [...]} is exactly what crowdstrike_json unwraps
    assert list(json.loads(res.content)) == ["resources"]
    assert res.cursor.startswith("2026-06-25T10:0")     # advanced to the newest


def test_incident_fetch_keeps_the_cursor_on_an_idle_poll(monkeypatch):
    c = CrowdStrikeIncidentCollector("https://api", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_http_get", lambda url, headers: '{"resources":[]}')
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.content == "" and res.count == 0
    # never None: run_collector writes the cursor unconditionally, and a None would
    # NULL the checkpoint and replay the whole lookback window
    assert res.cursor == "2026-06-25T00:00:00.000Z"


def test_incident_detail_body_stringifies_the_ids():
    assert json.loads(incident_detail_body(["a", 7])) == {"ids": ["a", "7"]}


# ══════════════════════════════════════════════════════════════════════════════
#  Registration
# ══════════════════════════════════════════════════════════════════════════════
def test_all_three_collectors_declare_a_registered_parser_format():
    from app.parsers import PARSERS

    for cls in (CrowdStrikeFdrCollector, CrowdStrikeStreamCollector,
                CrowdStrikeIncidentCollector):
        assert cls.fmt in PARSERS, cls.__name__
        assert cls.name and cls.label
    names = {CrowdStrikeFdrCollector.name, CrowdStrikeStreamCollector.name,
             CrowdStrikeIncidentCollector.name}
    assert len(names) == 3

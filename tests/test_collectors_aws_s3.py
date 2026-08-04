# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the AWS S3 + SQS log transport (CloudTrail at full fidelity).

DB-free and network-free: every URL builder, signer, notification unwrapper and
object decoder is a pure function called with a fixture string, and the two thin
network methods (`_sqs`, `_get_object`) are patched on the instance.
"""
import gzip
import json

import app.collectors.aws_s3 as aws_s3
from app.collectors.aws_s3 import (AwsS3CloudTrailCollector, S3SqsCollector,
                                   gunzip_text, gzip_records, s3_canonical_path,
                                   s3_host, s3_object_keys, s3_object_url,
                                   sigv4_rest_headers, sqs_delete_body, sqs_host,
                                   sqs_messages, sqs_receive_body)

# --------------------------------------------------------------------------- #
#  Fixtures — the exact wire shapes AWS produces                               #
# --------------------------------------------------------------------------- #
_KEY = ("AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/25/"
        "123456789012_CloudTrail_us-east-1_20260625T1000Z_aB3.json.gz")

# S3 -> SNS -> SQS: the SNS `Message` is the S3 event as a JSON *string*.
_S3_EVENT = json.dumps({"Records": [{
    "eventName": "ObjectCreated:Put",
    "s3": {"bucket": {"name": "my-trail-bucket"},
           "object": {"key": _KEY, "size": 4096}},
}]})
_SNS_BODY = json.dumps({"Type": "Notification", "MessageId": "m-1",
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:trail",
                        "Message": _S3_EVENT})

# What AWS posts once, on its own, when the notification is first configured.
_TEST_EVENT_BODY = json.dumps({"Service": "Amazon S3", "Event": "s3:TestEvent",
                               "Time": "2026-06-25T10:00:00.000Z",
                               "Bucket": "my-trail-bucket", "RequestId": "R1"})

_TRAIL_OBJECT = gzip.compress(json.dumps({"Records": [
    {"eventTime": "2026-06-25T10:00:00Z", "eventName": "GetObject",
     "eventSource": "s3.amazonaws.com"},
    {"eventTime": "2026-06-25T11:30:00Z", "eventName": "PutObject",
     "eventSource": "s3.amazonaws.com"},
]}).encode("utf-8"))


def _receive(*bodies: str) -> str:
    """A ReceiveMessage response carrying one message per body."""
    return json.dumps({"Messages": [
        {"MessageId": f"m{i}", "ReceiptHandle": f"RH{i}", "Body": b}
        for i, b in enumerate(bodies)]})


def _wire(c, monkeypatch, receive_pages, objects):
    """Patch the two thin network methods; return the call log.

    `receive_pages` is exhaustible so an over-fetch raises StopIteration rather
    than looping forever; `objects` maps (bucket, key) -> bytes or an Exception
    to raise."""
    calls = {"sqs": [], "get": []}
    pages = iter(receive_pages)

    def _sqs(target, body):
        calls["sqs"].append((target, body))
        return next(pages) if target.endswith("ReceiveMessage") else "{}"

    def _get_object(bucket, key):
        calls["get"].append((bucket, key))
        data = objects[(bucket, key)]
        if isinstance(data, Exception):
            raise data
        return data

    monkeypatch.setattr(c, "_sqs", _sqs)
    monkeypatch.setattr(c, "_get_object", _get_object)
    return calls


def _deleted(calls) -> list:
    """The receipt handles the collector asked SQS to delete."""
    out = []
    for target, body in calls["sqs"]:
        if target.endswith("DeleteMessageBatch"):
            out += [e["ReceiptHandle"] for e in json.loads(body)["Entries"]]
    return out


# --------------------------------------------------------------------------- #
#  SigV4 for REST requests — pinned to AWS's published S3 test vectors         #
# --------------------------------------------------------------------------- #
# From the S3 API docs, "Signature Calculations for the Authorization Header:
# Transferring Payload in a Single Chunk". Same credentials/date for all three;
# only the canonical request differs, which is precisely the part `cloud.py`'s
# POST-to-"/" signer cannot express.
_AK = "AKIAIOSFODNN7EXAMPLE"
_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_AMZ, _DS = "20130524T000000Z", "20130524"
_HOST = "examplebucket.s3.amazonaws.com"
_EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _sig(auth: str) -> str:
    return auth.split("Signature=")[1]


def test_sigv4_rest_headers_matches_aws_published_get_object_vector():
    h = sigv4_rest_headers(_AK, _SK, "us-east-1", "s3", "GET", _HOST,
                           "/test.txt", "", b"", _AMZ, _DS,
                           extra_headers={"range": "bytes=0-9"})
    assert h["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/"
        "s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;"
        "x-amz-date, Signature="
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
    # The empty-payload hash is a REQUIRED signed header for S3, and must also
    # be sent — a signature over a header we omit is rejected at the edge.
    assert h["x-amz-content-sha256"] == _EMPTY_SHA
    assert h["x-amz-date"] == _AMZ


def test_sigv4_rest_headers_signs_the_query_string():
    # "Example: GET Bucket Lifecycle" — proves `query` reaches the canonical
    # request. Drop the `query` element from the join and this fails.
    lifecycle = sigv4_rest_headers(_AK, _SK, "us-east-1", "s3", "GET", _HOST,
                                   "/", "lifecycle=", b"", _AMZ, _DS)
    assert _sig(lifecycle["Authorization"]) == \
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    # "Example: Get Bucket (List Objects)" — two sorted query parameters.
    listing = sigv4_rest_headers(_AK, _SK, "us-east-1", "s3", "GET", _HOST,
                                 "/", "max-keys=2&prefix=J", b"", _AMZ, _DS)
    assert _sig(listing["Authorization"]) == \
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    assert _sig(lifecycle["Authorization"]) != _sig(listing["Authorization"])


def test_sigv4_rest_headers_omits_host_but_signs_it():
    h = sigv4_rest_headers(_AK, _SK, "us-east-1", "s3", "GET", _HOST, "/k", "",
                           b"", _AMZ, _DS)
    assert "host" not in h and "Host" not in h      # urllib derives it from the URL
    assert "SignedHeaders=host;" in h["Authorization"]
    # A different host must change the signature, i.e. it really is signed.
    other = sigv4_rest_headers(_AK, _SK, "us-east-1", "s3", "GET", "other.s3.amazonaws.com",
                               "/k", "", b"", _AMZ, _DS)
    assert _sig(h["Authorization"]) != _sig(other["Authorization"])


def test_sigv4_rest_headers_signs_payload_method_and_session_token():
    body = b'{"QueueUrl":"q"}'
    post = sigv4_rest_headers(_AK, _SK, "us-east-1", "sqs", "POST",
                              "sqs.us-east-1.amazonaws.com", "/", "", body,
                              _AMZ, _DS, extra_headers={"x-amz-target": "T"})
    # payload hash is the body's, not the empty hash
    assert post["x-amz-content-sha256"] == \
        __import__("hashlib").sha256(body).hexdigest() != _EMPTY_SHA
    assert "x-amz-target" in post["Authorization"]  # extra headers are signed
    # Method is part of the canonical request.
    get = sigv4_rest_headers(_AK, _SK, "us-east-1", "sqs", "GET",
                             "sqs.us-east-1.amazonaws.com", "/", "", body,
                             _AMZ, _DS, extra_headers={"x-amz-target": "T"})
    assert _sig(post["Authorization"]) != _sig(get["Authorization"])
    # STS credentials add the security token to the signature AND the headers.
    sts = sigv4_rest_headers(_AK, _SK, "us-east-1", "sqs", "POST",
                             "sqs.us-east-1.amazonaws.com", "/", "", body,
                             _AMZ, _DS, session_token="ST")
    assert sts["x-amz-security-token"] == "ST"
    assert "x-amz-security-token" in sts["Authorization"]


def test_sigv4_rest_headers_is_deterministic():
    args = (_AK, _SK, "us-east-1", "s3", "GET", _HOST, "/test.txt", "", b"", _AMZ, _DS)
    assert sigv4_rest_headers(*args) == sigv4_rest_headers(*args)


# --------------------------------------------------------------------------- #
#  Endpoint / request builders                                                 #
# --------------------------------------------------------------------------- #
def test_endpoint_builders_use_regional_virtual_hosted_style():
    assert sqs_host("eu-west-1") == "sqs.eu-west-1.amazonaws.com"
    assert s3_host("my-trail-bucket", "us-east-2") == \
        "my-trail-bucket.s3.us-east-2.amazonaws.com"
    assert s3_object_url("b", "a/b.json.gz", "us-east-1") == \
        "https://b.s3.us-east-1.amazonaws.com/a/b.json.gz"


def test_s3_canonical_path_encodes_each_segment_once_and_keeps_slashes():
    # Slashes stay separators; the unreserved set is never escaped; everything
    # else is escaped exactly once (double-encoding breaks the signature).
    assert s3_canonical_path(_KEY) == "/" + _KEY
    assert s3_canonical_path("logs/my file.json.gz") == "/logs/my%20file.json.gz"
    assert s3_canonical_path("a/b+c:d.gz") == "/a/b%2Bc%3Ad.gz"
    assert s3_canonical_path("a/-_.~x") == "/a/-_.~x"        # unreserved, untouched
    assert s3_canonical_path("/already-rooted") == "/already-rooted"


def test_sqs_receive_body_clamps_to_the_documented_ranges():
    body = json.loads(sqs_receive_body("https://sqs/q"))
    assert body["QueueUrl"] == "https://sqs/q"
    assert body["MaxNumberOfMessages"] == 10 and body["WaitTimeSeconds"] == 1
    assert body["VisibilityTimeout"] == 300
    over = json.loads(sqs_receive_body("q", max_messages=500, wait_seconds=90,
                                       visibility_timeout=99999))
    assert over["MaxNumberOfMessages"] == 10        # SQS rejects >10
    assert over["WaitTimeSeconds"] == 20            # SQS rejects >20
    assert over["VisibilityTimeout"] == 43200       # SQS rejects >12h
    under = json.loads(sqs_receive_body("q", max_messages=0, wait_seconds=-5))
    assert under["MaxNumberOfMessages"] == 1 and under["WaitTimeSeconds"] == 0


def test_sqs_delete_body_gives_every_entry_a_unique_id():
    body = json.loads(sqs_delete_body("https://sqs/q", ["RH-a", "RH-b"]))
    assert body["QueueUrl"] == "https://sqs/q"
    assert body["Entries"] == [{"Id": "0", "ReceiptHandle": "RH-a"},
                               {"Id": "1", "ReceiptHandle": "RH-b"}]
    assert len({e["Id"] for e in body["Entries"]}) == 2   # SQS rejects duplicate Ids


def test_sqs_messages_unwraps_and_treats_an_empty_queue_as_no_messages():
    assert sqs_messages(_receive(_SNS_BODY)) == [("RH0", _SNS_BODY)]
    assert sqs_messages("{}") == []                 # empty queue: no Messages key
    assert sqs_messages('{"Messages":[]}') == []
    assert sqs_messages("not json") == []
    assert sqs_messages('{"Messages":["oops",{"Body":"b"}]}') == []   # no handle


# --------------------------------------------------------------------------- #
#  Shared step 1: SQS notification -> S3 object keys                           #
# --------------------------------------------------------------------------- #
def test_s3_object_keys_unwraps_the_sns_double_encoding():
    # The whole point: `Message` is a JSON STRING holding the S3 event. Delete
    # the inner-unwrap branch and this returns [].
    assert s3_object_keys(_SNS_BODY) == [("my-trail-bucket", _KEY)]


def test_s3_object_keys_accepts_a_direct_s3_notification():
    # A queue subscribed straight to S3 (no SNS) needs no different code path.
    assert s3_object_keys(_S3_EVENT) == [("my-trail-bucket", _KEY)]


def test_s3_object_keys_url_decodes_the_key():
    # S3 encodes the key in the notification, with '+' for spaces; it must be
    # decoded here because the caller re-encodes it into the signed path.
    # Drop the unquote_plus and the S3 GET is signed for the wrong object.
    body = json.dumps({"Records": [{"s3": {
        "bucket": {"name": "b"},
        "object": {"key": "AWSLogs/my+folder/a%3Ab.json.gz"}}}]})
    assert s3_object_keys(body) == [("b", "AWSLogs/my folder/a:b.json.gz")]


def test_s3_object_keys_returns_nothing_for_the_subscription_test_event():
    # AWS posts this once on subscription; it names no object.
    assert s3_object_keys(_TEST_EVENT_BODY) == []
    assert s3_object_keys(json.dumps({"Type": "Notification",
                                      "Message": _TEST_EVENT_BODY})) == []


def test_s3_object_keys_survives_every_malformed_shape():
    for junk in ("", "not json", "[]", "null", '"a string"', "{}",
                 '{"Records":"not a list"}', '{"Records":[null,3,"x"]}',
                 '{"Records":[{"s3":{}}]}',
                 '{"Records":[{"s3":{"bucket":{},"object":{}}}]}',
                 '{"Records":[{"s3":{"bucket":{"name":""},"object":{"key":"k"}}}]}',
                 '{"Message":"not json either"}', '{"Message":123}'):
        assert s3_object_keys(junk) == [], junk


def test_s3_object_keys_skips_non_create_events_and_folder_markers():
    removed = json.dumps({"Records": [{"eventName": "ObjectRemoved:Delete",
                                       "s3": {"bucket": {"name": "b"},
                                              "object": {"key": "k.gz"}}}]})
    assert s3_object_keys(removed) == []
    folder = json.dumps({"Records": [{"eventName": "ObjectCreated:Put",
                                      "s3": {"bucket": {"name": "b"},
                                             "object": {"key": "AWSLogs/"}}}]})
    assert s3_object_keys(folder) == []
    # ObjectCreated:CompleteMultipartUpload is how large trail files land.
    multi = json.dumps({"Records": [{"eventName": "ObjectCreated:CompleteMultipartUpload",
                                     "s3": {"bucket": {"name": "b"},
                                            "object": {"key": "k.gz"}}}]})
    assert s3_object_keys(multi) == [("b", "k.gz")]


def test_s3_object_keys_returns_every_record_in_one_notification():
    body = json.dumps({"Records": [
        {"s3": {"bucket": {"name": "b1"}, "object": {"key": "k1.gz"}}},
        {"s3": {"bucket": {"name": "b2"}, "object": {"key": "k2.gz"}}}]})
    assert s3_object_keys(body) == [("b1", "k1.gz"), ("b2", "k2.gz")]


# --------------------------------------------------------------------------- #
#  Shared step 2: gzipped object bytes -> records                              #
# --------------------------------------------------------------------------- #
def test_gunzip_text_decompresses_and_passes_plain_bytes_through():
    assert gunzip_text(gzip.compress(b"hello")) == "hello"
    assert gunzip_text(b"hello") == "hello"          # VPC Flow can be uncompressed
    assert gunzip_text(b"") == ""


def test_gunzip_text_survives_a_truncated_or_corrupt_member():
    # A half-written object must not raise out of fetch and wedge the poll.
    blob = gzip.compress(b'{"Records":[]}')
    assert gunzip_text(blob[:len(blob) // 2]) == ""   # truncated
    assert gunzip_text(b"\x1f\x8b" + b"\x00" * 32) == ""  # gzip magic, garbage body


def test_gunzip_text_never_dies_on_undecodable_bytes():
    assert gunzip_text(gzip.compress(b"\xff\xfe ok")) .endswith("ok")


def test_gzip_records_unwraps_the_cloudtrail_records_envelope():
    recs = gzip_records(_TRAIL_OBJECT)
    assert [r["eventName"] for r in recs] == ["GetObject", "PutObject"]


def test_gzip_records_accepts_bare_arrays_and_ndjson():
    assert gzip_records(gzip.compress(b'[{"a":1},{"a":2}]')) == [{"a": 1}, {"a": 2}]
    # WAF writes one JSON object per line with no wrapper. Remove the NDJSON
    # fallback and this returns [].
    nd = gzip.compress(b'{"a":1}\n{"a":2}\n\n')
    assert gzip_records(nd) == [{"a": 1}, {"a": 2}]


def test_gzip_records_ignores_a_cloudtrail_digest_file():
    # Digest files sit in the same bucket and fire the same notification, but
    # carry no "Records" key — they must self-filter, not become junk events.
    digest = gzip.compress(json.dumps({"awsAccountId": "1", "digestStartTime": "x",
                                       "logFiles": [{"s3ObjectKey": "k"}]}).encode())
    assert gzip_records(digest) == []


def test_gzip_records_takes_the_wrapper_key_as_a_parameter():
    blob = gzip.compress(json.dumps({"logEvents": [{"a": 1}]}).encode())
    assert gzip_records(blob) == []                          # default key absent
    assert gzip_records(blob, key="logEvents") == [{"a": 1}]  # reusable per source


def test_gzip_records_survives_junk_and_empty_objects():
    for junk in (b"", gzip.compress(b""), gzip.compress(b"   "),
                 gzip.compress(b"not json at all"), gzip.compress(b"3"),
                 b"\x1f\x8btruncated"):
        assert gzip_records(junk) == [], junk


# --------------------------------------------------------------------------- #
#  Collector identity + configuration gate                                     #
# --------------------------------------------------------------------------- #
def test_cloudtrail_s3_collector_identity_reuses_the_existing_parser():
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    assert c.name == "aws_s3_cloudtrail"        # distinct checkpoint from aws_cloudtrail
    assert c.fmt == "aws_cloudtrail"            # already a registered PARSERS key
    assert isinstance(c, S3SqsCollector)


def test_fetch_output_feeds_the_shipped_cloudtrail_parser_unchanged(monkeypatch):
    """The design claim, pinned: no new parser and no CIM edit.

    The content this collector produces goes through the SAME parser as an
    uploaded CloudTrail file, and the parser emits the vendor/product pair the
    shipped CIM clause `{vendor: [aws], product: [cloudtrail]}` keys on — so the
    events land in the Change model with zero models.yaml work. Change `fmt` or
    reshape `content` and this breaks.
    """
    from app.parsers import aws_cloudtrail          # direct import; no PARSERS needed

    data_event = gzip.compress(json.dumps({"Records": [{
        "eventTime": "2026-06-25T10:00:00Z", "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com", "sourceIPAddress": "203.0.113.9",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
    }]}).encode("utf-8"))

    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    _wire(c, monkeypatch, [_receive(_SNS_BODY), "{}"],
          {("my-trail-bucket", _KEY): data_event})
    res = c.fetch(None)

    events = list(aws_cloudtrail.parse(res.content))
    assert len(events) == 1
    e = events[0]
    assert (e.vendor, e.product) == ("aws", "cloudtrail")   # the CIM membership handle
    assert e.rule_name == "GetObject" and e.user_name == "alice"
    assert e.src_ip == "203.0.113.9"
    # A DATA event — the whole reason for this collector; LookupEvents omits it.
    assert e.log_type == "s3"


def test_s3sqs_collector_configured_requires_region_queue_and_keys():
    ok = ("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    assert AwsS3CloudTrailCollector(*ok).configured()
    assert not AwsS3CloudTrailCollector("", "https://sqs/q", "AK", "SK", "", 24).configured()
    assert not AwsS3CloudTrailCollector("us-east-1", "", "AK", "SK", "", 24).configured()
    assert not AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "", "SK", "", 24).configured()
    assert not AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "", "", 24).configured()
    # session_token is optional — only present on STS credentials.
    assert AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "ST", 24).configured()


# --------------------------------------------------------------------------- #
#  fetch(): the poll                                                           #
# --------------------------------------------------------------------------- #
def test_fetch_reads_the_named_object_and_shapes_it_for_the_parser(monkeypatch):
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(_SNS_BODY), "{}"],
                  {("my-trail-bucket", _KEY): _TRAIL_OBJECT})

    res = c.fetch("2026-06-25T00:00:00Z")

    assert calls["get"] == [("my-trail-bucket", _KEY)]
    assert res.count == 2
    # Exactly what app/parsers/aws_cloudtrail.py already eats.
    assert json.loads(res.content)["Records"][0]["eventName"] == "GetObject"
    assert res.cursor.startswith("2026-06-25T11:30:00")   # advanced to the newest record


def test_fetch_deletes_a_message_only_after_its_records_are_in_hand(monkeypatch):
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(_SNS_BODY), "{}"],
                  {("my-trail-bucket", _KEY): _TRAIL_OBJECT})
    c.fetch(None)

    assert _deleted(calls) == ["RH0"]
    targets = [t for t, _ in calls["sqs"]]
    # The delete is the LAST SQS call, after every receive.
    assert targets[-1].endswith("DeleteMessageBatch")
    assert targets.count("AmazonSQS.DeleteMessageBatch") == 1


def test_fetch_on_an_empty_queue_ingests_nothing_and_keeps_the_cursor(monkeypatch):
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, ["{}"], {})

    res = c.fetch("2026-06-25T00:00:00Z")

    # "" (not "[]" / '{"Records":[]}') is the no-op signal run_collector gates on;
    # anything else re-ingests an identical body every idle poll.
    assert res.content == "" and res.count == 0
    # A None cursor here would write SQL NULL and destroy the checkpoint.
    assert res.cursor == "2026-06-25T00:00:00Z"
    assert calls["get"] == [] and _deleted(calls) == []
    assert len(calls["sqs"]) == 1                    # stopped on the empty page


def test_fetch_with_no_cursor_still_returns_a_non_null_checkpoint(monkeypatch):
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    _wire(c, monkeypatch, ["{}"], {})
    res = c.fetch(None)
    assert res.cursor and res.cursor.endswith("Z")    # iso_lookback, never None


def test_fetch_leaves_the_message_queued_when_the_object_is_gone(monkeypatch):
    # A lifecycle-expired / deleted object must be survivable, not an exception,
    # and must NOT be acknowledged — SQS redelivery and redrive own the retry.
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(_SNS_BODY), "{}"],
                  {("my-trail-bucket", _KEY): OSError("HTTP Error 404: Not Found")})

    res = c.fetch("2026-06-25T00:00:00Z")

    assert res.content == "" and res.count == 0
    assert res.cursor == "2026-06-25T00:00:00Z"      # no progress, no cursor move
    assert _deleted(calls) == []                     # unacknowledged
    assert calls["get"] == [("my-trail-bucket", _KEY)]


def test_fetch_still_returns_the_readable_objects_of_a_partly_broken_batch(monkeypatch):
    good = json.dumps({"Records": [{"eventName": "ObjectCreated:Put",
                                    "s3": {"bucket": {"name": "b"},
                                           "object": {"key": "good.gz"}}}]})
    bad = json.dumps({"Records": [{"eventName": "ObjectCreated:Put",
                                   "s3": {"bucket": {"name": "b"},
                                          "object": {"key": "gone.gz"}}}]})
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(good, bad), "{}"],
                  {("b", "good.gz"): _TRAIL_OBJECT,
                   ("b", "gone.gz"): OSError("404")})

    res = c.fetch(None)

    assert res.count == 2                            # the readable object survived
    assert _deleted(calls) == ["RH0"]                # only the message we finished


def test_fetch_consumes_the_subscription_test_event_without_touching_s3(monkeypatch):
    # s3:TestEvent names no object. It must be deleted, or it is redelivered
    # forever. Initialise `complete = False` in fetch and this fails.
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(_TEST_EVENT_BODY), "{}"], {})

    res = c.fetch("2026-06-25T00:00:00Z")

    assert calls["get"] == []                        # no S3 call at all
    assert _deleted(calls) == ["RH0"]                # consumed, not redelivered
    assert res.content == "" and res.count == 0


def test_fetch_consumes_an_unparseable_message_instead_of_poisoning_the_queue(monkeypatch):
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive("<<not json>>"), "{}"], {})
    c.fetch(None)
    assert calls["get"] == [] and _deleted(calls) == ["RH0"]


def test_fetch_drains_multiple_batches_until_the_queue_is_empty(monkeypatch):
    a = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                        "object": {"key": "a.gz"}}}]})
    b = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                        "object": {"key": "b.gz"}}}]})
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    # Exhaustible: a fourth ReceiveMessage would raise StopIteration.
    calls = _wire(c, monkeypatch, [_receive(a), _receive(b), "{}"],
                  {("b", "a.gz"): _TRAIL_OBJECT, ("b", "b.gz"): _TRAIL_OBJECT})

    res = c.fetch(None)

    assert calls["get"] == [("b", "a.gz"), ("b", "b.gz")]
    assert res.count == 4                            # 2 records from each object
    assert sorted(_deleted(calls)) == ["RH0", "RH0"]  # both batches acknowledged


def test_fetch_stops_at_the_per_poll_object_budget(monkeypatch):
    # The scheduler runs collectors serially on one thread with a 30s timeout
    # per request, so an unbounded backlog must not hold the loop.
    monkeypatch.setattr(aws_s3, "_MAX_OBJECTS", 1)
    a = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                        "object": {"key": "a.gz"}}}]})
    b = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                        "object": {"key": "b.gz"}}}]})
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(a, b)],
                  {("b", "a.gz"): _TRAIL_OBJECT, ("b", "b.gz"): _TRAIL_OBJECT})

    res = c.fetch(None)

    assert calls["get"] == [("b", "a.gz")]           # second object left for later
    assert res.count == 2
    assert _deleted(calls) == ["RH0"]                # only the finished message


def test_fetch_lets_an_sqs_error_propagate_to_the_runner(monkeypatch):
    # run_collector must see the exception: it is the only thing stopping the
    # checkpoint from advancing past unread data. Never swallow it in fetch.
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)

    def _boom(target, body):
        raise OSError("HTTP Error 403: Forbidden")

    monkeypatch.setattr(c, "_sqs", _boom)
    try:
        c.fetch(None)
    except OSError as exc:
        assert "403" in str(exc)
    else:
        raise AssertionError("fetch swallowed an SQS failure")


def test_fetch_batches_deletes_at_the_sqs_ten_entry_maximum(monkeypatch):
    bodies = [json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                              "object": {"key": f"k{i}.gz"}}}]})
              for i in range(12)]
    c = AwsS3CloudTrailCollector("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    calls = _wire(c, monkeypatch, [_receive(*bodies), "{}"],
                  {("b", f"k{i}.gz"): _TRAIL_OBJECT for i in range(12)})

    c.fetch(None)

    batches = [json.loads(body) for target, body in calls["sqs"]
               if target.endswith("DeleteMessageBatch")]
    assert [len(bt["Entries"]) for bt in batches] == [10, 2]   # SQS rejects >10
    assert len(_deleted(calls)) == 12


# --------------------------------------------------------------------------- #
#  Subclass hooks — the transport other AWS sources reuse                      #
# --------------------------------------------------------------------------- #
def test_subclass_hooks_reshape_records_without_touching_the_transport(monkeypatch):
    class _FlowLike(S3SqsCollector):
        name, fmt, label = "aws_s3_flow", "generic_json", "flow-like"
        cursor_field = "ts"

        def records_from_object(self, bucket, key, data):
            return [{"line": ln, "ts": "2026-06-25T09:00:00Z"}
                    for ln in gunzip_text(data).splitlines() if ln]

        def shape_content(self, records):
            return "\n".join(r["line"] for r in records)

    c = _FlowLike("us-east-1", "https://sqs/q", "AK", "SK", "", 24)
    body = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"},
                                           "object": {"key": "flow.gz"}}}]})
    calls = _wire(c, monkeypatch, [_receive(body), "{}"],
                  {("b", "flow.gz"): gzip.compress(b"2 acc eni ACCEPT\n2 acc eni REJECT\n")})

    res = c.fetch(None)

    assert res.content == "2 acc eni ACCEPT\n2 acc eni REJECT"
    assert res.count == 2 and res.cursor.startswith("2026-06-25T09:00:00")
    assert _deleted(calls) == ["RH0"]                # transport unchanged

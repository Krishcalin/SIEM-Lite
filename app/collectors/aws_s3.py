# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""AWS S3 + SQS log transport — CloudTrail at full fidelity.

``cloud.py:AwsCloudTrailCollector`` pulls the ``LookupEvents`` API, which is
convenient but lossy: it is aggressively throttled, returns management events
only, and never shows a DATA event (S3 object reads, Lambda invokes) — exactly
the records an investigation needs. The supported high-fidelity path is the
delivery pipeline AWS itself writes:

    CloudTrail -> S3 (gzipped ``{"Records": [...]}`` objects)
               -> S3 event notification -> SNS -> SQS

This collector consumes the tail of that pipeline: poll SQS for
object-created notifications, GET each named object out of S3, gunzip it and
unwrap ``{"Records": [...]}`` so the *existing* ``aws_cloudtrail`` parser
handles the result unchanged. No new parser and no CIM change: the events are
byte-identical to an uploaded CloudTrail file, so they land in the same models.

Two encodings make this fiddly, and both are handled by pure functions here:

  * S3 -> SNS -> SQS is DOUBLE-ENCODED. The SQS message ``Body`` is an SNS
    notification whose ``Message`` field is the S3 event as a JSON *string*.
  * The object key inside the notification is URL-encoded (spaces as ``+``),
    so it must be decoded before it is re-encoded into the request path.

THIS MODULE IS SHARED TRANSPORT. VPC Flow Logs and WAF logs arrive over the
same S3+SQS pipeline and differ only in how one object's bytes become records,
so the two steps are separate exported pure functions —
``s3_object_keys`` (notification -> object keys) and ``gzip_records``
(object bytes -> records) — and ``S3SqsCollector`` exposes them as the
``records_from_object`` / ``shape_content`` hooks. A new AWS source subclasses
it and overrides those two methods; the SQS plumbing is inherited.

SIGNING: ``cloud.py:sigv4_headers`` is hard-wired to an ``x-amz-json-1.1`` POST
to ``/`` and cannot sign ``GET /some/object/key``, so ``sigv4_rest_headers``
below builds the canonical request for an arbitrary method/path/query. The
signing-key derivation itself is NOT re-derived — it is ``cloud._signing_key``,
imported. The result is pinned to AWS's three published S3 test vectors in the
tests.

DELIVERY: a message is deleted from SQS only once every object it names has
been read and its records are in hand; a message whose object could not be read
is left queued, so SQS redelivery (and ultimately the queue's redrive policy)
governs the retry. Ingest happens after ``fetch`` returns, so an ingest failure
can still lose an already-deleted batch — the records remain in S3, and the
event-level dedup makes a replay cheap.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import urllib.request
import zlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote, unquote_plus

from ..util import read_capped
from .base import Collector, FetchResult, iso_lookback, max_time_iso
from .cloud import _signing_key

log = logging.getLogger("logocean")

# --- one-poll budgets (the scheduler runs collectors serially on one thread) --
_MAX_BATCHES = 10                    # ReceiveMessage calls per poll
_MAX_MESSAGES = 10                   # messages per call (SQS hard maximum)
_MAX_OBJECTS = 50                    # S3 GETs per poll
_DELETE_BATCH = 10                   # entries per DeleteMessageBatch (SQS maximum)
_WAIT_SECONDS = 1                    # short long-poll; a 20s wait would stall the loop
_VISIBILITY_TIMEOUT = 300            # a message we fail to delete returns after this
_MAX_OBJECT_BYTES = 64 * 1024 * 1024

# SQS speaks the AWS JSON protocol: POST to "/" with the operation in x-amz-target.
_SQS_CONTENT_TYPE = "application/x-amz-json-1.0"
_SQS_RECEIVE = "AmazonSQS.ReceiveMessage"
_SQS_DELETE = "AmazonSQS.DeleteMessageBatch"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _loads(text: str):
    """json.loads that yields None instead of raising — every input here is
    attacker-adjacent vendor text and a bad message must never kill a poll."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


# =========================================================================== #
#  SigV4 for REST-style requests (arbitrary method / path / query)            #
# =========================================================================== #
def sigv4_rest_headers(access_key: str, secret_key: str, region: str, service: str,
                       method: str, host: str, path: str, query: str, payload: bytes,
                       amz_date: str, datestamp: str,
                       extra_headers: Optional[dict] = None,
                       session_token: str = "") -> dict:
    """Sign an arbitrary AWS REST request; returns the headers to send.

    ``cloud.sigv4_headers`` covers only an ``x-amz-json-1.1`` POST to ``/``.
    This is the same algorithm with the canonical request generalized over
    method, path and query string, which is what S3 (``GET /key``) needs. The
    HMAC-chained signing key is reused from ``cloud`` rather than re-derived.

    ``path`` must already be URI-encoded (see ``s3_canonical_path``) and
    ``query`` must already be canonical (sorted ``k=v`` pairs, ``&``-joined).
    Pure: both timestamps are arguments, so it is deterministic and unit-tested
    against AWS's published S3 vectors. ``host`` is signed but omitted from the
    result because urllib derives it from the URL."""
    payload_hash = hashlib.sha256(payload or b"").hexdigest()
    signed = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    for key, value in (extra_headers or {}).items():
        signed[key.lower()] = str(value).strip()
    if session_token:
        signed["x-amz-security-token"] = session_token

    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    canonical_request = "\n".join(
        [method, path, query, canonical_headers, signed_headers, payload_hash])

    algorithm = "AWS4-HMAC-SHA256"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [algorithm, amz_date, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    signature = hmac.new(_signing_key(secret_key, datestamp, region, service),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {k: v for k, v in signed.items() if k != "host"}
    out["Authorization"] = (f"{algorithm} Credential={access_key}/{scope}, "
                            f"SignedHeaders={signed_headers}, Signature={signature}")
    return out


# =========================================================================== #
#  Endpoint / request builders (pure)                                         #
# =========================================================================== #
def sqs_host(region: str) -> str:
    return f"sqs.{region}.amazonaws.com"


def s3_host(bucket: str, region: str) -> str:
    """Virtual-hosted-style S3 endpoint. The regional form is used even for
    us-east-1, where the legacy global endpoint would also work."""
    return f"{bucket}.s3.{region}.amazonaws.com"


def s3_canonical_path(key: str) -> str:
    """An object key as a signed request path.

    S3 URI-encodes each path segment ONCE and keeps ``/`` as the separator, so
    ``quote(key, safe="/")`` is exactly right: Python never escapes the
    unreserved set ``A-Za-z0-9-._~`` and we exempt the slash."""
    return "/" + quote(key.lstrip("/"), safe="/")


def s3_object_url(bucket: str, key: str, region: str) -> str:
    return f"https://{s3_host(bucket, region)}{s3_canonical_path(key)}"


def sqs_receive_body(queue_url: str, max_messages: int = _MAX_MESSAGES,
                     wait_seconds: int = _WAIT_SECONDS,
                     visibility_timeout: int = _VISIBILITY_TIMEOUT) -> str:
    """ReceiveMessage payload. Counts are clamped to the SQS-documented ranges
    so a mis-set config cannot produce a request the API rejects outright."""
    return json.dumps({
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max(1, min(int(max_messages), 10)),
        "WaitTimeSeconds": max(0, min(int(wait_seconds), 20)),
        "VisibilityTimeout": max(0, min(int(visibility_timeout), 43200)),
    })


def sqs_delete_body(queue_url: str, handles: list) -> str:
    """DeleteMessageBatch payload; ``Id`` only has to be unique within the batch."""
    return json.dumps({
        "QueueUrl": queue_url,
        "Entries": [{"Id": str(i), "ReceiptHandle": h} for i, h in enumerate(handles)],
    })


def sqs_messages(body: str) -> list[tuple[str, str]]:
    """Unwrap a ReceiveMessage response -> [(receipt_handle, message_body)].

    An empty queue answers ``{}`` with no ``Messages`` key at all, which is the
    normal steady state, so it yields [] rather than an error."""
    obj = _loads(body)
    if not isinstance(obj, dict):
        return []
    out: list[tuple[str, str]] = []
    for msg in obj.get("Messages") or []:
        if not isinstance(msg, dict):
            continue
        handle, payload = msg.get("ReceiptHandle"), msg.get("Body")
        if isinstance(handle, str) and handle and isinstance(payload, str):
            out.append((handle, payload))
    return out


# =========================================================================== #
#  Shared transport step 1: SQS notification -> S3 object keys                 #
# =========================================================================== #
def s3_object_keys(message_body: str) -> list[tuple[str, str]]:
    """Extract the ``(bucket, key)`` pairs one SQS message points at.

    Handles the S3 -> SNS -> SQS double encoding: when the body is an SNS
    envelope, the S3 event is a JSON *string* under ``Message`` and has to be
    parsed a second time. A body that is already a bare S3 notification works
    too, so a queue subscribed directly to S3 needs no different code path.

    Returns [] — never raises — for the three benign cases that would otherwise
    wedge the queue:
      * ``s3:TestEvent``, which AWS posts once when the notification is created;
      * a non-create event (``ObjectRemoved:*``) that names nothing to read;
      * anything unparseable, truncated, or shaped unexpectedly.

    The key is URL-decoded here (S3 encodes it, with ``+`` for spaces) because
    the caller re-encodes it into the request path."""
    obj = _loads(message_body)
    if not isinstance(obj, dict):
        return []

    inner = obj.get("Message")
    if isinstance(inner, str):                     # SNS envelope -> unwrap once
        obj = _loads(inner)
        if not isinstance(obj, dict):
            return []

    # Belt-and-braces: a TestEvent also carries no "Records", so the loop below
    # would return [] anyway. Named explicitly because it is the one message an
    # operator WILL see on day one and would otherwise look like a parse failure.
    if obj.get("Event") == "s3:TestEvent":
        return []

    out: list[tuple[str, str]] = []
    for rec in obj.get("Records") or []:
        if not isinstance(rec, dict):
            continue
        name = rec.get("eventName")
        if isinstance(name, str) and not name.startswith("ObjectCreated"):
            continue
        s3 = rec.get("s3")
        if not isinstance(s3, dict):
            continue
        bucket = s3.get("bucket") if isinstance(s3.get("bucket"), dict) else {}
        target = s3.get("object") if isinstance(s3.get("object"), dict) else {}
        name_, key = bucket.get("name"), target.get("key")
        if not isinstance(name_, str) or not isinstance(key, str) or not name_ or not key:
            continue
        key = unquote_plus(key)
        if key.endswith("/"):                      # console-created folder marker
            continue
        out.append((name_, key))
    return out


# =========================================================================== #
#  Shared transport step 2: gzipped object bytes -> records                    #
# =========================================================================== #
def gunzip_text(data: bytes) -> str:
    """Decompress a gzipped S3 object to text; pass plain bytes through.

    Returns "" for a corrupt or truncated member instead of raising: a corrupt
    object never becomes readable, so the poll should drop it rather than fail
    forever on the same notification. Decoding is lossy (``errors="replace"``)
    for the same reason.

    Exported because VPC Flow Logs are gzipped *plain text*, not JSON — that
    collector needs this step without ``gzip_records``' JSON handling."""
    if not data:
        return ""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError, zlib.error) as exc:
            log.warning("aws_s3: undecompressable object (%s)", exc)
            return ""
    return data.decode("utf-8", "replace")


def gzip_records(data: bytes, key: str = "Records") -> list:
    """One gzipped S3 object -> a list of records.

    Accepts the three shapes AWS writes to S3: a wrapper object
    (``{"Records": [...]}`` — CloudTrail), a bare JSON array, and NDJSON (one
    object per line — WAF, and CloudTrail Lake exports).

    Returns [] for anything else, which deliberately includes a CloudTrail
    *digest* file: those sit in the same bucket, are delivered by the same
    notification, and carry no ``Records`` key, so they self-filter."""
    text = gunzip_text(data).strip()
    if not text:
        return []
    obj = _loads(text)
    if obj is None:                                # not one JSON doc -> try NDJSON
        return [rec for rec in (_loads(line) for line in text.splitlines() if line.strip())
                if isinstance(rec, dict)]
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        value = obj.get(key)
        return value if isinstance(value, list) else []
    return []


# =========================================================================== #
#  Collector                                                                   #
# =========================================================================== #
class S3SqsCollector(Collector):
    """Reusable SQS-notified S3 transport.

    Subclass it for any AWS source delivered to S3 and announced over SQS, and
    override the two hooks that differ per source:
      * ``records_from_object(bucket, key, data)`` — object bytes -> records
      * ``shape_content(records)``                 — records -> parser input
    plus ``cursor_field``, the record key holding the event timestamp."""

    cursor_field = "eventTime"

    def __init__(self, region: str, queue_url: str, access_key: str,
                 secret_key: str, session_token: str, lookback_hours: int):
        self.region = region
        self.queue_url = queue_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.lookback = lookback_hours

    def configured(self) -> bool:
        # session_token is optional (only set when running on STS credentials).
        return bool(self.region and self.queue_url
                    and self.access_key and self.secret_key)

    # -- per-source hooks ---------------------------------------------------- #
    def records_from_object(self, bucket: str, key: str, data: bytes) -> list:
        return gzip_records(data)

    def shape_content(self, records: list) -> str:
        return json.dumps({"Records": records})

    # -- network (thin; patched wholesale in tests) -------------------------- #
    def _http_get_bytes(self, url: str, headers: dict) -> bytes:
        """The one binary network call in the package.

        ``Collector._http_get`` decodes utf-8 with ``errors="replace"``, which
        would silently corrupt a gzip member, so S3 objects are read as bytes.
        Kept as thin as the base methods so a test can patch just this."""
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 — configured URL
            return read_capped(resp, _MAX_OBJECT_BYTES)

    def _sqs(self, target: str, body: str) -> str:
        now = _now()
        host = sqs_host(self.region)
        headers = sigv4_rest_headers(
            self.access_key, self.secret_key, self.region, "sqs",
            "POST", host, "/", "", body.encode("utf-8"),
            now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"),
            extra_headers={"content-type": _SQS_CONTENT_TYPE, "x-amz-target": target},
            session_token=self.session_token)
        return self._http_post(f"https://{host}/", headers, body.encode("utf-8"))

    def _get_object(self, bucket: str, key: str) -> bytes:
        now = _now()
        host = s3_host(bucket, self.region)
        path = s3_canonical_path(key)
        headers = sigv4_rest_headers(
            self.access_key, self.secret_key, self.region, "s3",
            "GET", host, path, "", b"",
            now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"),
            session_token=self.session_token)
        return self._http_get_bytes(f"https://{host}{path}", headers)

    def _delete(self, handles: list) -> None:
        for i in range(0, len(handles), _DELETE_BATCH):
            self._sqs(_SQS_DELETE,
                      sqs_delete_body(self.queue_url, handles[i:i + _DELETE_BATCH]))

    # -- the poll ------------------------------------------------------------ #
    def fetch(self, cursor: Optional[str]) -> FetchResult:
        """Drain up to one poll's worth of notifications.

        A message is queued for deletion only once every object it names has
        been read; if any read failed, or the per-poll object budget cut it
        short, the message is left in SQS so redelivery retries it. Records
        already read from a partially-processed message are still returned —
        at-least-once, with the events table's dedup absorbing the overlap.

        Errors from SQS itself are NOT caught: `run_collector` must see them so
        it records the failure and leaves the checkpoint alone."""
        since = cursor or iso_lookback(self.lookback)
        records: list = []
        done: list[str] = []
        objects = 0

        for _ in range(_MAX_BATCHES):
            messages = sqs_messages(
                self._sqs(_SQS_RECEIVE, sqs_receive_body(self.queue_url)))
            if not messages:
                break                              # empty queue: the steady state
            for handle, body in messages:
                complete = True
                for bucket, key in s3_object_keys(body):
                    if objects >= _MAX_OBJECTS:
                        complete = False           # over budget; retry next poll
                        break
                    objects += 1
                    try:
                        data = self._get_object(bucket, key)
                    except Exception as exc:       # noqa: BLE001 — one bad object
                        # Deleted, lifecycle-expired, or denied. Survivable: keep
                        # the message queued and let SQS redrive decide its fate.
                        log.warning("aws_s3: cannot read s3://%s/%s (%s)",
                                    bucket, key, exc)
                        complete = False
                        continue
                    records.extend(self.records_from_object(bucket, key, data))
                if complete:
                    # Nothing to read (TestEvent / non-create / junk) counts as
                    # complete: it will never become readable, so consume it.
                    done.append(handle)
            if objects >= _MAX_OBJECTS:
                break

        if done:
            self._delete(done)                     # only after the records are in hand
        content = self.shape_content(records) if records else ""
        return FetchResult(content, max_time_iso(records, self.cursor_field, since),
                           len(records))


class AwsS3CloudTrailCollector(S3SqsCollector):
    """CloudTrail delivered to S3 — management AND data events.

    Reuses the ``aws_cloudtrail`` parser and therefore the CloudTrail CIM
    membership unchanged: the content this produces is the same
    ``{"Records": [...]}`` document an operator would upload by hand."""

    name, fmt, label = ("aws_s3_cloudtrail", "aws_cloudtrail",
                        "AWS CloudTrail (S3 + SQS)")

# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""CrowdStrike Falcon collectors — FDR, Event Streams, Incidents.

Three separate onboarding paths, all feeding the existing ``crowdstrike_json``
parser so pulled records get the same parse -> CIM -> detect -> alert treatment
as an upload:

  * **FDR** (Falcon Data Replicator) — CrowdStrike drops gzip-NDJSON objects in an
    S3 bucket and posts a notification naming them on an SQS queue. We long-poll
    SQS, download + gunzip each object, and hand back the NDJSON.
  * **Event Streams** — OAuth2 against the Falcon API, discover the datafeed URL,
    read a *bounded* batch off the firehose, resume from the offset next poll.
  * **Incidents** — the Incidents API (query ids -> fetch entities), reshaped so a
    Falcon incident keeps ``incident_id``/``cid``/``state`` as scalars in ``raw``
    for a later LogOcean case import.

As everywhere in this package, every URL builder, request signer, body builder and
response unwrapper is a module-level pure function that a unit test calls with a
fixture string; the network calls are the few thin ``_sqs`` / ``_s3_get`` /
``_read_stream`` methods. No SDK, no new dependency — gzip and urllib are stdlib.

WHY THIS FILE SIGNS ITS OWN SIGV4
---------------------------------
``cloud.py:sigv4_headers`` is hard-wired to an ``x-amz-json-1.1`` POST to path
``/``: its canonical request is literally ``POST\\n/\\n\\n...``. It cannot sign the
S3 ``GET /<key>`` (non-root path) and it cannot sign SQS's JSON protocol (which
wants ``x-amz-json-1.0``). So the *canonical request* is rebuilt here for a general
method/path/query/header set, while the parts that were already verified against
AWS — ``_signing_key`` and ``_hmac`` — are imported and reused rather than
re-derived. ``sigv4_authorization`` is pinned to two AWS-published test vectors in
``tests/test_collectors_crowdstrike.py``.

FDR CURSOR — WHY IT HOLDS RECEIPT HANDLES
-----------------------------------------
SQS, not our ``collectors.cursor`` column, is the durable queue: an un-deleted
message reappears when its visibility timeout expires. So the cursor stores the
receipt handles of the batch just handed back, and the NEXT ``fetch`` deletes them
before receiving anything new.

That ordering is the crash-safety argument. ``run_collector`` persists the cursor
*only after a successful ingest* (runner.py:129-138 — both failure paths return
without passing ``cursor=``). So a handle can only ever reach us inside a cursor if
the batch it belongs to was ingested. If the fetch raised, the ingest raised, or
the process died in between, the handles are never recorded, the visibility timeout
lapses and SQS redelivers. Deleting on receipt instead would lose a whole batch to
one ingest error; deleting inside ``fetch`` after building the result would lose it
to a crash between fetch and ingest. Deferring the ack to the next poll is the only
placement the Collector contract allows that never acknowledges unread data.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import (parse_qsl, quote, unquote_plus, urlencode, urlsplit,
                          urlunsplit)

from ..util import first, parse_ts, read_capped
from .base import Collector, FetchResult, iso_lookback, max_time_iso
# Reuse the SigV4 key derivation that is already pinned to an AWS vector in
# tests/test_collectors.py rather than re-deriving it; only the canonical request
# (which is request-shape specific) is rebuilt below.
from .cloud import _signing_key

log = logging.getLogger("logocean")

_ALGORITHM = "AWS4-HMAC-SHA256"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# Bounds for one poll. The scheduler is serial on a single threadpool thread
# (runner.py:174-181) with no per-collector timeout, so every loop here is capped.
_MAX_PAGES = 20            # Incidents: id-query pages per poll
_INCIDENT_PAGE = 100       # ids per query page == ids per detail POST
_MAX_MESSAGES = 10         # SQS ReceiveMessage cap (AWS maximum)
_MAX_OBJECTS = 50          # S3 objects downloaded per poll
_SQS_DELETE_BATCH = 10     # DeleteMessageBatch cap (AWS maximum)
_MAX_FEEDS = 4             # datafeed partitions drained per poll
_STREAM_SECONDS = 10       # wall-clock budget per partition per poll
_STREAM_MAX_BYTES = 16 * 1024 * 1024
_STREAM_READ_TIMEOUT = 10  # socket timeout on the firehose read
_MAX_OBJECT_BYTES = 256 * 1024 * 1024   # cap on one decompressed-from S3 object

_SQS_JSON_CONTENT_TYPE = "application/x-amz-json-1.0"
_DEFAULT_API = "https://api.crowdstrike.com"
_TOKEN_SKEW = 60           # refresh a Falcon token this long before it expires


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _monotonic() -> float:
    return time.monotonic()


# =========================================================================== #
#  General SigV4 (any method / path / query / header set)                     #
# =========================================================================== #
def canonical_query(params: dict) -> str:
    """RFC3986-encoded, key-sorted canonical query string ('' when empty)."""
    items = sorted((quote(str(k), safe="-_.~"), quote(str(v), safe="-_.~"))
                   for k, v in (params or {}).items())
    return "&".join(f"{k}={v}" for k, v in items)


def canonical_request(method: str, uri_path: str, query: str, headers: dict,
                      payload_hash: str) -> str:
    """The SigV4 canonical request.

    Header names are lower-cased and values whitespace-collapsed, which is what
    the AWS ``get-header-value-trim`` vector requires. ``uri_path`` is used as
    given: S3 keys are single-encoded by the caller (``s3_canonical_path``)."""
    signed = {str(k).lower(): " ".join(str(v).split()) for k, v in headers.items()}
    names = ";".join(sorted(signed))
    rendered = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    return "\n".join([method.upper(), uri_path or "/", query, rendered, names,
                      payload_hash])


def sigv4_authorization(*, access_key: str, secret_key: str, region: str,
                        service: str, method: str, uri_path: str, query: str,
                        headers: dict, payload_hash: str, amz_date: str,
                        datestamp: str) -> str:
    """The ``Authorization`` header value for a signed request.

    Pure: the two timestamps are arguments, so it is deterministic and pinned to
    AWS-published test vectors in the unit tests."""
    creq = canonical_request(method, uri_path, query, headers, payload_hash)
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    sts = "\n".join([_ALGORITHM, amz_date, scope,
                     hashlib.sha256(creq.encode("utf-8")).hexdigest()])
    signature = hmac.new(_signing_key(secret_key, datestamp, region, service),
                         sts.encode("utf-8"), hashlib.sha256).hexdigest()
    names = ";".join(sorted(str(k).lower() for k in headers))
    return (f"{_ALGORITHM} Credential={access_key}/{scope}, "
            f"SignedHeaders={names}, Signature={signature}")


def sigv4_signed_headers(*, access_key: str, secret_key: str, region: str,
                         service: str, method: str, host: str, uri_path: str,
                         params: Optional[dict], payload: bytes, amz_date: str,
                         datestamp: str, session_token: str = "",
                         extra_headers: Optional[dict] = None) -> dict:
    """Request headers for a SigV4-signed call, ``Authorization`` included.

    ``host`` is signed but not returned — urllib derives ``Host`` from the URL and
    a duplicate that disagreed would break the signature."""
    signed = {"host": host, "x-amz-date": amz_date}
    if session_token:
        signed["x-amz-security-token"] = session_token
    for k, v in (extra_headers or {}).items():
        signed[str(k).lower()] = v
    authorization = sigv4_authorization(
        access_key=access_key, secret_key=secret_key, region=region,
        service=service, method=method, uri_path=uri_path,
        query=canonical_query(params or {}), headers=signed,
        payload_hash=hashlib.sha256(payload or b"").hexdigest(),
        amz_date=amz_date, datestamp=datestamp)
    out = {k: str(v) for k, v in signed.items() if k != "host"}
    out["authorization"] = authorization
    return out


# =========================================================================== #
#  FDR — SQS notifications + gzip-NDJSON objects in S3                        #
# =========================================================================== #
def sqs_host(region: str) -> str:
    return f"sqs.{region}.amazonaws.com"


def s3_host(bucket: str, region: str) -> str:
    """Virtual-hosted-style regional endpoint (valid in every region, us-east-1
    included, so there is only one code path to sign)."""
    return f"{bucket}.s3.{region}.amazonaws.com"


def s3_canonical_path(key: str) -> str:
    """``/`` + the single-encoded object key. S3 does not double-encode, and
    ``quote`` leaves the RFC3986 unreserved set (``-_.~``) alone."""
    return "/" + quote(str(key).lstrip("/"), safe="/")


def sqs_receive_body(queue_url: str, max_messages: int = _MAX_MESSAGES,
                     wait_seconds: int = 20, visibility_timeout: int = 900) -> str:
    """``AmazonSQS.ReceiveMessage`` payload (SQS JSON protocol).

    ``wait_seconds`` is the long poll and is clamped below the 30s urllib timeout
    on ``_http_post``; ``visibility_timeout`` must outlive one scheduler interval
    so the deferred ack on the next poll still holds a valid receipt handle."""
    return json.dumps({
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max(1, min(int(max_messages), _MAX_MESSAGES)),
        "WaitTimeSeconds": max(0, min(int(wait_seconds), 20)),
        "VisibilityTimeout": max(30, int(visibility_timeout)),
    })


def sqs_delete_batch_body(queue_url: str, handles: list) -> str:
    entries = [{"Id": str(i), "ReceiptHandle": h} for i, h in enumerate(handles)]
    return json.dumps({"QueueUrl": queue_url, "Entries": entries})


def sqs_messages(body: str) -> list[dict]:
    """Unwrap a ReceiveMessage response into ``[{"handle": str, "body": dict|None}]``.

    An SQS message ``Body`` is a JSON *string*; it is parsed here so the caller
    never has to. A message whose body is unparseable still comes back (with
    ``body=None``) so it gets acked rather than redelivered forever."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(obj, dict):
        return []
    out: list[dict] = []
    for m in obj.get("Messages") or []:
        if not isinstance(m, dict):
            continue
        handle = m.get("ReceiptHandle")
        if not isinstance(handle, str) or not handle:
            continue
        payload: Optional[dict] = None
        raw_body = m.get("Body")
        if isinstance(raw_body, str):
            try:
                parsed = json.loads(raw_body)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if isinstance(parsed, dict):
                payload = parsed
        elif isinstance(raw_body, dict):
            payload = raw_body
        out.append({"handle": handle, "body": payload})
    return out


def fdr_file_refs(notification: Any, default_bucket: str = "") -> list[tuple[str, str]]:
    """``(bucket, key)`` pairs named by one FDR notification.

    Accepts the FDR shape — ``{"bucket": ..., "files": [{"path": ...}]}`` — and a
    plain S3 event notification, whose keys are URL-encoded on the wire."""
    if not isinstance(notification, dict):
        return []
    out: list[tuple[str, str]] = []
    bucket = notification.get("bucket") or default_bucket
    files = notification.get("files")
    if isinstance(files, list):
        for f in files:
            if isinstance(f, dict):
                path = first(f.get("path"), f.get("key"))
            elif isinstance(f, str):
                path = f
            else:
                path = None
            if isinstance(path, str) and path and bucket:
                out.append((str(bucket), path))
    for rec in notification.get("Records") or []:
        if not isinstance(rec, dict):
            continue
        s3 = rec.get("s3")
        if not isinstance(s3, dict):
            continue
        b = s3.get("bucket") if isinstance(s3.get("bucket"), dict) else {}
        o = s3.get("object") if isinstance(s3.get("object"), dict) else {}
        name, key = b.get("name"), o.get("key")
        if isinstance(name, str) and name and isinstance(key, str) and key:
            out.append((name, unquote_plus(key)))
    return out


def gunzip_ndjson(data: bytes) -> list[str]:
    """Decompress one FDR object into its non-blank NDJSON lines.

    Plain (already-decompressed) NDJSON is accepted too. A *corrupt* gzip stream
    deliberately RAISES: the fetch fails, the message is never acked, and SQS
    redelivers it — swallowing it would ack an object we never read."""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    text = data.decode("utf-8", "replace")
    return [ln for ln in (line.strip() for line in text.splitlines()) if ln]


def fdr_cursor(handles: list) -> str:
    """The checkpoint: receipt handles to ack at the start of the next poll."""
    return json.dumps({"ack": [str(h) for h in handles]})


def fdr_pending_handles(cursor: Optional[str]) -> list[str]:
    """Handles owed an ack, from a stored cursor. Tolerant: an absent, empty or
    unparseable cursor simply means nothing is pending."""
    if not cursor:
        return []
    try:
        obj = json.loads(cursor)
    except (json.JSONDecodeError, ValueError):
        return []
    acks = obj.get("ack") if isinstance(obj, dict) else None
    if not isinstance(acks, list):
        return []
    return [h for h in acks if isinstance(h, str) and h]


class CrowdStrikeFdrCollector(Collector):
    """Falcon Data Replicator: SQS notifications -> gzip-NDJSON objects in S3."""

    name, fmt, label = ("crowdstrike_fdr", "crowdstrike_json",
                        "CrowdStrike Falcon Data Replicator")

    def __init__(self, queue_url: str, region: str, access_key: str,
                 secret_key: str, session_token: str, bucket: str,
                 visibility_timeout: int = 900):
        self.queue_url = queue_url
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        # Notifications carry their own bucket; this is only a fallback for the
        # S3-event shape, which names the bucket per record anyway.
        self.bucket = bucket
        self.visibility_timeout = visibility_timeout

    def configured(self) -> bool:
        return bool(self.queue_url and self.region and self.access_key
                    and self.secret_key)

    # ---- thin network methods ------------------------------------------- #
    def _sqs(self, target: str, body: str) -> str:
        now = _now()
        host = sqs_host(self.region)
        payload = body.encode("utf-8")
        headers = sigv4_signed_headers(
            access_key=self.access_key, secret_key=self.secret_key,
            region=self.region, service="sqs", method="POST", host=host,
            uri_path="/", params={}, payload=payload,
            amz_date=now.strftime("%Y%m%dT%H%M%SZ"),
            datestamp=now.strftime("%Y%m%d"), session_token=self.session_token,
            extra_headers={"content-type": _SQS_JSON_CONTENT_TYPE,
                           "x-amz-target": target})
        return self._http_post(f"https://{host}/", headers, payload)

    def _get_bytes(self, url: str, headers: dict) -> bytes:
        """Byte-preserving twin of ``Collector._http_get``: FDR objects are gzip
        and the ABC's lossy utf-8 decode would destroy them."""
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310 — configured URL
            return read_capped(resp, _MAX_OBJECT_BYTES)

    def _s3_get(self, bucket: str, key: str) -> bytes:
        now = _now()
        host = s3_host(bucket, self.region)
        path = s3_canonical_path(key)
        headers = sigv4_signed_headers(
            access_key=self.access_key, secret_key=self.secret_key,
            region=self.region, service="s3", method="GET", host=host,
            uri_path=path, params={}, payload=b"",
            amz_date=now.strftime("%Y%m%dT%H%M%SZ"),
            datestamp=now.strftime("%Y%m%d"), session_token=self.session_token,
            extra_headers={"x-amz-content-sha256": _EMPTY_SHA256})
        return self._get_bytes(f"https://{host}{path}", headers)

    # ---- ack + fetch ----------------------------------------------------- #
    def _ack(self, handles: list) -> None:
        """Delete the previous batch, tolerantly.

        A receipt handle dies with its visibility timeout, and a failed delete only
        means SQS redelivers — at-least-once, which the event dedup absorbs. Letting
        it raise would be the opposite of safe: the cursor carrying these handles
        would never advance, so every future poll would retry the same doomed delete
        and the collector would wedge. Nothing here can *skip* unread data, which is
        the invariant the no-catching-in-fetch rule exists to protect."""
        for i in range(0, len(handles), _SQS_DELETE_BATCH):
            chunk = handles[i:i + _SQS_DELETE_BATCH]
            try:
                self._sqs("AmazonSQS.DeleteMessageBatch",
                          sqs_delete_batch_body(self.queue_url, chunk))
            except Exception as exc:  # noqa: BLE001 — see the docstring
                log.warning("crowdstrike_fdr: SQS delete failed (%s); "
                            "%d message(s) will redeliver", exc, len(chunk))

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        self._ack(fdr_pending_handles(cursor))

        body = self._sqs("AmazonSQS.ReceiveMessage",
                         sqs_receive_body(self.queue_url,
                                          visibility_timeout=self.visibility_timeout))
        handles: list[str] = []
        lines: list[str] = []
        objects = 0
        for msg in sqs_messages(body):
            refs = fdr_file_refs(msg["body"], self.bucket)
            # Stop before blowing the object budget, but never skip the FIRST
            # message: a single notification bigger than the budget must still
            # make progress or the queue wedges.
            if objects and objects + len(refs) > _MAX_OBJECTS:
                break
            for bucket, key in refs:
                lines.extend(gunzip_ndjson(self._s3_get(bucket, key)))
            objects += len(refs)
            handles.append(msg["handle"])   # acked on the NEXT poll, post-ingest

        content = "\n".join(lines) if lines else ""
        return FetchResult(content, fdr_cursor(handles), len(lines))


# =========================================================================== #
#  Falcon API OAuth2 (client credentials) — shared by Streams & Incidents     #
# =========================================================================== #
def falcon_token_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/oauth2/token"


def falcon_token_form(client_id: str, client_secret: str) -> str:
    return urlencode({"client_id": client_id, "client_secret": client_secret})


def falcon_token(body: str) -> tuple[Optional[str], int]:
    """``(access_token, expires_in)`` from a Falcon OAuth2 response.

    A missing/garbled ``expires_in`` yields 0, which makes the caller treat the
    token as immediately stale — re-authenticating is always safe, caching a token
    with an unknown lifetime is not."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None, 0
    if not isinstance(obj, dict):
        return None, 0
    token = obj.get("access_token")
    try:
        expires = int(obj.get("expires_in"))
    except (TypeError, ValueError):
        expires = 0
    return (token if isinstance(token, str) and token else None), expires


class _FalconApiCollector(Collector):
    """Shared client-credentials token handling for the Falcon REST APIs."""

    fmt = "crowdstrike_json"

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 lookback_hours: int):
        self.base = (base_url or _DEFAULT_API).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.lookback = lookback_hours
        self._token_value = ""
        self._token_expires = 0.0

    def configured(self) -> bool:
        return bool(self.base and self.client_id and self.client_secret)

    def _token(self) -> str:
        """A Falcon bearer token, cached until ``_TOKEN_SKEW`` before it expires."""
        now = _monotonic()
        if self._token_value and now < self._token_expires:
            return self._token_value
        body = self._http_post(
            falcon_token_url(self.base),
            {"Content-Type": "application/x-www-form-urlencoded",
             "Accept": "application/json"},
            falcon_token_form(self.client_id, self.client_secret).encode("utf-8"))
        token, expires_in = falcon_token(body)
        if not token:
            raise RuntimeError("no access_token in CrowdStrike token response")
        self._token_value = token
        self._token_expires = now + max(expires_in - _TOKEN_SKEW, 0)
        return token

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}",
                "Accept": "application/json"}


# --------------------------------------------------------------------------- #
#  Event Streams (datafeed firehose, offset cursor)                           #
# --------------------------------------------------------------------------- #
def datafeed_url(base_url: str, app_id: str) -> str:
    return (f"{base_url.rstrip('/')}/sensors/entities/datafeed/v2"
            f"?{urlencode({'appId': app_id})}")


def datafeed_streams(body: str) -> list[dict]:
    """``[{"url": dataFeedURL, "token": sessionToken.token}]`` — one per partition.

    A resource missing either half is dropped: without the session token the
    firehose 401s, and there is nothing useful to report per-partition."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    resources = obj.get("resources") if isinstance(obj, dict) else None
    out: list[dict] = []
    for r in resources or []:
        if not isinstance(r, dict):
            continue
        url = first(r.get("dataFeedURL"), r.get("datafeedURL"), r.get("dataFeedUrl"))
        session = r.get("sessionToken")
        token = session.get("token") if isinstance(session, dict) else None
        if isinstance(url, str) and url and isinstance(token, str) and token:
            out.append({"url": url, "token": token})
    return out


def feed_key(url: str) -> str:
    """Stable per-partition key for the offset map: host + path. The *query*
    carries the offset and changes every poll, so it must not be part of the key."""
    parts = urlsplit(url)
    return f"{parts.netloc}{parts.path}"


def stream_url_with_offset(url: str, offset: Optional[str]) -> str:
    """Set/replace the ``offset`` parameter, preserving ``appId`` and the rest."""
    if offset in (None, ""):
        return url
    parts = urlsplit(url)
    params = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
              if k != "offset"]
    params.append(("offset", str(offset)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(params), parts.fragment))


def stream_records(text: str) -> list[dict]:
    """NDJSON objects off the firehose.

    A batch is cut at an arbitrary byte boundary, so the last line can be a partial
    object; it is dropped, and because the cursor is derived from the records that
    *did* parse, that offset is simply re-read on the next poll."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def max_offset(records: list, current: Optional[str]) -> Optional[str]:
    """Highest ``metadata.offset`` across a batch — the next per-partition offset.
    Falls back to ``current`` so an empty batch never NULLs the checkpoint."""
    best: Optional[int] = None
    for r in records:
        if not isinstance(r, dict):
            continue
        meta = r.get("metadata")
        value = meta.get("offset") if isinstance(meta, dict) else r.get("offset")
        try:
            offset = int(value)
        except (TypeError, ValueError):
            continue
        if best is None or offset > best:
            best = offset
    return str(best) if best is not None else current


def stream_offsets(cursor: Optional[str]) -> dict[str, str]:
    """The per-partition offset map from a stored cursor ({} when absent/garbled)."""
    if not cursor:
        return {}
    try:
        obj = json.loads(cursor)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict):
        return {}
    return {str(k): str(v) for k, v in obj.items() if v is not None}


def stream_cursor(offsets: dict) -> str:
    return json.dumps({str(k): str(v) for k, v in offsets.items()}, sort_keys=True)


class CrowdStrikeStreamCollector(_FalconApiCollector):
    """Falcon Event Streams, read in bounded batches and resumed by offset."""

    name, label = "crowdstrike_streams", "CrowdStrike Falcon Event Streams"

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 app_id: str, lookback_hours: int):
        super().__init__(base_url, client_id, client_secret, lookback_hours)
        # Falcon keys a stream session by appId; two consumers sharing one appId
        # steal each other's offsets, so this must be unique per deployment.
        self.app_id = app_id or "logocean"

    def _read_stream(self, url: str, headers: dict) -> str:
        """Read ONE bounded batch off the firehose and close.

        The datafeed never ends, so a plain ``_http_get`` would block until the
        socket timeout and raise. Whole NDJSON lines are read until the byte or
        wall-clock budget is spent. A mid-stream read error IS the end of the
        batch — an idle firehose sends nothing, and a reset mid-line only costs
        records the offset cursor has not advanced past, so nothing can be
        skipped. Connect/HTTP failures happen at ``urlopen``, outside the loop,
        and still propagate."""
        req = urllib.request.Request(url, headers=headers, method="GET")
        chunks: list[bytes] = []
        total = 0
        deadline = _monotonic() + _STREAM_SECONDS
        with urllib.request.urlopen(  # nosec B310 — configured URL
                req, timeout=_STREAM_READ_TIMEOUT) as resp:
            try:
                while total < _STREAM_MAX_BYTES and _monotonic() < deadline:
                    line = resp.readline()
                    if not line:
                        break
                    chunks.append(line)
                    total += len(line)
            except OSError as exc:      # includes TimeoutError — see the docstring
                log.debug("crowdstrike_streams: batch ended (%s)", exc)
        return b"".join(chunks).decode("utf-8", "replace")

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        offsets = stream_offsets(cursor)
        listing = self._http_get(datafeed_url(self.base, self.app_id), self._auth())
        records: list[dict] = []
        for feed in datafeed_streams(listing)[:_MAX_FEEDS]:
            key = feed_key(feed["url"])
            text = self._read_stream(
                stream_url_with_offset(feed["url"], offsets.get(key)),
                {"Authorization": f"Token {feed['token']}",
                 "Accept": "application/json"})
            batch = stream_records(text)
            records.extend(batch)
            advanced = max_offset(batch, offsets.get(key))
            if advanced is not None:
                offsets[key] = advanced
        content = json.dumps(records) if records else ""
        return FetchResult(content, stream_cursor(offsets), len(records))


# --------------------------------------------------------------------------- #
#  Incidents (Falcon Complete / Incidents API)                                #
# --------------------------------------------------------------------------- #
#: Falcon incident status codes. Mapped to text so the parser's ``action`` (which
#: reads ``action`` before ``Status``) is a string, not the raw integer.
_INCIDENT_STATUS = {20: "New", 25: "Reopened", 30: "In Progress", 40: "Closed"}


def incident_status(value: Any) -> Optional[str]:
    try:
        return _INCIDENT_STATUS.get(int(value))
    except (TypeError, ValueError):
        return value if isinstance(value, str) and value else None


def fql_time(iso: str) -> str:
    """Normalize a cursor to the RFC3339 ``Z`` form an FQL filter expects.

    Cursors are mixed-format in one column — ``iso_lookback`` emits
    ``...T00:00:00.000Z`` while ``max_time_iso`` returns ``...+00:00`` — and an
    unescaped ``+`` in a query string decodes as a space, silently shifting the
    window. Normalizing removes the offset entirely; the value is still urlencoded
    by the builder below."""
    dt = parse_ts(iso)
    if dt is None:
        return iso
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def incident_query_url(base_url: str, since_iso: str, offset: Optional[int] = None,
                       limit: int = _INCIDENT_PAGE) -> str:
    params: list[tuple[str, Any]] = [
        ("filter", f"modified_timestamp:>'{fql_time(since_iso)}'"),
        ("sort", "modified_timestamp.asc"),
        ("limit", limit),
    ]
    if offset:
        params.append(("offset", offset))
    return (f"{base_url.rstrip('/')}/incidents/queries/incidents/v1"
            f"?{urlencode(params)}")


def incident_detail_url(base_url: str) -> str:
    return f"{base_url.rstrip('/')}/incidents/entities/incidents/GET/v1"


def incident_detail_body(ids: list) -> str:
    return json.dumps({"ids": [str(i) for i in ids]})


def incident_ids(body: str) -> tuple[list[str], Optional[int]]:
    """``(ids, next_offset)`` from an incident id-query response.

    ``next_offset`` is None on the last page. A pagination block that is missing or
    token-shaped rather than integer-shaped also yields None — one page is a safe
    under-read (the cursor still advances to the newest record seen), an infinite
    loop is not."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return [], None
    if not isinstance(obj, dict):
        return [], None
    ids = [i for i in (obj.get("resources") or []) if isinstance(i, str)]
    meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else None
    if not ids or not pagination:
        return ids, None
    try:
        seen = int(pagination.get("offset") or 0) + len(ids)
        total = int(pagination.get("total") or 0)
    except (TypeError, ValueError):
        return ids, None
    return ids, (seen if seen < total else None)


def _first_str(value: Any) -> Optional[str]:
    """First scalar of a list-valued incident field (``tactics``, ``users``, ...)."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
            if isinstance(item, dict):
                name = first(item.get("name"), item.get("display_name"))
                if isinstance(name, str) and name:
                    return name
    return None


def _put(rec: dict, key: str, value: Any) -> None:
    """Set a canonical scalar without clobbering a value the vendor already sent."""
    if value not in (None, "") and rec.get(key) in (None, ""):
        rec[key] = value


def shape_incident(inc: dict) -> dict:
    """Add the scalar keys the parser and CIM can actually read.

    The Incidents API nests hosts/tactics/techniques/users in lists, and neither
    ``crowdstrike_json._g`` nor ``app/cim/match._raw_value`` can reach into a list
    — a container yields nothing. So the first element of each is lifted to a
    top-level scalar, following the ``windows_security.py:126`` precedent of
    writing one agreed spelling beside the vendor's own. Nothing is removed:
    ``incident_id``, ``cid`` and ``state`` survive in ``raw`` for a later case
    import, and the original nested fields stay searchable."""
    out = dict(inc)
    _put(out, "timestamp", first(inc.get("modified_timestamp"), inc.get("created"),
                                 inc.get("start"), inc.get("end")))
    hosts = inc.get("hosts")
    if isinstance(hosts, list) and hosts and isinstance(hosts[0], dict):
        host = hosts[0]
        _put(out, "hostname", first(host.get("hostname"), host.get("device_id")))
        _put(out, "local_ip", host.get("local_ip"))
        _put(out, "external_ip", host.get("external_ip"))
        _put(out, "aid", host.get("device_id"))
    _put(out, "tactic", _first_str(inc.get("tactics")))
    _put(out, "technique", _first_str(inc.get("techniques")))
    _put(out, "user_name", _first_str(inc.get("users")))
    _put(out, "action", incident_status(first(inc.get("status"), inc.get("state"))))
    return out


def incident_records(body: str) -> list[dict]:
    """Shaped incident entities from an ``entities/incidents/GET/v1`` response."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    resources = obj.get("resources") if isinstance(obj, dict) else None
    return [shape_incident(r) for r in (resources or []) if isinstance(r, dict)]


class CrowdStrikeIncidentCollector(_FalconApiCollector):
    """Falcon Incidents — id query, then batched entity fetch."""

    name, label = "crowdstrike_incidents", "CrowdStrike Falcon incidents"

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        auth = self._auth()
        post_headers = dict(auth)
        post_headers["Content-Type"] = "application/json"

        records: list[dict] = []
        offset: Optional[int] = None
        for _ in range(_MAX_PAGES):
            listing = self._http_get(
                incident_query_url(self.base, since, offset), auth)
            ids, offset = incident_ids(listing)
            if ids:
                detail = self._http_post(
                    incident_detail_url(self.base), post_headers,
                    incident_detail_body(ids).encode("utf-8"))
                records.extend(incident_records(detail))
            if not offset:
                break

        # {"resources": [...]} is exactly what crowdstrike_json._iter_records
        # unwraps, so the batch parses identically to a console export.
        content = json.dumps({"resources": records}) if records else ""
        return FetchResult(content,
                           max_time_iso(records, "modified_timestamp", since),
                           len(records))

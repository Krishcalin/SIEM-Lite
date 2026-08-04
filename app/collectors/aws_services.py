# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""AWS security-service collectors: GuardDuty, Security Hub, Config compliance and
Route 53 Resolver query logs.

``cloud.py`` already ships CloudTrail, but CloudTrail is an ``x-amz-json-1.1`` POST
to ``/`` and ``cloud.py:sigv4_headers`` is hard-wired to exactly that shape — its
canonical request is literally ``POST / <empty query> ...``. GuardDuty and Security
Hub are REST-JSON APIs with resource paths (``/detector/{id}/findings``,
``/findings``), so they cannot use it. ``sigv4_rest_headers`` below is the general
signer: same signing key derivation (``cloud.py:_signing_key`` is reused, not
re-derived), a real canonical request over method + path + query + headers. It is
pinned in the unit tests to the AWS-published ``get-vanilla`` SigV4 test vector AND
asserted to reproduce ``sigv4_headers`` byte-for-byte for the POST-to-``/`` case, so
the two signers can never drift.

Four collectors, all sharing the existing ``aws/*`` vault credential slots:

  * ``aws_guardduty``          ListFindings + GetFindings   -> aws_guardduty parser
  * ``aws_securityhub``        GetFindings (ASFF)           -> aws_securityhub parser
  * ``aws_config_compliance``  GetFindings filtered to the AWS Config integration
  * ``aws_route53_resolver``   CloudWatch Logs FilterLogEvents on the query-log group

Why AWS Config compliance is read THROUGH Security Hub rather than from the Config
API: ``config:GetComplianceDetailsByConfigRule`` has no time-window parameter and
no ordering, so it cannot be checkpointed — every poll would re-read the whole
estate, one request per rule, on a scheduler that is serial with a 30s timeout per
call. Config publishes the same evaluations into Security Hub as ASFF with a
``Compliance.Status`` and a filterable ``UpdatedAt``, which is exactly a compliance
CHANGE feed and costs one paginated call. Same data, checkpointable.

Every URL builder, request body builder and response unwrapper is a module-level
pure function, so the whole file is unit-tested with no network and no credentials.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote

from ..util import parse_ts, to_int
from .base import (Collector, FetchResult, iso_lookback, make_cursor, max_time_iso,
                   parse_cursor)
from .cloud import _hmac, _signing_key, sigv4_headers

# How many pages to pull in a single run (bounds one poll). The scheduler is serial
# with a 30s timeout per request, so a poll must stay well inside the interval.
_MAX_PAGES = 20
# GuardDuty spends TWO requests per page (ListFindings then GetFindings), so its own
# cap is half. Do not import another module's private constant — each file owns one.
_GD_MAX_PAGES = 10

_GD_PAGE = 50            # GuardDuty ListFindings/GetFindings cap out at 50 ids
_SH_PAGE = 100           # Security Hub GetFindings caps out at 100
_LOGS_PAGE = 1000        # bound the response well under base.py's 64 MB cap

# CloudWatch Logs is a json-1.1 POST to "/" — the ONE AWS API here that the shipped
# `sigv4_headers` can sign as-is.
_LOGS_TARGET = "Logs_20140328.FilterLogEvents"
_DETECTOR_PATH = "/detector"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _lower(value: Any) -> dict:
    if not isinstance(value, dict):
        return {}
    return {str(k).lower(): v for k, v in value.items()}


def _pick(d: dict, *names: str) -> Any:
    for n in names:
        v = d.get(n)
        if v is not None and v != "":
            return v
    return None


def _epoch_ms(value: Optional[str], fallback: Optional[datetime] = None) -> int:
    """A cursor as epoch milliseconds.

    Cursors are MIXED-FORMAT in one text column — ``iso_lookback`` writes
    ``2026-06-25T00:00:00.000Z`` and ``max_time_iso`` writes ``...+00:00`` — so this
    goes through ``util.parse_ts``, which reads both."""
    dt = parse_ts(value) if value else None
    return int((dt or fallback or _now()).timestamp() * 1000)


def newest_updated_at(records: list, current: Optional[str]) -> Optional[str]:
    """``max_time_iso`` over ``UpdatedAt``, tolerating the lowerCamel spelling.

    Threads `current` through as the fallback, so an empty or unparseable page never
    returns None — a None cursor is written as SQL NULL and destroys the checkpoint.
    """
    shim = [{"t": _pick(_lower(r), "updatedat", "createdat")}
            for r in records if isinstance(r, dict)]
    return max_time_iso(shim, "t", current)


# =========================================================================== #
#  SigV4 for REST-style AWS APIs (method + path + query)                      #
# =========================================================================== #
def canonical_path(path: str) -> str:
    """The canonical URI: the absolute path, URI-encoded, ``/`` preserved."""
    return quote(path or "/", safe="/") or "/"


def canonical_query(params: Optional[dict]) -> str:
    """The canonical query string: ``k=v`` pairs, each side URI-encoded, sorted."""
    if not params:
        return ""
    return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}"
                    for k, v in sorted(params.items()))


def sigv4_rest_headers(access_key: str, secret_key: str, region: str, service: str,
                       host: str, method: str, path: str, query: Optional[dict],
                       body: str, amz_date: str, datestamp: str,
                       content_type: str = "", session_token: str = "",
                       target: str = "") -> dict:
    """SigV4-signed headers for an arbitrary AWS REST request.

    The generalization of ``cloud.py:sigv4_headers``, which can only sign an
    ``x-amz-json-1.1`` POST to ``/``. Pure: both timestamps are arguments, so it is
    deterministic and unit-testable against AWS' published test vectors."""
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    signed = {"host": host, "x-amz-date": amz_date}
    if content_type:
        signed["content-type"] = content_type
    if session_token:
        signed["x-amz-security-token"] = session_token
    if target:
        signed["x-amz-target"] = target
    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    canonical_request = "\n".join([method.upper(), canonical_path(path),
                                   canonical_query(query), canonical_headers,
                                   signed_headers, payload_hash])

    algorithm = "AWS4-HMAC-SHA256"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [algorithm, amz_date, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    signature = _hmac(_signing_key(secret_key, datestamp, region, service),
                      string_to_sign).hex()
    authorization = (f"{algorithm} Credential={access_key}/{scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")

    out = {"X-Amz-Date": amz_date, "Authorization": authorization}
    if content_type:
        out["Content-Type"] = content_type
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    if target:
        out["X-Amz-Target"] = target
    return out


class _AwsCollector(Collector):
    """Shared SigV4 credentials + one thin signed-request method."""

    service: str = ""

    def __init__(self, region: str, access_key: str, secret_key: str,
                 session_token: str, lookback_hours: int):
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.lookback = lookback_hours

    def configured(self) -> bool:
        return bool(self.region and self.access_key and self.secret_key)

    def _host(self) -> str:
        return f"{self.service}.{self.region}.amazonaws.com"

    def _rest(self, method: str, path: str, body: str = "",
              query: Optional[dict] = None) -> str:
        now = _now()
        host = self._host()
        headers = sigv4_rest_headers(
            self.access_key, self.secret_key, self.region, self.service, host,
            method, path, query, body,
            now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"),
            content_type="application/json" if body else "",
            session_token=self.session_token)
        url = f"https://{host}{path}"
        qs = canonical_query(query)
        if qs:
            url = f"{url}?{qs}"
        if method.upper() == "GET":
            return self._http_get(url, headers)
        return self._http_post(url, headers, body.encode("utf-8"))


# =========================================================================== #
#  GuardDuty — ListFindings + GetFindings                                     #
# =========================================================================== #
def list_findings_path(detector_id: str) -> str:
    return f"/detector/{quote(detector_id, safe='')}/findings"


def get_findings_path(detector_id: str) -> str:
    return f"/detector/{quote(detector_id, safe='')}/findings/get"


def list_findings_body(since_ms: int, next_token: Optional[str] = None) -> str:
    """ListFindings for everything updated since the cursor, oldest first.

    ``updatedAt`` takes epoch MILLISECONDS in the finding criterion; sorting ascending
    is what makes the ``UpdatedAt`` watermark a safe checkpoint."""
    payload: dict = {
        "findingCriteria": {"criterion": {"updatedAt": {"greaterThanOrEqual": since_ms}}},
        "sortCriteria": {"attributeName": "updatedAt", "orderBy": "ASC"},
        "maxResults": _GD_PAGE,
    }
    if next_token:
        payload["nextToken"] = next_token
    return json.dumps(payload)


def get_findings_body(ids: list) -> str:
    return json.dumps({"findingIds": list(ids),
                       "sortCriteria": {"attributeName": "updatedAt", "orderBy": "ASC"}})


def detector_ids(body: str) -> list:
    """Unwrap a ListDetectors response (a region has at most one detector)."""
    obj = _lower(_json_obj(body))
    ids = _pick(obj, "detectorids")
    return [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []


def finding_ids(body: str) -> tuple[list, Optional[str]]:
    """Unwrap a ListFindings response -> (finding ids, next token)."""
    obj = _lower(_json_obj(body))
    ids = _pick(obj, "findingids")
    token = _pick(obj, "nexttoken")
    return ([i for i in ids if isinstance(i, str)] if isinstance(ids, list) else [],
            token if isinstance(token, str) else None)


def guardduty_findings(body: str) -> list:
    """Unwrap a GetFindings response -> the finding objects."""
    obj = _lower(_json_obj(body))
    found = _pick(obj, "findings")
    return [f for f in found if isinstance(f, dict)] if isinstance(found, list) else []


def _json_obj(body: str) -> Any:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


class AwsGuardDutyCollector(_AwsCollector):
    name, fmt, label = "aws_guardduty", "aws_guardduty", "AWS GuardDuty findings"
    service = "guardduty"

    def __init__(self, region: str, access_key: str, secret_key: str,
                 session_token: str, detector_id: str, lookback_hours: int):
        super().__init__(region, access_key, secret_key, session_token, lookback_hours)
        # Optional: a region has exactly one detector, discovered on first use when
        # the operator has not pinned it.
        self.detector_id = detector_id or ""

    def _get(self, path: str) -> str:
        return self._rest("GET", path)

    def _post(self, path: str, body: str) -> str:
        return self._rest("POST", path, body)

    def _detector(self) -> str:
        if not self.detector_id:
            ids = detector_ids(self._get(_DETECTOR_PATH))
            if not ids:
                raise RuntimeError(f"no GuardDuty detector in region {self.region}")
            self.detector_id = ids[0]
        return self.detector_id

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        detector = self._detector()
        since_ms = _epoch_ms(since, _now() - timedelta(hours=self.lookback))
        findings: list = []
        token: Optional[str] = None
        for _ in range(_GD_MAX_PAGES):
            ids, token = finding_ids(
                self._post(list_findings_path(detector),
                           list_findings_body(since_ms, token)))
            if ids:
                findings.extend(guardduty_findings(
                    self._post(get_findings_path(detector), get_findings_body(ids))))
            if not token:
                break
        content = json.dumps({"Findings": findings}) if findings else ""
        return FetchResult(content, newest_updated_at(findings, since), len(findings))


# =========================================================================== #
#  Security Hub — GetFindings (ASFF), and the AWS Config integration          #
# =========================================================================== #
def asff_time(value: Any) -> str:
    """An ASFF DateFilter bound: ``2026-06-25T11:30:00.000Z``.

    Cursors are mixed-format in one column (``iso_lookback`` writes ``...000Z``,
    ``max_time_iso`` writes ``...+00:00``), so both are normalized through
    ``util.parse_ts`` before Security Hub ever sees them."""
    dt = parse_ts(value) or _now()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def securityhub_filters(start_iso: str, end_iso: str, product_name: str = "") -> dict:
    """Active findings updated inside the window, optionally from one integration."""
    filters: dict = {
        "UpdatedAt": [{"Start": start_iso, "End": end_iso}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    }
    if product_name:
        filters["ProductName"] = [{"Value": product_name, "Comparison": "EQUALS"}]
    return filters


def securityhub_body(start_iso: str, end_iso: str, next_token: Optional[str] = None,
                     product_name: str = "") -> str:
    payload: dict = {
        "Filters": securityhub_filters(start_iso, end_iso, product_name),
        "SortCriteria": [{"Field": "UpdatedAt", "SortOrder": "asc"}],
        "MaxResults": _SH_PAGE,
    }
    if next_token:
        payload["NextToken"] = next_token
    return json.dumps(payload)


def securityhub_findings(body: str) -> tuple[list, Optional[str]]:
    """Unwrap a GetFindings response -> (ASFF findings, next token)."""
    obj = _lower(_json_obj(body))
    found = _pick(obj, "findings")
    token = _pick(obj, "nexttoken")
    return ([f for f in found if isinstance(f, dict)] if isinstance(found, list) else [],
            token if isinstance(token, str) else None)


class AwsSecurityHubCollector(_AwsCollector):
    name, fmt, label = ("aws_securityhub", "aws_securityhub",
                        "AWS Security Hub findings (ASFF)")
    service = "securityhub"
    #: "" pulls every integration's findings; a subclass narrows it to one product.
    product_name = ""

    def _post(self, body: str) -> str:
        return self._rest("POST", "/findings", body)

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        start, end = asff_time(since), asff_time(_now())
        findings: list = []
        token: Optional[str] = None
        for _ in range(_MAX_PAGES):
            page, token = securityhub_findings(
                self._post(securityhub_body(start, end, token, self.product_name)))
            findings.extend(page)
            if not token:
                break
        content = json.dumps({"Findings": findings}) if findings else ""
        return FetchResult(content, newest_updated_at(findings, since), len(findings))


class AwsConfigComplianceCollector(AwsSecurityHubCollector):
    """AWS Config rule evaluations, read as ASFF through the Security Hub integration.

    Its own collector name (and therefore its own checkpoint and its own admin
    on/off switch) because compliance drift and threat findings have completely
    different volumes and review cadences."""

    name = "aws_config_compliance"
    label = "AWS Config compliance findings (via Security Hub, ASFF)"
    product_name = "Config"


# =========================================================================== #
#  Route 53 Resolver query logs (via CloudWatch Logs)                         #
# =========================================================================== #
def filter_log_events_body(log_group: str, start_ms: int, end_ms: int,
                           next_token: Optional[str] = None) -> str:
    payload: dict = {
        "logGroupName": log_group,
        "startTime": start_ms,
        "endTime": end_ms,
        "limit": _LOGS_PAGE,
    }
    if next_token:
        payload["nextToken"] = next_token
    return json.dumps(payload)


def canonicalize_route53(rec: dict, cw_timestamp: Any = None) -> dict:
    """Stamp the source identity and the canonical key spellings onto one record.

    Route 53 Resolver names its fields ``query_timestamp`` / ``srcaddr`` / ``srcport``
    / ``query_name`` / ``query_type``. The record is fed to the ``generic_json``
    mapper, which reads ``timestamp`` / ``src_ip`` / ``src_port`` / ``type`` /
    ``vendor`` / ``product``, and the CIM DNS model reads ``query`` / ``qtype_name``.
    Writing ONE agreed spelling beside the vendor's own is the same move
    ``windows_security.py`` makes for ``event_id`` — no value is invented, only
    aliased, and the original record is left intact underneath. An existing key is
    never overwritten.

    (Interim: a dedicated ``aws_route53_resolver`` parser would do this at parse time
    and is the follow-up. Until then this is what keeps the records from landing as
    vendor ``json`` with a null ``log_type``, i.e. in no CIM model at all.)
    """
    out = dict(rec)
    out.setdefault("vendor", "aws")
    out.setdefault("product", "route53-resolver")
    out.setdefault("type", "dns")
    ts = rec.get("query_timestamp")
    if ts in (None, ""):
        ts = cw_timestamp
    if ts not in (None, "") and "timestamp" not in out:
        out["timestamp"] = ts
    for src, alias in (("srcaddr", "src_ip"), ("srcport", "src_port"),
                       ("query_name", "query"), ("query_type", "qtype_name")):
        value = rec.get(src)
        if value not in (None, "") and alias not in out:
            out[alias] = value
    return out


def route53_records(body: str) -> tuple[list, Optional[str]]:
    """Unwrap a CloudWatch Logs FilterLogEvents page -> (query records, next token).

    Each ``events[].message`` is itself a JSON Route 53 Resolver query-log record —
    the same string-inside-JSON shape CloudTrail's ``CloudTrailEvent`` uses."""
    obj = _json_obj(body)
    if not isinstance(obj, dict):
        return [], None
    out: list = []
    for ev in obj.get("events") or []:
        if not isinstance(ev, dict):
            continue
        message = ev.get("message")
        if not isinstance(message, str):
            continue
        rec = _json_obj(message)
        if isinstance(rec, dict):
            out.append(canonicalize_route53(rec, ev.get("timestamp")))
    token = obj.get("nextToken")
    return out, token if isinstance(token, str) else None


class AwsRoute53ResolverCollector(_AwsCollector):
    name, fmt, label = ("aws_route53_resolver", "generic_json",
                        "AWS Route 53 Resolver query logs")
    service = "logs"

    def __init__(self, region: str, access_key: str, secret_key: str,
                 session_token: str, log_group: str, lookback_hours: int):
        super().__init__(region, access_key, secret_key, session_token, lookback_hours)
        self.log_group = log_group

    def configured(self) -> bool:
        return bool(self.region and self.access_key and self.secret_key and self.log_group)

    def _post(self, body: str) -> str:
        """CloudWatch Logs is an ``x-amz-json-1.1`` POST to ``/`` — the shipped
        ``sigv4_headers`` signs it exactly as-is."""
        now = _now()
        host = self._host()
        headers = sigv4_headers(self.access_key, self.secret_key, self.region,
                                self.service, host, _LOGS_TARGET, body,
                                now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d"),
                                self.session_token)
        return self._http_post(f"https://{host}/", headers, body.encode("utf-8"))

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        state = parse_cursor(cursor)
        since = state.get("since") or iso_lookback(self.lookback)
        now = _now()
        start_ms = _epoch_ms(since, now - timedelta(hours=self.lookback))

        # A FilterLogEvents `nextToken` is only meaningful for the IDENTICAL request,
        # so a parked one is replayed against the window it was issued for. Without
        # the stored `window_end` the token is unusable and the walk simply restarts —
        # `since` is unchanged, so that re-reads rather than skips.
        resume = str(state.get("next") or "")
        parked_end = to_int(state.get("window_end"))
        if resume and parked_end is None:
            resume = ""
        end_ms = parked_end if resume else int(now.timestamp() * 1000)

        records: list = []
        token: Optional[str] = resume or None
        for _ in range(_MAX_PAGES):
            page, token = route53_records(self._post(
                filter_log_events_body(self.log_group, start_ms, end_ms, token)))
            records.extend(page)
            if not token:
                break
        content = json.dumps(records) if records else ""

        if token:
            # Cut short at the page cap with a live nextToken. Park it and hold `since`
            # where it is, for the same reason as the Defender walk — with one extra
            # twist that makes it worse here: FilterLogEvents has no sort parameter AND
            # it interleaves log STREAMS (one per resolver endpoint / VPC), so a paged
            # result set is not globally timestamp-ordered even in principle. Taking
            # `max(timestamp)` over the pages read then set `startTime` past queries
            # sitting on later pages, and they were never fetched again. A busy
            # multi-VPC query-log group passes 20 pages x 1000 events per tick at
            # roughly 66 queries/second.
            return FetchResult(content,
                               make_cursor(since=since, next=token, window_end=end_ms),
                               len(records))

        return FetchResult(content,
                           make_cursor(since=max_time_iso(records, "timestamp", since)),
                           len(records))

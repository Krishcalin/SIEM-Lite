"""Cloud & identity collectors that need request signing or OAuth2 (AWS, Entra,
Microsoft 365).

Unlike the simple token collectors in ``sources.py``, these authenticate with
AWS SigV4 or the Microsoft OAuth2 client-credentials flow. As elsewhere, every
network call goes through ``_http_get``/``_http_post`` while the signing, URL,
form and response-shaping logic stays in pure functions so it is unit-tested
without a network or real credentials.

Each collector pulls vendor JSON and re-shapes it into exactly what the existing
parser expects, so pulled events get the same parse -> detect -> alert path as
uploads:

  * AWS CloudTrail   ``LookupEvents`` -> ``{"Records": [...]}``  -> aws_cloudtrail
  * Entra ID         Graph ``auditLogs/signIns`` ``{"value":[...]}`` -> entra_signin
  * Microsoft 365    Management Activity content blobs (array)     -> m365_audit
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote, urlencode

from ..util import parse_ts
from .base import Collector, FetchResult, iso_lookback, json_records, max_time_iso

# How many pages / content blobs to pull in a single run (bounds one poll).
_MAX_PAGES = 20


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _epoch(iso_or_none: Optional[str], fallback: datetime) -> int:
    dt = parse_ts(iso_or_none) if iso_or_none else None
    return int((dt or fallback).timestamp())


# =========================================================================== #
#  AWS CloudTrail (SigV4-signed LookupEvents)                                 #
# =========================================================================== #
_CT_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sigv4_headers(access_key: str, secret_key: str, region: str, service: str,
                  host: str, target: str, body: str, amz_date: str,
                  datestamp: str, session_token: str = "") -> dict:
    """Build SigV4-signed headers for an ``x-amz-json-1.1`` POST to ``/``.

    Pure: given the same inputs (including the two timestamps) it is fully
    deterministic, so it can be unit-tested without AWS."""
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    signed = {
        "content-type": "application/x-amz-json-1.1",
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-target": target,
    }
    if session_token:
        signed["x-amz-security-token"] = session_token
    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, payload_hash])

    algorithm = "AWS4-HMAC-SHA256"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [algorithm, amz_date, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    signature = hmac.new(_signing_key(secret_key, datestamp, region, service),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (f"{algorithm} Credential={access_key}/{scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")

    out = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Date": amz_date,
        "X-Amz-Target": target,
        "Authorization": authorization,
    }
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    return out


def cloudtrail_body(start_epoch: int, end_epoch: int,
                    next_token: Optional[str] = None) -> str:
    payload = {"StartTime": start_epoch, "EndTime": end_epoch, "MaxResults": 50}
    if next_token:
        payload["NextToken"] = next_token
    return json.dumps(payload)


def cloudtrail_records(body: str) -> tuple[list, Optional[str]]:
    """Unwrap a LookupEvents response: each event's ``CloudTrailEvent`` is a JSON
    string holding the real record. Returns (records, next_token)."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return [], None
    if not isinstance(obj, dict):
        return [], None
    records = []
    for e in obj.get("Events") or []:
        ce = e.get("CloudTrailEvent") if isinstance(e, dict) else None
        if isinstance(ce, str):
            try:
                records.append(json.loads(ce))
            except (json.JSONDecodeError, ValueError):
                continue
    return records, obj.get("NextToken")


class AwsCloudTrailCollector(Collector):
    name, fmt, label = "aws_cloudtrail", "aws_cloudtrail", "AWS CloudTrail"
    service = "cloudtrail"

    def __init__(self, region: str, access_key: str, secret_key: str,
                 session_token: str, lookback_hours: int):
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.lookback = lookback_hours

    def configured(self) -> bool:
        return bool(self.region and self.access_key and self.secret_key)

    def _post(self, body: str) -> str:
        now = _now()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        host = f"cloudtrail.{self.region}.amazonaws.com"
        headers = sigv4_headers(self.access_key, self.secret_key, self.region,
                                self.service, host, _CT_TARGET, body, amz_date,
                                datestamp, self.session_token)
        return self._http_post(f"https://{host}/", headers, body.encode("utf-8"))

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        start = _epoch(cursor, now - timedelta(hours=self.lookback))
        end = int(now.timestamp())
        records: list = []
        token: Optional[str] = None
        for _ in range(_MAX_PAGES):
            body = self._post(cloudtrail_body(start, end, token))
            page, token = cloudtrail_records(body)
            records.extend(page)
            if not token:
                break
        content = json.dumps({"Records": records}) if records else ""
        next_cursor = max_time_iso(records, "eventTime", cursor or iso_lookback(self.lookback))
        return FetchResult(content, next_cursor, len(records))


# =========================================================================== #
#  Microsoft OAuth2 (client credentials) — shared by Entra & M365             #
# =========================================================================== #
def ms_token_url(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{quote(tenant)}/oauth2/v2.0/token"


def ms_token_form(client_id: str, client_secret: str, scope: str) -> str:
    return urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    })


def ms_access_token(body: str) -> Optional[str]:
    try:
        return json.loads(body).get("access_token")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return None


class _MicrosoftCollector(Collector):
    """Shared client-credentials token acquisition for Microsoft APIs."""

    scope: str = ""

    def __init__(self, tenant: str, client_id: str, client_secret: str,
                 lookback_hours: int):
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.lookback = lookback_hours

    def configured(self) -> bool:
        return bool(self.tenant and self.client_id and self.client_secret)

    def _token(self) -> str:
        body = self._http_post(
            ms_token_url(self.tenant),
            {"Content-Type": "application/x-www-form-urlencoded"},
            ms_token_form(self.client_id, self.client_secret, self.scope).encode("utf-8"))
        token = ms_access_token(body)
        if not token:
            raise RuntimeError("no access_token in Microsoft token response")
        return token


# --------------------------------------------------------------------------- #
#  Entra ID sign-in logs (Microsoft Graph)                                    #
# --------------------------------------------------------------------------- #
def graph_signin_url(since_iso: str) -> str:
    flt = quote(f"createdDateTime gt {since_iso}")
    return ("https://graph.microsoft.com/v1.0/auditLogs/signIns"
            f"?$top=1000&$orderby=createdDateTime&$filter={flt}")


class EntraSignInCollector(_MicrosoftCollector):
    name, fmt, label = "entra_signin", "entra_signin", "Microsoft Entra ID sign-ins"
    scope = "https://graph.microsoft.com/.default"

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        token = self._token()
        body = self._http_get(graph_signin_url(since),
                              {"Authorization": f"Bearer {token}",
                               "Accept": "application/json"})
        recs = json_records(body, key="value")
        return FetchResult(body, max_time_iso(recs, "createdDateTime", since), len(recs))


# --------------------------------------------------------------------------- #
#  Microsoft 365 Unified Audit Log (Office 365 Management Activity API)       #
# --------------------------------------------------------------------------- #
def _m365_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def mgmt_content_url(tenant: str, content_type: str, start: str, end: str) -> str:
    qs = urlencode({"contentType": content_type, "startTime": start, "endTime": end})
    return (f"https://manage.office.com/api/v1.0/{quote(tenant)}"
            f"/activity/feed/subscriptions/content?{qs}")


def content_uris(body: str) -> list[str]:
    """Pull the ``contentUri`` blob locations out of a content-listing response."""
    return [r["contentUri"] for r in json_records(body)
            if isinstance(r, dict) and isinstance(r.get("contentUri"), str)]


class M365AuditCollector(_MicrosoftCollector):
    name, fmt, label = "m365_audit", "m365_audit", "Microsoft 365 audit log"
    scope = "https://manage.office.com/.default"

    def __init__(self, tenant: str, client_id: str, client_secret: str,
                 content_type: str, lookback_hours: int):
        super().__init__(tenant, client_id, client_secret, lookback_hours)
        self.content_type = content_type or "Audit.General"

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        # Management API caps the window at 24h and within the last 7 days.
        start_dt = parse_ts(cursor) if cursor else None
        floor = now - timedelta(hours=min(self.lookback, 24))
        if start_dt is None or start_dt < floor:
            start_dt = floor
        start, end = _m365_time(start_dt), _m365_time(now)

        token = self._token()
        auth = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        listing = self._http_get(
            mgmt_content_url(self.tenant, self.content_type, start, end), auth)

        records: list = []
        for uri in content_uris(listing)[:_MAX_PAGES]:
            records.extend(json_records(self._http_get(uri, auth)))

        content = json.dumps(records) if records else ""
        # The window end is the watermark — next run starts where this one ended.
        return FetchResult(content, _m365_time(now) + "Z", len(records))

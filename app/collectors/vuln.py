# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Vulnerability-scanner collectors: Qualys VMDR, Tenable Vulnerability
Management (Tenable.io) and Rapid7 InsightVM.

These are the sources that populate the Vulnerability CIM model, which ships
empty by design. Each collector pulls scanner findings and re-shapes them into
exactly what its parser expects, so a pulled finding gets the same
parse -> CIM-stamp -> detect -> alert path as an upload:

  * Qualys   ``asset/host/vm/detection`` XML pages   -> ``qualys``
  * Tenable  ``vulns/export`` chunks (JSON array)    -> ``tenable``
  * Rapid7   asset x finding x catalog join envelope -> ``rapid7``

As everywhere in this package the network call is one thin method and every URL,
body, header and response unwrapper is a module-level pure function, so the whole
file is unit-tested with no network and no credentials.

THREE THINGS ARE DIFFERENT HERE, all deliberate:

1. POLL CADENCE. Scanner data changes on a scan cadence (hours to days), not a log
   cadence. ``CollectorScheduler`` ticks every ``COLLECTOR_INTERVAL`` (default
   300s), is SERIAL on one threadpool thread and applies no per-collector timeout,
   so a scanner that walked its whole API every tick would starve every collector
   behind it. ``_VulnCollector.due()`` makes the in-between ticks a genuine no-op:
   no vendor request, and the checkpoint is written back UNCHANGED so nothing is
   skipped. It is instance state, so a restart costs one extra pull — the same
   asymmetry the package already has for credentials.

2. THE WALK IS RESUMABLE ACROSS TICKS, because none of these three APIs returns a
   scan estate in one poll. A collector that capped its page walk and then advanced
   its watermark anyway would DROP everything past the cap, silently and forever.
   Instead the resume pointer — Qualys' continuation URL, Tenable's export uuid and
   chunk list, Rapid7's asset page number — is parked in the cursor beside the
   window it belongs to, and the watermark only moves once the walk completes. A
   resuming tick ignores the cadence floor so a backfill still makes progress.

3. TENABLE IS ASYNCHRONOUS, and is modelled as such rather than pretended to be one
   GET. ``POST /vulns/export`` only QUEUES a job; the caller then polls ``/status``
   and downloads numbered chunks. Blocking inside ``fetch`` until it finished would
   hold the shared scheduler thread for minutes, so the first tick queues and
   parks, and later ticks poll and drain.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.error
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlencode

from ..util import parse_ts, to_int
# `make_cursor` / `parse_cursor` live in base.py — every paged collector needs the
# same watermark-plus-resume-state column, not just the scanners. Re-exported here
# because this module is where they were introduced and where callers import them.
from .base import (Collector, FetchResult, iso_lookback, json_records, make_cursor,
                   parse_cursor)

#: Pages one poll walks before parking its resume pointer and letting the shared
#: scheduler move on. Module-private per the package's convention (cloud.py and
#: gcp.py each declare their own rather than sharing one from base.py).
_MAX_PAGES = 20
#: Findings requested per asset page on the Rapid7 console.
_FINDING_PAGE = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _obj(body: str) -> dict:
    """A response body as a dict ({} on anything else)."""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _int_list(value: Any) -> list[int]:
    """A sorted, de-duplicated list of ints out of whatever the cursor held."""
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        return []
    return sorted({n for n in (to_int(item) for item in value) if n is not None})


def basic_auth(username: str, password: str) -> str:
    """An HTTP Basic ``Authorization`` header value. Encoding, not cryptography."""
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


class _VulnCollector(Collector):
    """Shared poll-cadence floor for the scanner collectors — see note 1 in the
    module docstring. ``min_interval_seconds`` is the floor between two REAL pulls;
    resuming an already-started walk deliberately ignores it."""

    min_interval_seconds: int = 3600

    def __init__(self, lookback_hours: int, min_interval_seconds: Optional[int] = None):
        self.lookback = lookback_hours
        if min_interval_seconds is not None:
            self.min_interval_seconds = max(int(min_interval_seconds), 0)
        self._last_pull: Optional[datetime] = None

    def due(self, now: datetime) -> bool:
        """True when a fresh pull is allowed: never pulled, or the floor has passed."""
        if self._last_pull is None:
            return True
        return (now - self._last_pull).total_seconds() >= self.min_interval_seconds


# =========================================================================== #
#  Qualys VMDR — Host List Detection (XML, Basic auth)                        #
# =========================================================================== #
def qualys_time(value: Optional[str]) -> str:
    """A cursor rendered the way the Qualys API wants it: ``YYYY-MM-DDTHH:MM:SSZ``.

    Cursors are MIXED-FORMAT in one column — ``iso_lookback`` emits
    ``...T00:00:00.000Z`` while ``max_time_iso`` emits ``...+00:00`` — and Qualys
    rejects both a fractional second and a numeric offset. Normalizing through
    ``parse_ts`` accepts either shape and, as a side effect, removes the ``+``
    that would otherwise have to survive query-string escaping.
    """
    dt = parse_ts(value) if value else None
    return (dt or _now()).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def qualys_headers(username: str, password: str) -> dict:
    """Qualys rejects any request without ``X-Requested-With`` (its CSRF guard)."""
    return {"Authorization": basic_auth(username, password),
            "X-Requested-With": "LogOcean",
            "Accept": "application/xml"}


def qualys_detection_url(base: str, since: Optional[str], truncation_limit: int = 1000) -> str:
    """The Host List Detection request for everything updated since the watermark."""
    qs = urlencode({
        "action": "list",
        "output_format": "XML",
        "show_igs": "0",
        "show_reopened_info": "1",
        "status": "New,Active,Re-Opened,Fixed",
        "truncation_limit": str(truncation_limit),
        "detection_updated_since": qualys_time(since),
    })
    return f"{base.rstrip('/')}/api/2.0/fo/asset/host/vm/detection/?{qs}"


_WARNING_RE = re.compile(r"<WARNING>(.*?)</WARNING>", re.S | re.I)
_URL_RE = re.compile(r"<URL>(.*?)</URL>", re.S | re.I)
_XML_ENTITIES = (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                 ("&apos;", "'"), ("&amp;", "&"))


def qualys_next_url(body: str) -> Optional[str]:
    """The ``<WARNING><URL>`` continuation link Qualys returns when a response was
    truncated at ``truncation_limit``. None when this was the last page."""
    warning = _WARNING_RE.search(body or "")
    if not warning:
        return None
    match = _URL_RE.search(warning.group(1))
    if not match:
        return None
    url = match.group(1).strip()
    if url.startswith("<![CDATA[") and url.endswith("]]>"):
        url = url[9:-3].strip()
    for entity, char in _XML_ENTITIES:          # `&amp;` last: it un-escapes the rest
        url = url.replace(entity, char)
    return url.strip() or None


_DETECTION_RE = re.compile(r"<DETECTION[\s>]", re.I)


def qualys_detection_count(body: str) -> int:
    """Findings in one page — counted off the text so an idle poll costs no parse."""
    return len(_DETECTION_RE.findall(body or ""))


class QualysDetectionCollector(_VulnCollector):
    name, fmt, label = "qualys", "qualys", "Qualys VMDR host detections"

    def __init__(self, base_url: str, username: str, password: str,
                 lookback_hours: int, min_interval_seconds: Optional[int] = None,
                 truncation_limit: int = 1000):
        super().__init__(lookback_hours, min_interval_seconds)
        self.base = base_url
        self.username = username
        self.password = password
        self.truncation_limit = truncation_limit

    def configured(self) -> bool:
        return bool(self.base and self.username and self.password)

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        state = parse_cursor(cursor)
        since = state.get("since") or iso_lookback(self.lookback)
        resume = state.get("next")
        if not resume and not self.due(now):
            return FetchResult("", make_cursor(since=since), 0)
        # The window END is fixed when the walk STARTS, not when it finishes: a
        # backfill can span many ticks, and re-reading the clock on each one would
        # step the watermark past detections updated while we were still paging.
        until = (state.get("until") if resume else None) or qualys_time(now.isoformat())

        headers = qualys_headers(self.username, self.password)
        url = resume or qualys_detection_url(self.base, since, self.truncation_limit)
        pages: list[str] = []
        count = 0
        nxt: Optional[str] = None
        for _ in range(_MAX_PAGES):
            body = self._http_get(url, headers)
            pages.append(body)
            count += qualys_detection_count(body)
            nxt = qualys_next_url(body)
            if not nxt:
                break
            url = nxt

        self._last_pull = now
        # "" — not the empty envelope. `run_collector` gates ingest on
        # `content.strip()`, so returning the idle XML would re-ingest identical
        # bytes every poll and pile up zero-row `already_ingested` batches.
        content = "\n".join(p for p in pages if p.strip()) if count else ""
        if nxt:
            # Budget spent mid-walk: park the continuation link and hold the
            # watermark. Dropping the remainder here is the silent data loss this
            # collector exists to avoid.
            return FetchResult(content, make_cursor(since=since, until=until, next=nxt), count)
        return FetchResult(content, make_cursor(since=until), count)


# =========================================================================== #
#  Tenable Vulnerability Management — asynchronous vulns export                #
# =========================================================================== #
_TENABLE_BASE = "https://cloud.tenable.com"


def tenable_headers(access_key: str, secret_key: str) -> dict:
    return {"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"}


def tenable_export_url(base: str) -> str:
    return f"{base.rstrip('/')}/vulns/export"


def tenable_status_url(base: str, export_uuid: str) -> str:
    return f"{base.rstrip('/')}/vulns/export/{export_uuid}/status"


def tenable_chunk_url(base: str, export_uuid: str, chunk: int) -> str:
    return f"{base.rstrip('/')}/vulns/export/{export_uuid}/chunks/{chunk}"


def tenable_export_body(since_epoch: int, num_assets: int = 500) -> str:
    """The export request. ``filters.since`` is EPOCH SECONDS (not ISO) and selects
    findings whose ``last_found`` moved after the watermark."""
    return json.dumps({"num_assets": num_assets,
                       "filters": {"since": since_epoch,
                                   "state": ["OPEN", "REOPENED", "FIXED"]}},
                      sort_keys=True)


def tenable_export_uuid(body: str) -> Optional[str]:
    value = _obj(body).get("export_uuid")
    return value if isinstance(value, str) and value else None


def tenable_export_status(body: str) -> tuple[str, list[int]]:
    """``(status, chunks_available)`` from a status poll.

    Status is upper-cased so the caller compares against one spelling; chunk ids
    are coerced to int and sorted so they stay comparable with the cursor's list.
    """
    obj = _obj(body)
    return str(obj.get("status") or "").strip().upper(), _int_list(obj.get("chunks_available"))


class TenableVulnExportCollector(_VulnCollector):
    name, fmt, label = "tenable", "tenable", "Tenable Vulnerability Management"

    #: Abandon an export still unfinished after this long and request a fresh one
    #: from the SAME watermark, so a job Tenable silently dropped cannot wedge the
    #: collector at one window forever while reporting last_status='ok'.
    export_max_age_seconds: int = 6 * 3600

    def __init__(self, access_key: str, secret_key: str, lookback_hours: int,
                 min_interval_seconds: Optional[int] = None, base_url: str = "",
                 num_assets: int = 500, max_chunks: int = 10):
        super().__init__(lookback_hours, min_interval_seconds)
        self.access_key = access_key
        self.secret_key = secret_key
        self.base = base_url or _TENABLE_BASE
        self.num_assets = num_assets
        self.max_chunks = max_chunks

    def configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def _expired(self, requested: Optional[str], now: datetime) -> bool:
        dt = parse_ts(requested) if requested else None
        return dt is None or (now - dt).total_seconds() > self.export_max_age_seconds

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        headers = tenable_headers(self.access_key, self.secret_key)
        state = parse_cursor(cursor)
        since = state.get("since") or iso_lookback(self.lookback)
        export, requested = state.get("export"), state.get("requested")
        done = _int_list(state.get("done"))

        if export and self._expired(requested, now):
            export, requested, done = None, None, []

        # ── Phase 1: queue an export, then stop. It is asynchronous; the uuid is
        #    parked in the cursor and the next tick resumes at the status poll.
        if not export:
            if not self.due(now):
                return FetchResult("", make_cursor(since=since), 0)
            start = parse_ts(since) or (now - timedelta(hours=self.lookback))
            body = self._http_post(
                tenable_export_url(self.base), headers,
                tenable_export_body(int(start.timestamp()), self.num_assets).encode("utf-8"))
            export = tenable_export_uuid(body)
            if not export:
                raise RuntimeError("no export_uuid in Tenable export response")
            self._last_pull = now
            return FetchResult("", make_cursor(since=since, export=export,
                                               requested=now.isoformat()), 0)

        # ── Phase 2: poll status.
        status, chunks = tenable_export_status(
            self._http_get(tenable_status_url(self.base, export), headers))
        if status in ("ERROR", "CANCELLED"):
            # Release the dead job WITHOUT advancing `since`: the next tick requests
            # a fresh export over the identical window, so no finding is skipped.
            return FetchResult("", make_cursor(since=since), 0)

        pending = [c for c in chunks if c not in done]

        # A FINISHED export with nothing left to drain is DONE — release it and
        # advance the watermark. This has to come BEFORE the "nothing ready yet"
        # return below, and the ordering is the whole bug: with the completion test
        # left further down (at `complete`, after the drain loop), an export was only
        # ever released on a tick that saw FINISHED *and* found an undrained chunk.
        # Two entirely ordinary Tenable behaviours miss that window and wedge the
        # collector for good:
        #   * FINISHED with `chunks_available: []` — what Tenable returns when nothing
        #     matched `filters.since`, i.e. the normal steady state for an hourly poll
        #     against a daily scan cadence. The FIRST quiet window wedges it.
        #   * chunks drained while status was still PROCESSING, then FINISHED on the
        #     next tick with the same chunk list — the ordinary interleaving.
        # Once wedged, `since` never moves: every tick spends a status call, returns 0
        # and records `last_status='ok'`, until `_expired` releases the job six hours
        # later and re-exports the identical window, forever.
        if status == "FINISHED" and not pending:
            return FetchResult("", make_cursor(since=requested or now.isoformat()), 0)

        if not pending:
            return FetchResult("", make_cursor(since=since, export=export,
                                               requested=requested, done=sorted(done)), 0)

        # ── Phase 3: drain the chunks that are ready, up to this run's budget.
        findings: list = []
        for chunk in pending[:self.max_chunks]:
            findings.extend(json_records(
                self._http_get(tenable_chunk_url(self.base, export, chunk), headers)))
            done.append(chunk)

        complete = status == "FINISHED" and not [c for c in chunks if c not in done]
        if complete:
            # The export covered everything up to the moment it was REQUESTED, so
            # that instant is the watermark — not the newest record, which would
            # re-request from a point the export had already passed.
            next_cursor = make_cursor(since=requested or now.isoformat())
        else:
            next_cursor = make_cursor(since=since, export=export,
                                      requested=requested, done=sorted(done))
        content = json.dumps(findings) if findings else ""
        return FetchResult(content, next_cursor, len(findings))


# =========================================================================== #
#  Rapid7 InsightVM — Console API v3 (asset x finding x catalog join)          #
# =========================================================================== #
def r7_headers(username: str, password: str) -> dict:
    return {"Authorization": basic_auth(username, password),
            "Accept": "application/json",
            "Content-Type": "application/json"}


def r7_search_url(base: str, page: int, size: int) -> str:
    """Asset search, sorted by id.

    The sort is load-bearing, not cosmetic: the walk parks a PAGE NUMBER between
    ticks, and page numbers only mean anything over a stable ordering.
    """
    return (f"{base.rstrip('/')}/api/3/assets/search"
            f"?{urlencode({'page': page, 'size': size, 'sort': 'id,asc'})}")


def r7_asset_vulns_url(base: str, asset_id: Any, page: int, size: int) -> str:
    return (f"{base.rstrip('/')}/api/3/assets/{asset_id}/vulnerabilities"
            f"?{urlencode({'page': page, 'size': size})}")


def r7_vuln_url(base: str, vuln_id: str) -> str:
    return f"{base.rstrip('/')}/api/3/vulnerabilities/{vuln_id}"


def r7_search_body(since: Optional[str]) -> str:
    """Assets scanned on or after the watermark.

    InsightVM's ``last-scan-date`` filter takes a DATE, so the watermark is floored
    to its day and the window is deliberately WIDER than the cursor. Re-fetched
    findings are dropped by the events table's unique constraint, which is the same
    trade the Okta collector's inclusive ``since`` already makes.
    """
    dt = parse_ts(since) if since else None
    day = (dt or _now()).astimezone(timezone.utc).strftime("%Y-%m-%d")
    return json.dumps({"match": "all",
                       "filters": [{"field": "last-scan-date",
                                    "operator": "is-on-or-after",
                                    "value": day}]}, sort_keys=True)


def r7_page(body: str) -> tuple[list, int]:
    """``(resources, total_pages)`` from an InsightVM v3 paged response."""
    obj = _obj(body)
    resources = obj.get("resources")
    page = obj.get("page") if isinstance(obj.get("page"), dict) else {}
    total = to_int(page.get("totalPages"))
    return ([r for r in resources if isinstance(r, dict)] if isinstance(resources, list) else [],
            total if total is not None else 1)


def r7_join(asset: dict, finding: dict, vulnerability: dict) -> dict:
    """One finding envelope — the shape ``app/parsers/rapid7.py`` reads.

    InsightVM splits a finding across three resources and none of them is a finding
    on its own: the asset has the identity, the per-asset record has the status and
    proof, and the catalog entry has the title, severity and CVEs.
    """
    return {"asset": asset, "finding": finding, "vulnerability": vulnerability}


class Rapid7InsightVmCollector(_VulnCollector):
    name, fmt, label = "rapid7", "rapid7", "Rapid7 InsightVM"

    def __init__(self, base_url: str, username: str, password: str,
                 lookback_hours: int, min_interval_seconds: Optional[int] = None,
                 page_size: int = 25, max_vuln_lookups: int = 200,
                 cache_limit: int = 5000):
        super().__init__(lookback_hours, min_interval_seconds)
        self.base = base_url
        self.username = username
        self.password = password
        #: Assets per poll AND the parking granularity — ONE asset page per tick.
        #: The console costs a request per asset plus one per unseen vulnerability
        #: id, on a scheduler that is serial with a 30s-per-request ceiling, so the
        #: poll is bounded by the page rather than by the size of the estate.
        self.page_size = page_size
        self.max_vuln_lookups = max_vuln_lookups
        #: Catalog entries live on the INSTANCE, and collectors are built once at
        #: startup, so the id -> {title, severity, cves} join warms up across polls
        #: and steady state costs roughly one request per asset.
        self._vuln_cache: dict[str, dict] = {}
        self.cache_limit = cache_limit
        self._lookups = 0

    def configured(self) -> bool:
        return bool(self.base and self.username and self.password)

    def _vulnerability(self, vuln_id: Any, headers: dict) -> dict:
        """The catalog entry for one vulnerability id, cached and budgeted.

        Returning {} when the budget is spent DEGRADES a finding (no title, no
        severity) but never drops it, and the parser still recovers the CVE from
        the id. The cache is warm on the next poll, so this self-heals.
        """
        if not vuln_id:
            return {}
        key = str(vuln_id)
        if key in self._vuln_cache:
            return self._vuln_cache[key]
        if self._lookups >= self.max_vuln_lookups:
            return {}
        self._lookups += 1
        try:
            entry = _obj(self._http_get(r7_vuln_url(self.base, key), headers))
        except urllib.error.HTTPError as exc:
            # A 404 means the console reported a finding for a check its catalog no
            # longer has. Cache the miss and carry on. Any OTHER status (auth, 5xx)
            # propagates, because the cursor must not advance past a window we
            # could not read — that is what makes delivery at-least-once.
            if exc.code != 404:
                raise
            entry = {}
        if len(self._vuln_cache) < self.cache_limit:
            self._vuln_cache[key] = entry
        return entry

    def _findings(self, asset_id: Any, headers: dict) -> list:
        out: list = []
        for page in range(_MAX_PAGES):
            resources, total_pages = r7_page(self._http_get(
                r7_asset_vulns_url(self.base, asset_id, page, _FINDING_PAGE), headers))
            out.extend(resources)
            if not resources or page + 1 >= total_pages:
                break
        return out

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        state = parse_cursor(cursor)
        since = state.get("since") or iso_lookback(self.lookback)
        page = to_int(state.get("page")) or 0
        resuming = page > 0
        if not resuming and not self.due(now):
            return FetchResult("", make_cursor(since=since), 0)
        # Fixed when the walk STARTS — see the same note on the Qualys collector.
        until = (state.get("until") if resuming else None) or now.isoformat()

        headers = r7_headers(self.username, self.password)
        body = r7_search_body(since).encode("utf-8")
        self._lookups = 0

        assets, total_pages = r7_page(self._http_post(
            r7_search_url(self.base, page, self.page_size), headers, body))

        records: list = []
        for asset in assets:
            asset_id = asset.get("id")
            if asset_id is None:
                continue
            for finding in self._findings(asset_id, headers):
                records.append(r7_join(
                    asset, finding, self._vulnerability(finding.get("id"), headers)))

        self._last_pull = now
        content = json.dumps(records) if records else ""
        if assets and page + 1 < total_pages:
            # More asset pages in this window: park the page number and hold the
            # watermark, so the estate past this page is not silently skipped.
            return FetchResult(content, make_cursor(since=since, until=until,
                                                    page=page + 1), len(records))
        return FetchResult(content, make_cursor(since=until), len(records))

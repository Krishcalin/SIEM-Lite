# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Palo Alto Cortex Data Lake — Prisma Access / cloud-delivered NGFW logs.

Prisma Access does not syslog to you; its logs land in Cortex Data Lake (CDL) and
are read back through the CDL Query Service. Authentication is the Palo Alto
developer-token OAuth2 **refresh-token grant** (not client-credentials, not a
signed JWT), so it needs neither SigV4 nor RS256 — just a form POST.

Reading is a two-step job API:

  1. ``POST /query/v2/jobs``           -> ``{"jobId": "..."}``
  2. ``GET  /query/v2/jobResults/<id>`` -> ``{"state": "DONE",
                                              "page": {"result": {"data": [...]}}}``

THE RESHAPE, AND WHY THERE IS NO THIRD PAN PARSER
-------------------------------------------------
LogOcean already has two Palo Alto parsers and neither is thrown away here.
``paloalto_syslog`` maps by POSITION (a CDL record is a JSON object, so its field
order is meaningless) but ``paloalto_csv`` maps by HEADER NAME, case-insensitively,
over candidate spellings. So a CDL record is re-shaped into a **PAN CSV export
document** — the exact text ``paloalto_csv`` already eats — and this collector's
``fmt`` is the already-registered ``paloalto_csv`` key. Nothing new to parse,
nothing new to keep in step with PAN-OS.

Two details of that reshape are load-bearing for CIM, not cosmetic:

  * The ``Type`` column is stamped from the CDL TABLE that was queried
    (``firewall.traffic`` -> ``TRAFFIC``), never from the record's own ``log_type``
    field — CDL returns that as an enum whose encoding varies. The corrected
    Network clause reads ``raw: [log_type, type, Type]`` as ordered COALESCE
    alternatives, so a record carrying ``log_type: 1`` would win the COALESCE with
    an integer and silently drop PAN traffic out of the Network model. Every
    spelling of ``log_type`` / ``type`` is therefore CONSUMED by the ``Type``
    column and never re-emitted as an extra column.
  * PAN's own convention is that URL / WildFire / Data-filtering records are
    ``Type=THREAT`` with a distinguishing SUBTYPE, and ``paloalto_csv`` puts the
    SUBTYPE in ``log_type``. That is exactly what the corrected registry expects:
    ``end`` / ``deny`` reach Network through the ``raw`` type term, ``vulnerability``
    reaches IDS, ``url`` reaches Web.

Everything is a pure function over plain strings — URL building, the token form,
the query body, the response unwrap and the record -> CSV reshape — so the whole
file is unit-tested with fixture strings, no network and no credentials. The two
thin ``_http_*`` wrappers are the only place a socket is opened.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import quote, urlencode

from ..util import first, parse_ts
from .base import Collector, FetchResult, iso_lookback, max_time_iso

# How many result pages to pull per table in a single run. The scheduler is SERIAL
# on one threadpool thread and each HTTP call may take 30s, so one poll is bounded
# at 1 token + len(tables) * (1 submit + _MAX_PAGES results) requests.
_MAX_PAGES = 5
_PAGE_SIZE = 1000
# How long a jobResults GET may block server-side waiting for the job (ms).
_MAX_WAIT_MS = 10000

#: Palo Alto developer-token endpoint — the same host for every CDL region.
_TOKEN_URL = "https://api.paloaltonetworks.com/api/oauth2/RequestToken"

#: CDL region -> Query Service API host. Both the friendly name and the two-letter
#: code are accepted because operators copy either out of the CDL console.
_CDL_HOSTS = {
    "americas": "api.us.cdl.paloaltonetworks.com",
    "us": "api.us.cdl.paloaltonetworks.com",
    "europe": "api.nl.cdl.paloaltonetworks.com",
    "nl": "api.nl.cdl.paloaltonetworks.com",
    "uk": "api.uk.cdl.paloaltonetworks.com",
    "singapore": "api.sg.cdl.paloaltonetworks.com",
    "sg": "api.sg.cdl.paloaltonetworks.com",
    "japan": "api.jp.cdl.paloaltonetworks.com",
    "jp": "api.jp.cdl.paloaltonetworks.com",
    "australia": "api.au.cdl.paloaltonetworks.com",
    "au": "api.au.cdl.paloaltonetworks.com",
    "canada": "api.ca.cdl.paloaltonetworks.com",
    "ca": "api.ca.cdl.paloaltonetworks.com",
    "germany": "api.de.cdl.paloaltonetworks.com",
    "de": "api.de.cdl.paloaltonetworks.com",
    "india": "api.in.cdl.paloaltonetworks.com",
    "in": "api.in.cdl.paloaltonetworks.com",
}
_DEFAULT_REGION = "americas"

#: CDL tables polled when nothing is configured — the Prisma Access security core.
#: `firewall.system` and `firewall.config` are deliberately NOT here: `paloalto_csv`
#: has no SYSTEM/CONFIG special-casing (only `paloalto_syslog` rewrites log_type to
#: `system` / `config` and keeps `raw["subtype"]`), so a CDL system record would
#: arrive with log_type=`general` and miss the Change model's PAN clause. They can
#: still be configured; that gap is a `models.yaml` question for the CIM owner, not
#: something this reshape may paper over by inventing a `type` raw key — that key is
#: the first alternative of the Network clause's COALESCE.
_DEFAULT_TABLES = ("firewall.traffic", "firewall.threat", "firewall.url")
#: A table name reaches a SQL string, so it is whitelisted rather than escaped.
_TABLE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")

#: CDL table leaf -> the PAN log TYPE its records carry. PAN files URL / WildFire /
#: data-filtering records under Type=THREAT with a distinguishing subtype, which is
#: what `paloalto_csv` (and therefore the CIM registry) expects to see.
_TABLE_TYPES = {
    "traffic": "TRAFFIC",
    "threat": "THREAT",
    "url": "THREAT",
    "wildfire": "THREAT",
    "file_data": "THREAT",
    "data_filtering": "THREAT",
    "system": "SYSTEM",
    "config": "CONFIG",
    "auth": "AUTHENTICATION",
    "authentication": "AUTHENTICATION",
    "decryption": "DECRYPTION",
    "globalprotect": "GLOBALPROTECT",
    "hipmatch": "HIPMATCH",
}

#: PAN CSV-export column -> the CDL field spellings that feed it, best first.
#: EVERY listed spelling is consumed, so no alternative can reappear as an extra
#: column and hijack a CIM COALESCE (see the module docstring on `Type`).
#: The column names are the ones `app/parsers/paloalto_csv.py:_g` looks up.
_COLUMNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Receive Time", ("receive_time", "receivetime", "cdl_receive_time")),
    ("Generate Time", ("time_generated", "timegenerated", "generated_time", "event_time")),
    ("Type", ("log_type", "type", "logtype")),
    ("Threat/Content Type", ("sub_type", "subtype", "log_subtype")),
    ("Severity", ("severity",)),
    ("Action", ("action",)),
    ("Source address", ("source_ip", "src_ip", "sourceip", "source_address")),
    ("Destination address", ("dest_ip", "dst_ip", "destination_ip", "destip", "dest_address")),
    ("Source Port", ("source_port", "src_port", "sport")),
    ("Destination Port", ("dest_port", "dst_port", "dport")),
    ("IP Protocol", ("protocol", "ip_protocol", "proto")),
    ("Application", ("app", "application")),
    ("Source User", ("source_user", "src_user", "user", "user_name")),
    ("Device Name", ("device_name", "devicename", "serial", "serial_number")),
    ("Rule", ("rule", "rule_name", "rule_matched")),
    ("Bytes", ("bytes", "bytes_total", "byte_count")),
    ("Threat/Content Name", ("threat_name", "threat_id", "threatid")),
    ("URL", ("url", "url_domain", "misc", "filename", "file_name")),
    ("Category", ("category", "url_category", "category_of_threatid")),
)
_CANON = tuple(c for c, _ in _COLUMNS)
_CANON_LOWER = {c.lower() for c in _CANON}
_CONSUMED = {n for _, names in _COLUMNS for n in names}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _oldest(marks: list[Optional[str]], fallback: str) -> str:
    """The OLDEST of several per-table watermarks — the next shared checkpoint.

    THE MINIMUM, NOT THE MAXIMUM, and the difference is silent data loss. Each table
    is queried and truncated independently (`LIMIT 1000` per job), but the collector
    parks ONE cursor for all of them. Taking the maximum over the union let a
    low-volume table that reached the window end drag the checkpoint past a
    high-volume table's cut-off point, and every row in that gap was skipped for
    good — the next poll's `WHERE time_generated BETWEEN start AND end` begins after
    them. That fires on the shipped default `_DEFAULT_TABLES`, where `firewall.traffic`
    outruns `firewall.threat`/`firewall.url` by orders of magnitude.

    The minimum costs re-reading rows the drained tables already returned; `dedup_hash`
    collapses those on insert. Duplicated work is recoverable, a skipped window is not.

    (Bound worth knowing: if a truncated table's whole page shares one `time_generated`,
    its mark equals `since` and that table cannot advance. `BETWEEN` is inclusive, so
    the poll repeats rather than skipping — stalled, never lossy.)
    """
    best: Optional[datetime] = None
    for mark in marks:
        dt = parse_ts(mark) if mark else None
        if dt is not None and (best is None or dt < best):
            best = dt
    return best.isoformat() if best else fallback


def _epoch(iso_or_none: Optional[str], fallback: datetime) -> int:
    """A stored cursor as epoch seconds.

    ``util.parse_ts`` reads both cursor spellings this column holds — the
    ``...T00:00:00.000Z`` that ``iso_lookback`` writes on the first run and the
    ``...+00:00`` that ``max_time_iso`` writes afterwards — so the window is
    identical either way and no query-string escaping is involved."""
    dt = parse_ts(iso_or_none) if iso_or_none else None
    return int((dt or fallback).timestamp())


# --------------------------------------------------------------------------- #
#  OAuth2 refresh-token grant                                                  #
# --------------------------------------------------------------------------- #
def cdl_token_form(client_id: str, client_secret: str, refresh_token: str) -> str:
    """The ``application/x-www-form-urlencoded`` body of a refresh-token grant."""
    return urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    })


def cdl_access_token(body: str) -> Optional[str]:
    try:
        return json.loads(body).get("access_token")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
#  Query Service URLs + bodies                                                 #
# --------------------------------------------------------------------------- #
def cdl_host(region: str) -> str:
    """Resolve a CDL region to its Query Service host.

    An empty region means the default (americas); a value containing a dot is
    taken as a literal hostname (private/preview endpoints). An unknown name
    RAISES rather than silently defaulting: querying the wrong region returns a
    perfectly valid empty result set forever, which is indistinguishable from
    "nothing happened" in the collector status."""
    r = (region or "").strip().lower().rstrip("/")
    if not r:
        return _CDL_HOSTS[_DEFAULT_REGION]
    if "." in r:
        return r.split("//")[-1].strip("/")
    host = _CDL_HOSTS.get(r)
    if not host:
        raise ValueError(f"unknown Cortex Data Lake region: {region!r}")
    return host


def cdl_query_url(host: str) -> str:
    return f"https://{host}/query/v2/jobs"


def cdl_results_url(host: str, job_id: str, page: int = 0) -> str:
    return (f"https://{host}/query/v2/jobResults/{quote(job_id, safe='')}"
            f"?maxWait={_MAX_WAIT_MS}&pageNumber={page}&pageSize={_PAGE_SIZE}")


def cdl_tables(spec: str) -> tuple[str, ...]:
    """Parse the configured comma-separated table list.

    A name that is not a bare dotted identifier is dropped (it would otherwise be
    interpolated into the query string); an empty or fully-invalid list falls back
    to the shipped default."""
    names = tuple(t.strip() for t in (spec or "").split(",") if t.strip())
    valid = tuple(t for t in names if _TABLE_RE.match(t))
    return valid or _DEFAULT_TABLES


def cdl_query_body(table: str, start_epoch: int, end_epoch: int,
                   limit: int = _PAGE_SIZE) -> str:
    """The job-submission body for one table over one time window.

    ``table`` is re-validated here even though ``cdl_tables`` already filtered it:
    this is the function that puts it into a SQL string, so it is the function
    that must refuse anything but a dotted identifier."""
    if not _TABLE_RE.match(table or ""):
        raise ValueError(f"unsafe Cortex Data Lake table name: {table!r}")
    sql = (f"SELECT * FROM `{table}` "
           f"WHERE time_generated BETWEEN {int(start_epoch)} AND {int(end_epoch)} "
           f"ORDER BY time_generated ASC LIMIT {int(limit)}")
    return json.dumps({"query": sql,
                       "startTime": int(start_epoch),
                       "endTime": int(end_epoch)})


def cdl_job_id(body: str) -> Optional[str]:
    """The ``jobId`` of a submitted query, or None if the response is not one."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    job = obj.get("jobId") or obj.get("job_id")
    return job if isinstance(job, str) and job else None


def cdl_page_records(body: str) -> tuple[list, Optional[str]]:
    """Unwrap one jobResults page -> (records, job state).

    The records live at ``page.result.data``; the state is ``RUNNING`` / ``DONE`` /
    ``FAILED``. Anything unexpected yields ``([], None)`` so a malformed page
    behaves like an empty one rather than raising mid-walk."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return [], None
    if not isinstance(obj, dict):
        return [], None
    data: list = []
    page = obj.get("page")
    if isinstance(page, dict):
        result = page.get("result")
        if isinstance(result, dict) and isinstance(result.get("data"), list):
            data = [r for r in result["data"] if isinstance(r, dict)]
    state = obj.get("state")
    return data, state if isinstance(state, str) else None


# --------------------------------------------------------------------------- #
#  CDL record -> PAN CSV export row                                            #
# --------------------------------------------------------------------------- #
def cdl_table_type(table: str) -> str:
    """The PAN log TYPE a CDL table holds (``firewall.url`` -> ``THREAT``)."""
    leaf = (table or "").strip().rsplit(".", 1)[-1].lower()
    return _TABLE_TYPES.get(leaf, leaf.upper())


def _cell(value: Any) -> str:
    """One CSV cell. A nested CDL object/array is JSON-encoded rather than dropped
    so it stays searchable in ``raw``; None becomes the empty cell that
    ``paloalto_csv._g`` skips."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


def cdl_row(rec: dict, log_type: str = "") -> dict:
    """One CDL record as a PAN CSV-export row.

    The canonical columns come first (mapped from the CDL field spellings), then
    every field that no column consumed, under its own name — so a Prisma Access
    field like ``tunnel_id`` or ``source_location`` still reaches ``raw`` and the
    jsonb index instead of being silently discarded.

    ``log_type`` (the TYPE derived from the queried table) OVERRIDES whatever the
    record carries: see the module docstring."""
    low = {str(k).strip().lower(): v for k, v in rec.items() if k is not None}
    row: dict[str, str] = {}
    for column, names in _COLUMNS:
        row[column] = _cell(first(*(low.get(n) for n in names)))
    if log_type:
        row["Type"] = log_type
    for key in sorted(low):
        if key in _CONSUMED or key in _CANON_LOWER:
            continue
        row[key] = _cell(low[key])
    return row


def cdl_csv(rows: list) -> str:
    """Rows -> a PAN CSV-export document, or ``""`` when there is nothing.

    The header is the canonical columns in their fixed order followed by the union
    of every row's extra fields, sorted — deterministic for a given batch, and a
    single header row over mixed log types (a missing value is simply an empty
    cell, which ``paloalto_csv`` already skips).

    Returning ``""`` rather than a header-only document is deliberate:
    ``run_collector`` skips ingest entirely on empty content but still advances the
    cursor, whereas a header-only string would ingest a zero-row batch on every
    idle poll forever."""
    if not rows:
        return ""
    extras = sorted({k for r in rows for k in r} - set(_CANON))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(_CANON) + extras,
                            restval="", lineterminator="\n")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
#  Collector                                                                   #
# --------------------------------------------------------------------------- #
class CortexDataLakeCollector(Collector):
    """Prisma Access / cloud NGFW logs out of Cortex Data Lake, fed to `paloalto_csv`."""

    name, fmt, label = ("cortex_data_lake", "paloalto_csv",
                        "Palo Alto Cortex Data Lake (Prisma Access)")

    def __init__(self, region: str, client_id: str, client_secret: str,
                 refresh_token: str, tables: str, lookback_hours: int):
        # The region is kept raw, not resolved: __init__ runs for every candidate in
        # build_collectors() and must never raise. A bad region surfaces from fetch()
        # as last_status="error" with the offending value in the message.
        self.region = region
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.tables = cdl_tables(tables)
        self.lookback = lookback_hours

    def configured(self) -> bool:
        # Region and tables both have defaults, so only the OAuth triple is required.
        return bool(self.client_id and self.client_secret and self.refresh_token)

    # -- the only three methods that touch the network ---------------------- #
    def _token(self) -> str:
        body = self._http_post(
            _TOKEN_URL,
            {"Content-Type": "application/x-www-form-urlencoded",
             "Accept": "application/json"},
            cdl_token_form(self.client_id, self.client_secret,
                           self.refresh_token).encode("utf-8"))
        token = cdl_access_token(body)
        if not token:
            raise RuntimeError("no access_token in Cortex Data Lake token response")
        return token

    def _post(self, token: str, url: str, body: str) -> str:
        return self._http_post(url,
                               {"Authorization": f"Bearer {token}",
                                "Content-Type": "application/json",
                                "Accept": "application/json"},
                               body.encode("utf-8"))

    def _get(self, token: str, url: str) -> str:
        return self._http_get(url, {"Authorization": f"Bearer {token}",
                                    "Accept": "application/json"})

    # -- the pull ------------------------------------------------------------ #
    def fetch(self, cursor: Optional[str]) -> FetchResult:
        now = _now()
        since_iso = cursor or iso_lookback(self.lookback)
        start = _epoch(cursor, now - timedelta(hours=self.lookback))
        end = int(now.timestamp())
        host = cdl_host(self.region)
        token = self._token()

        records: list = []
        rows: list = []
        # Watermarks of the tables that were CUT OFF, if any. The checkpoint is a
        # SINGLE instant shared by every table, so it may not advance past the oldest
        # of these — see `_oldest`. A table that drained contributes nothing here: it
        # constrains nothing, and letting it do so would freeze the cursor on any
        # permanently quiet table.
        marks: list[Optional[str]] = []

        for table in self.tables:
            job = cdl_job_id(self._post(token, cdl_query_url(host),
                                        cdl_query_body(table, start, end)))
            if not job:
                continue
            log_type = cdl_table_type(table)
            state: Optional[str] = None
            table_recs: list = []
            for page in range(_MAX_PAGES):
                recs, state = cdl_page_records(
                    self._get(token, cdl_results_url(host, job, page)))
                if state == "FAILED":
                    # Raise, never swallow: run_collector turns this into
                    # last_status="error" and leaves the cursor untouched, so the
                    # window is retried instead of being skipped.
                    raise RuntimeError(
                        f"Cortex Data Lake query failed for {table} (job {job})")
                table_recs.extend(recs)
                rows.extend(cdl_row(r, log_type) for r in recs)
                if len(recs) < _PAGE_SIZE:
                    break
            if state is not None and state != "DONE":
                # Still RUNNING when we stopped reading: the rows this job had not
                # materialized yet are NOT in `records`, so advancing the cursor here
                # would skip them for good. Raise and retry the same window instead.
                # `None` means the response carried no state at all — unknowable, so
                # it is treated as a normal short read rather than a failure.
                raise RuntimeError(
                    f"Cortex Data Lake query for {table} ended in state {state!r}")

            records.extend(table_recs)
            # A table that came back holding the full SQL `LIMIT` was CUT OFF: rows
            # newer than its last fetched one exist in CDL and were not read. Because
            # `cdl_query_body` sorts `ORDER BY time_generated ASC`, that last fetched
            # row is exactly where this table must resume from.
            if len(table_recs) >= _PAGE_SIZE:
                marks.append(max_time_iso(table_recs, "time_generated", since_iso))

        content = cdl_csv(rows)
        # Nothing was truncated -> every table was drained and the union maximum is a
        # sound watermark (and, on an idle poll, `max_time_iso` holds the cursor where
        # it was rather than jumping it to `now` over rows CDL has not materialised
        # yet). Something WAS truncated -> the checkpoint may only reach the oldest
        # cut-off point, or the busy table's tail is skipped for good.
        next_cursor = (_oldest(marks, since_iso) if marks
                       else max_time_iso(records, "time_generated", since_iso))
        return FetchResult(content, next_cursor, len(rows))

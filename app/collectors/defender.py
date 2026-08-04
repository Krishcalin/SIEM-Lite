# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Microsoft Defender XDR collectors — Graph Security alerts (``alerts_v2``) and
Microsoft 365 Defender incidents.

Both endpoints live on Microsoft Graph behind the SAME app registration and the
SAME OAuth2 client-credentials flow the Entra sign-in collector already uses, so
this module re-uses ``cloud._MicrosoftCollector`` wholesale rather than
re-deriving the token dance: it only contributes URL builders, a page unwrapper
and a paging loop, all of them pure or one thin ``_http_get`` deep.

  * alerts     ``/security/alerts_v2``  -> ``{"value": [...]}``  -> defender_xdr
  * incidents  ``/security/incidents``  -> ``{"value": [...]}``  -> defender_xdr

Both are windowed on ``lastUpdateDateTime`` rather than ``createdDateTime``, and
that choice is deliberate: a Defender alert is MUTABLE — its status,
classification, determination and evidence keep changing through triage. Cursoring
on the update stamp means a resumed run re-fetches the alerts whose state moved
(and only those), which is what keeps a resolved alert from sitting in LogOcean
forever as "new". Re-ingesting an unchanged alert is free: ``ingest`` SHA-256s the
batch and ``normalize.dedup_hash`` hashes the record, so an unchanged body adds no
rows.

Paging follows Graph's ``@odata.nextLink`` (an absolute URL that already carries
the ``$skiptoken``), bounded by ``_MAX_PAGES`` so one poll cannot hold the serial
scheduler thread indefinitely.
"""
from __future__ import annotations

import json
from typing import Optional
from urllib.parse import quote

from ..util import parse_ts
from .base import (FetchResult, iso_lookback, make_cursor, max_time_iso,
                   parse_cursor)
from .cloud import _MicrosoftCollector

# How many `@odata.nextLink` hops to follow in a single run (bounds one poll).
_MAX_PAGES = 20

_GRAPH = "https://graph.microsoft.com/v1.0/security"
_ALERTS_PATH = f"{_GRAPH}/alerts_v2"
_INCIDENTS_PATH = f"{_GRAPH}/incidents"

#: The checkpoint field. Both an alert and an incident carry it.
CURSOR_FIELD = "lastUpdateDateTime"


def graph_filter_time(value: Optional[str]) -> str:
    """Normalize a cursor to an OData UTC literal (``2026-06-25T11:30:00.000Z``).

    The cursor column is MIXED-FORMAT by construction: ``iso_lookback`` writes
    ``...T00:00:00.000Z`` on the first run and ``max_time_iso`` writes
    ``datetime.isoformat()`` (``...+00:00``) on every run after. Normalizing here
    means the ``+`` never reaches a query string in the first place — an
    unescaped one decodes as a space and silently shifts the window by the offset.
    Unparseable input is passed through untouched rather than guessed at.
    """
    dt = parse_ts(value) if value else None
    if dt is None:
        return str(value or "")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def updated_since_filter(since_iso: Optional[str]) -> str:
    """The OData ``$filter`` selecting records touched after the cursor."""
    return f"{CURSOR_FIELD} gt {graph_filter_time(since_iso)}"


def alerts_url(since_iso: Optional[str], top: int = 200) -> str:
    """Graph ``alerts_v2`` listing for everything updated after the cursor.

    No ``$orderby``: ``max_time_iso`` takes the maximum over the whole batch, so
    ordering buys nothing and only risks a 400 from an endpoint that does not
    support it on this collection.
    """
    return (f"{_ALERTS_PATH}?$top={int(top)}"
            f"&$filter={quote(updated_since_filter(since_iso))}")


def incidents_url(since_iso: Optional[str], top: int = 50,
                  expand_alerts: bool = False) -> str:
    """Graph ``incidents`` listing for everything updated after the cursor.

    ``expand_alerts`` pulls each incident's alerts inline. It is OFF by default
    because it makes every incident page an order of magnitude heavier and,
    when the alert collector is also enabled, fetches the same alerts twice.
    """
    url = (f"{_INCIDENTS_PATH}?$top={int(top)}"
           f"&$filter={quote(updated_since_filter(since_iso))}")
    return f"{url}&$expand=alerts" if expand_alerts else url


def graph_page(body: str) -> tuple[list, Optional[str]]:
    """Unwrap one Graph collection page -> (records, next_link).

    ``@odata.nextLink`` is absolute and already carries the skiptoken, so the
    caller follows it verbatim instead of rebuilding the query.
    """
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return [], None
    if not isinstance(obj, dict):
        return [], None
    value = obj.get("value")
    nxt = obj.get("@odata.nextLink")
    return ((value if isinstance(value, list) else []),
            (nxt if isinstance(nxt, str) and nxt else None))


class _DefenderCollector(_MicrosoftCollector):
    """Shared paging for the two Defender XDR Graph collections.

    Subclasses contribute ``name`` and :meth:`first_url` only — everything else
    (token, paging, cursor, empty-batch guard) is identical between them.
    """

    fmt = "defender_xdr"
    scope = "https://graph.microsoft.com/.default"
    page_size = 200

    def first_url(self, since_iso: str) -> str:      # pragma: no cover - overridden
        raise NotImplementedError

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        state = parse_cursor(cursor)
        since = state.get("since") or iso_lookback(self.lookback)
        resume = str(state.get("next") or "")
        token = self._token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        records: list = []
        url: Optional[str] = resume or self.first_url(since)
        for page_no in range(_MAX_PAGES):
            try:
                body = self._http_get(url, headers)
            except Exception:                       # noqa: BLE001
                # A parked @odata.nextLink whose skiptoken has aged out. `since` was
                # never advanced past the point the walk stopped, so restarting from
                # it re-reads and loses nothing. Only the FIRST hop is retried this
                # way — a failure mid-walk is a real error and belongs to the caller.
                if page_no or not resume:
                    raise
                url = self.first_url(since)
                body = self._http_get(url, headers)
            page, url = graph_page(body)
            records.extend(page)
            if not url:
                break

        # "" rather than '{"value": []}' on an idle poll: `run_collector` skips
        # ingest entirely for empty content but still advances the cursor, so an
        # idle collector creates no batch rows at all.
        content = json.dumps({"value": records}) if records else ""

        if url:
            # THE WALK WAS CUT SHORT at _MAX_PAGES with pages still waiting. Park the
            # continuation and leave `since` exactly where it was; the next poll picks
            # up at this skiptoken instead of re-deriving the window.
            #
            # Advancing the watermark here was a silent deletion. The next poll's
            # `$filter` is `lastUpdateDateTime gt <cursor>`, so every record on an
            # unread page stamped OLDER than the maximum of the pages we did read
            # became permanently unreachable. `alerts_url` deliberately sends no
            # `$orderby` — which is what would have made a max-over-what-was-read a
            # valid watermark — and Graph documents no default order for alerts_v2,
            # with newest-first being the common behaviour. Under that, the very first
            # page pinned the cursor at the newest alert in the tenant and pages 21+
            # were erased. Any first run or post-outage backfill past 20 x $top
            # reaches it: 4,000 alerts, 1,000 incidents.
            #
            # Parking the token fixes it without depending on server-side ordering at
            # all, which is why it is preferred over adding an $orderby that Graph may
            # answer with a 400.
            return FetchResult(content, make_cursor(since=since, next=url), len(records))

        return FetchResult(content,
                           make_cursor(since=max_time_iso(records, CURSOR_FIELD, since)),
                           len(records))


class DefenderAlertCollector(_DefenderCollector):
    """Graph Security ``alerts_v2`` — Defender for Endpoint / Identity /
    Office 365 / Cloud Apps alerts, in one unified schema."""

    name = "defender_alerts"
    label = "Microsoft Defender XDR — alerts"
    page_size = 200

    def first_url(self, since_iso: str) -> str:
        return alerts_url(since_iso, self.page_size)


class DefenderIncidentCollector(_DefenderCollector):
    """Microsoft 365 Defender incidents — the correlation object over alerts."""

    name = "defender_incidents"
    label = "Microsoft Defender XDR — incidents"
    page_size = 50

    def __init__(self, tenant: str, client_id: str, client_secret: str,
                 lookback_hours: int, expand_alerts: bool = False):
        super().__init__(tenant, client_id, client_secret, lookback_hours)
        self.expand_alerts = bool(expand_alerts)

    def first_url(self, since_iso: str) -> str:
        return incidents_url(since_iso, self.page_size, self.expand_alerts)

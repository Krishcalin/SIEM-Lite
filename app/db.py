# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""PostgreSQL access layer: pool, schema/partition management, insert, search,
stats, batch tracking, and retention purge."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

# These imports do NOT parse models.yaml. `registry.get_registry()` is lazy and caches
# on first call, so after `import app.db` the registry cache is still empty and a
# malformed models.yaml has not been detected — this module used to claim the opposite.
# Validation is an explicit startup step instead (`validate_cim_registry`, called by the
# app lifespan before anything is served), and the write path degrades rather than
# raising. See the "CIM registry" section below for why that split is the only shape
# that cannot lose an event.
from .cim import sql as cim_sql
from .cim.match import cim_models_for
from .cim.registry import _REGISTRY_PATH as _REGISTRY_FILE, get_registry, load as load_registry
from .cim.spec import CimRegistry
from .config import settings
from .models import NormalizedEvent
from .normalize import dedup_hash, tsv_text
from .ot import OT_PROTOCOLS
from .risk import ENTITY_COLUMN, weight_case_sql
from .severity import max_severity
from .util import hash_api_key, to_port

log = logging.getLogger("logocean")

_pool: Optional[ConnectionPool] = None
_SCHEMA = (Path(__file__).resolve().parent.parent / "schema.sql").read_text(encoding="utf-8")

_INSERT = """
INSERT INTO events (event_time, vendor, product, log_type, severity, action,
    src_ip, dst_ip, src_port, dst_port, protocol, app, user_name, host_name,
    rule_name, bytes_total, message, raw, search_tsv, cim_models, batch_id, dedup_hash)
VALUES (%(event_time)s, %(vendor)s, %(product)s, %(log_type)s, %(severity)s, %(action)s,
    %(src_ip)s::inet, %(dst_ip)s::inet, %(src_port)s, %(dst_port)s, %(protocol)s, %(app)s,
    %(user_name)s, %(host_name)s, %(rule_name)s, %(bytes_total)s, %(message)s,
    %(raw)s, to_tsvector('simple', %(tsv)s), %(cim_models)s::text[],
    %(batch_id)s, %(dedup_hash)s)
ON CONFLICT (dedup_hash, event_time) DO NOTHING
"""

_SEARCH_COLS = """id, event_time, vendor, product, log_type, severity, action,
    host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port,
    protocol, app, user_name, host_name, rule_name, bytes_total, message"""


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(settings.db_dsn, min_size=1, max_size=10, open=True,
                               kwargs={"row_factory": dict_row})
    return _pool


def split_statements(script: str) -> list[str]:
    """Cut a SQL script into executable statements. Pure — no database, so the split
    itself is unit-testable.

    psycopg sends one statement per `execute`, so schema.sql has to be cut on `;`.

    CORRECTING THE RECORD. An earlier version of this docstring said the naive
    `script.split(";")` had been silently truncating this schema — a `;` inside a `--`
    comment cutting the comment in half and leaving bare SQL text at the head of the next
    chunk, after which every table "was never created". That never happened. Both
    implementations yield the SAME 77 executable statements over today's schema.sql, and
    the executable SQL (comments stripped) is IDENTICAL. No table has ever gone missing
    here, and nothing downstream should be read as evidence that one did.

    Being exact about it, because the near-miss is the reason the scanner earns its keep:
    the two are NOT byte-identical. schema.sql has a `;` inside a `--` comment in two
    places (the api_keys and alerts headers), and there the naive split does cut the
    comment in half — the tail is simply re-attached to the front of the next chunk
    instead of the back of the previous one. It stays harmless only because both
    semicolons happen to be the LAST character on their line, so the orphaned tail starts
    at a newline and the following line still opens with `--`. That is a property of how
    those two sentences were typed, not of the schema. Write "-- note: use a; not b" with
    the semicolon mid-line and the tail ` not b` lands as bare text at the head of the
    next chunk, which then fails to parse — and it would fail in the integration job
    only, historically the least trustworthy job in this repo.

    So the scanner is a guard against the next hand edit rather than a repair of a past
    one. It tracks the two contexts where a `;` is not a terminator: inside a
    single-quoted literal (including the `''` escape) and inside a `--` line comment.
    Chunks with no executable text (only comments) are dropped rather than sent as empty
    queries.

    KNOWN GAPS — none of them reachable from today's schema.sql, all of them cheap to
    hit with an ordinary edit:

    * `$$ … $$` / `$tag$ … $tag$` dollar quoting is not tracked, so a function body or a
      DO block containing a `;` would be cut apart. The schema declares neither.
    * `/* … */` block comments are not tracked either (and nothing anywhere in the repo
      mentioned this before): a `;` inside one terminates a statement, and the `--` and
      `'` scanning inside such a comment is not suppressed. The schema uses only `--`.
    * `E'…'` escape-string literals treat `\\'` as an escaped quote where this scanner
      sees the literal ending. The schema has no `E''` strings.

    Any of the three is a reason to reach for a real parser rather than to extend this
    one; until then, keep schema.sql inside the subset above.
    """
    stmts: list[str] = []
    buf: list[str] = []
    has_code = False
    in_str = in_comment = False
    i, n = 0, len(script)
    while i < n:
        ch = script[i]
        if in_comment:
            in_comment = ch != "\n"
            buf.append(ch)
        elif in_str:
            buf.append(ch)
            if ch == "'":
                if script[i + 1:i + 2] == "'":     # '' is an escaped quote, not the end
                    buf.append("'")
                    i += 1
                else:
                    in_str = False
        elif script[i:i + 2] == "--":
            in_comment = True
            buf.append(ch)
        elif ch == ";":
            if has_code:
                stmts.append("".join(buf).strip())
            buf, has_code = [], False
        else:
            if ch == "'":
                in_str = True
            has_code = has_code or not ch.isspace()
            buf.append(ch)
        i += 1
    if has_code:
        stmts.append("".join(buf).strip())
    return stmts


def init_schema() -> None:
    """Run schema.sql (split into statements; no functions/DO blocks present)."""
    with pool().connection() as conn:
        for stmt in split_statements(_SCHEMA):
            conn.execute(stmt)
        conn.commit()


# --------------------------------------------------------------------------- #
#  Partition management                                                        #
# --------------------------------------------------------------------------- #
def ensure_partitions(conn, months: Iterable[tuple[int, int]]) -> None:
    for year, month in sorted(set(months)):
        start = dt.date(year, month, 1)
        end = dt.date(year + 1, 1, 1) if month == 12 else dt.date(year, month + 1, 1)
        name = f"events_{year:04d}{month:02d}"
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF events "
            f"FOR VALUES FROM (%s) TO (%s)", (start, end))


# --------------------------------------------------------------------------- #
#  CIM registry: startup validation, and a write path that cannot lose an event #
# --------------------------------------------------------------------------- #
# `_row` derives `events.cim_models` from the registry, and `registry.get_registry()`
# parses models.yaml LAZILY — nothing loads it at import. Two rules follow, and together
# they are the whole design:
#
#  1. STARTUP VALIDATES, AND REFUSES TO BOOT. `validate_cim_registry()` is called by the
#     app lifespan before anything is served, UNCONDITIONALLY — including under
#     CIM_ENABLED=false, because that flag gates the `cim_<tag>` VIEWS only and never the
#     per-row stamp. models.yaml ships with the repo, so a registry that will not parse
#     is a deploy error; failing at boot with the YAML author's own message is the honest
#     response, and it is the only signal that arrives before any data is at stake.
#
#  2. THE WRITE PATH DEGRADES AND NEVER RAISES. If the registry breaks after boot — an
#     operator edits the YAML and calls `cim.reload()`, a test clears the cache — then
#     `_cim_tags` stores the event with `cim_models = NULL` and records the failure
#     instead of aborting the insert. That is not a nicety. `streaming._flush` catches
#     every exception out of the write and DISCARDS the buffered batch, so a `_row` that
#     raises turns one bad YAML file into permanent, silent loss of every syslog and API
#     event for as long as it stays broken. An untagged row is visible (/health, the log,
#     `cim_write_state`) and repairable (`backfill_cim`); a dropped event is neither.
#
# The trade this reverses was argued the other way before: an event stored with the
# wrong tags is "silent, durable corruption", so the write path should fail loudly. The
# first half is true, which is why the failure is counted and surfaced; the conclusion
# was not, because the loud failure lands in a caller that answers it by throwing the
# events away.

_cim_write_state: dict[str, Any] = {"failures": 0, "error": None, "since": None}


def cim_write_state() -> dict[str, Any]:
    """How the ingest-time CIM stamp is faring — the snapshot /health reports.

    `failures` counts EVENTS stored without their model tags since the last reset (not
    incidents), `error` is the most recent message and `since` the first occurrence. Any
    non-zero count means rows in the store are untagged, every data model under-reports
    them, and a `backfill_cim` is owed once models.yaml is fixed.
    """
    return dict(_cim_write_state)


def reset_cim_write_state() -> None:
    """Clear the degraded-write counters (after fixing the registry; used by tests)."""
    _cim_write_state.update(failures=0, error=None, since=None)


def _cim_tags(evt: NormalizedEvent,
              tags: Optional[Iterable[str]] = None) -> Optional[list[str]]:
    """`cim_models_for(evt)`, downgraded to NULL when the registry cannot be evaluated.

    `match.tags_for` never raises on a malformed EVENT; it does raise on a malformed
    REGISTRY, which is exactly the failure that must not reach the caller — see rule 2
    above. Logged in full the first time and then every thousandth event, so a registry
    broken for an hour costs a bounded number of log lines instead of one per event.

    `tags` is this event's ALREADY-RESOLVED membership, threaded in by
    `pipeline.write_stream` so the registry walk happens once per ingested event instead
    of twice (the detection `datamodels:` gate wants the same value as the event streams).
    `cim_models_for` only canonicalizes it — no registry is touched — so a threaded value
    cannot reach the degrade branch below, which is correct: the walk it would have
    failed in already happened, in the pipeline.

    NOTE the deliberate asymmetry with the pipeline. When the pipeline's own resolution
    raises it threads `None` rather than an empty set, so the event arrives here
    unresolved, this function re-derives it, and the failure lands in `_cim_write_state`.
    That is the ONLY thing keeping /health's untagged counter honest: a pipeline that
    boxed its own failure would hand over a confident `frozenset()` and every row would
    go in untagged while the counter read zero.
    """
    try:
        return cim_models_for(evt, tags=tags)
    except Exception as exc:                  # noqa: BLE001 — storing beats discarding
        first = _cim_write_state["failures"] == 0
        _cim_write_state["failures"] += 1
        _cim_write_state["error"] = f"{type(exc).__name__}: {exc}"
        if first:
            _cim_write_state["since"] = dt.datetime.now(dt.timezone.utc)
            log.exception(
                "CIM membership could not be derived; events are being STORED WITH NO "
                "cim_models rather than dropped. Every data model under-reports until "
                "app/cim/models.yaml is fixed and db.backfill_cim() has re-derived the "
                "affected rows")
        elif _cim_write_state["failures"] % 1000 == 0:
            log.error("CIM membership still unavailable: %d events stored untagged (%s)",
                      _cim_write_state["failures"], _cim_write_state["error"])
        return None


def validate_cim_registry() -> CimRegistry:
    """Parse + validate app/cim/models.yaml eagerly. Raises on a malformed registry.

    This is rule 1 above, and it is the ONLY eager load in the process: everything else
    (`_row`, `init_cim`, the LOQL `datamodel:` compiler, `detection.engine._cim`) reaches
    the registry through the lazy cached `get_registry()`. Calling it from the lifespan
    turns a broken YAML file into a startup failure that names the offending line,
    instead of the two failures it used to become — an insert that raised inside `_row`
    and surfaced to an uploader as "Ingest failed", and, on the live path, every syslog
    and API event silently discarded while /health still answered "ok".
    """
    reg = get_registry()
    log.info("CIM registry v%s validated: %d models (%s)",
             reg.version, len(reg.models), ", ".join(reg.tags))
    return reg


# --------------------------------------------------------------------------- #
#  Ingest                                                                      #
# --------------------------------------------------------------------------- #
def _row(evt: NormalizedEvent, batch_id: int,
         tags: Optional[Iterable[str]] = None) -> dict[str, Any]:
    """The bind parameters for one `events` row.

    `tags` is this event's already-resolved CIM membership (see `_cim_tags`); omitting it
    derives membership here exactly as before, which is what every caller outside
    `insert_events` does — `backfill_cim`, the tests, and any ingest path that never ran
    detection.
    """
    return {
        "event_time": evt.event_time, "vendor": evt.vendor, "product": evt.product,
        "log_type": evt.log_type, "severity": evt.severity, "action": evt.action,
        "src_ip": evt.src_ip, "dst_ip": evt.dst_ip,
        # clamp ports to their column domain so a hostile value can't overflow the
        # 32-bit `integer` column and abort the whole insert chunk
        "src_port": to_port(evt.src_port), "dst_port": to_port(evt.dst_port),
        "protocol": evt.protocol, "app": evt.app,
        "user_name": evt.user_name, "host_name": evt.host_name, "rule_name": evt.rule_name,
        "bytes_total": evt.bytes_total, "message": evt.message,
        "raw": Jsonb(evt.raw), "tsv": tsv_text(evt),
        # CIM membership is derived here, in Python, on the same footing as the
        # full-text vector one line up: `search_tsv` <- tsv_text(evt) and
        # `cim_models` <- cim_models_for(evt). NULL (not '{}') for an event that
        # belongs to no model, so the GIN index stays proportional to tagged rows —
        # `backfill_cim` re-derives through the SAME function to keep a corrected row
        # byte-identical to a freshly ingested one. Wrapped by `_cim_tags` so a
        # registry that broke after startup costs the tags and never the event.
        "cim_models": _cim_tags(evt, tags),
        "batch_id": batch_id, "dedup_hash": dedup_hash(evt),
    }


def insert_events(conn, events: list[NormalizedEvent], batch_id: int,
                  cim_tags: Optional[Sequence[Optional[Iterable[str]]]] = None) -> None:
    """Insert a chunk of events within the caller's transaction.

    `cim_tags` is the chunk's already-resolved CIM membership, INDEX-ALIGNED with
    `events`: `cim_tags[i]` belongs to `events[i]`, and `None` at a position means "not
    resolved" — that row derives its own membership in `_row`, exactly as every row does
    when the argument is omitted entirely. `pipeline.write_stream` passes it so the
    registry is walked once per event rather than twice (once for the detection
    `datamodels:` gate, once here); it probes for this parameter with `inspect.signature`
    and falls back to the three-argument call, so an older build or a test double is
    still correct, just slower.

    A length mismatch is a ValueError rather than a silent truncation or a shifted
    alignment. It can only ever be a caller bug, and the cheap failure modes it would
    otherwise take — `zip` stopping at the shorter list, or every row after a missing one
    inheriting its neighbour's tags — are both invisible in the stored data.
    """
    if not events:
        return
    if cim_tags is not None and len(cim_tags) != len(events):
        raise ValueError(
            f"cim_tags has {len(cim_tags)} entries for {len(events)} events; it must be "
            "index-aligned with `events` (None at a position means 'derive this one')")
    months = {(e.event_time.year, e.event_time.month) for e in events if e.event_time}
    ensure_partitions(conn, months)
    rows = [_row(e, batch_id, None if cim_tags is None else cim_tags[i])
            for i, e in enumerate(events)]
    with conn.cursor() as cur:
        cur.executemany(_INSERT, rows)


# --------------------------------------------------------------------------- #
#  CIM data models: view DDL, registry stamp, membership backfill              #
# --------------------------------------------------------------------------- #
# `events.cim_models` is filled per row by `_row` above. What is left for the
# database is (a) one `cim_<tag>` view per model, rebuilt from the registry on every
# startup, and (b) correcting HISTORY after a models.yaml edit — rows ingested under
# the old rule keep the old tags until `backfill_cim` re-derives them. `backfill_cim`
# is the operator entry point that replaces the `python -m app.cli cim-rebuild`
# command the registry header used to advertise but which never existed.
#
# Every SQL string below is either a module constant or the return value of a pure
# function, so the DB-free unit tests can assert on the emitted text on a machine with
# no PostgreSQL — which is where this code is written and where CI runs its fast job.

# Exactly the shape `sql.view_name` emits ("cim_" + a validated tag). Nothing outside
# this pattern is ever dropped by the reconciler.
_CIM_VIEW_RE = re.compile(r"^cim_[a-z][a-z0-9_]*$")

# The views are created unqualified, so they land in `current_schema()`; look for them
# only there rather than across the whole search_path. `\_` escapes LIKE's single-char
# wildcard, so this matches `cim_dns` but not `cimxdns`.
_CIM_VIEW_SCAN = ("SELECT viewname FROM pg_views "
                  "WHERE schemaname = current_schema() AND viewname LIKE %s")
_CIM_VIEW_LIKE = r"cim\_%"

_CIM_STAMP_UPSERT = """
INSERT INTO cim_meta (id, registry_version, model_tags, membership_hash, applied_at)
VALUES (true, %(version)s, %(tags)s::text[], %(hash)s, now())
ON CONFLICT (id) DO UPDATE SET
    registry_version = EXCLUDED.registry_version,
    model_tags       = EXCLUDED.model_tags,
    membership_hash  = EXCLUDED.membership_hash,
    applied_at       = EXCLUDED.applied_at
"""
_CIM_BACKFILL_STAMP = ("UPDATE cim_meta SET backfilled_at = now(), "
                       "backfill_hash = %(hash)s WHERE id = true")

# The eleven columns `cim.match` reads, plus the id/event_time key and the stored
# value. Selecting `raw` is NOT optional: a row fetched without it matches no `raw:`
# term and raises nothing, which would quietly un-tag every Windows, Sysmon and Zeek
# event in the store.
_CIM_BACKFILL_COLS = ("id, event_time, vendor, product, log_type, severity, action, "
                      "protocol, app, user_name, host_name, raw, cim_models")

# `event_time` is in the predicate purely so the planner can prune to the one
# partition that holds the row; `id` alone would probe the index of every partition.
_CIM_UPDATE = ("UPDATE events SET cim_models = %(tags)s::text[] "
               "WHERE id = %(id)s AND event_time = %(event_time)s")


def cim_membership_fingerprint(registry: Optional[CimRegistry] = None) -> str:
    """A stable digest of the registry's MEMBERSHIP rules. Pure — no database.

    Canonicalized before hashing (values within a term, terms within a clause, clauses
    within a model, models by tag) so it changes when the rule set changes and *not*
    when someone merely reorders models.yaml — otherwise every cosmetic edit would
    look like "history is stale" and provoke a pointless full-table backfill.

    `fields:` are deliberately excluded: a field edit only changes the views, which
    :func:`init_cim` rebuilds on the next boot, whereas a membership edit invalidates
    the `cim_models` value stored on every row already in the table. This digest
    answers exactly one question — is a backfill due?
    """
    reg = registry if registry is not None else get_registry()
    models = []
    for m in sorted(reg.models, key=lambda mm: mm.tag):
        clauses = sorted(
            "&".join(sorted(
                f"{t.source.kind}:{t.source.name}:{t.source.paths!r}:{sorted(t.values)!r}"
                for t in c.terms))
            for c in m.clauses)
        models.append(m.tag + "=" + "|".join(clauses))
    return hashlib.sha256("\n".join(models).encode("utf-8")).hexdigest()


def _orphan_cim_views(existing: Iterable[str], keep: Iterable[str]) -> list[str]:
    """The `cim_*` views present in the database that the current registry no longer
    defines. Pure + DB-free so the diff itself is unit-testable.

    Only names this module could have created are returned (`^cim_[a-z][a-z0-9_]*$`,
    i.e. exactly what `sql.view_name` emits). A relation with a stranger name that
    merely starts with `cim` is left for a human — a startup path should never delete
    something it cannot prove it owns. Note the flip side: `cim_` IS a reserved
    namespace here, so an operator must not name their own view `cim_something`.
    """
    wanted = set(keep)
    return sorted(n for n in set(existing)
                  if n not in wanted and _CIM_VIEW_RE.match(n))


def _drop_orphan_cim_views(conn, keep: Iterable[str]) -> list[str]:
    """Drop the model views of models that have been removed from the registry.

    Deliberately WITHOUT CASCADE. An operator may have built a view, matview or
    dependent grant on top of `cim_authentication`, and CASCADE would delete it with
    no trace. RESTRICT makes such a drop fail instead — so each orphan runs inside its
    own savepoint and a blocked one is logged and left in place rather than aborting
    startup for the whole application.
    """
    rows = conn.execute(_CIM_VIEW_SCAN, (_CIM_VIEW_LIKE,)).fetchall()
    orphans = _orphan_cim_views((r["viewname"] for r in rows), keep)
    dropped: list[str] = []
    for name in orphans:
        try:
            with conn.transaction():          # savepoint: rolls back only this drop
                # `name` came from pg_views and matched _CIM_VIEW_RE, so it is a bare
                # lower-case identifier — same gate purge_older_than applies before it
                # interpolates a partition name.
                conn.execute(f"DROP VIEW IF EXISTS {name}")
            dropped.append(name)
            log.info("dropped orphaned CIM view %s (its model left the registry)", name)
        except Exception as exc:              # noqa: BLE001 — a dependent object, usually
            log.warning("could not drop orphaned CIM view %s; something depends on it "
                        "(no CASCADE by design): %s", name, exc)
    return dropped


def _stamp_cim(conn, reg: CimRegistry) -> None:
    """Record which registry the views were built from — the durable half of drift
    detection. `backfilled_at`/`backfill_hash` are untouched here on purpose: they
    belong to :func:`backfill_cim` and must keep pointing at the registry that the
    stored history was derived under, even once a newer one is live on the views."""
    conn.execute(_CIM_STAMP_UPSERT,
                 {"version": reg.version, "tags": [m.tag for m in reg.models],
                  "hash": cim_membership_fingerprint(reg)})


def _cim_ddl_groups(registry: CimRegistry) -> list[tuple[str, str, list[str]]]:
    """``(tag, view_name, [drop, create])`` per model — exactly the statements
    :func:`cim.sql.ddl_statements` emits, in the same order, grouped so each model can be
    applied on its own. Pure + DB-free, like every other SQL builder in this section.

    The MODEL, not the statement, is the unit of retry: a DROP that fails leaves the old
    view in place, and the CREATE that follows would then fail too (SQLSTATE 42P07,
    "relation already exists") because these views are deliberately DROP + CREATE rather
    than CREATE OR REPLACE — REPLACE cannot change a projection list, which is precisely
    what a `fields:` edit does.
    """
    return [(m.tag, cim_sql.view_name(m),
             [cim_sql.drop_view_ddl(m), cim_sql.create_view_ddl(m)])
            for m in registry.models]


def init_cim(registry: Optional[CimRegistry] = None) -> dict[str, Any]:
    """Apply the CIM registry to the database: rebuild the per-model views, drop the
    views of models that no longer exist, and stamp which registry was applied.

    Idempotent and safe on every startup. Returns `views` (rebuilt), `failed`
    (`[{"view", "error"}]`) and `dropped` (orphans reclaimed); it does NOT raise when a
    single model's DDL fails.

    PER-MODEL TRANSACTIONS, NOT ONE. This used to run the whole statement list in a
    single transaction, and that made one operator-owned object a permanent, silent
    outage for the entire read surface: docs/CIM.md presents `cim_<tag>` as the query
    surface, so an analyst writes `CREATE VIEW my_logons AS SELECT * FROM
    cim_authentication`, and from the next startup on the `DROP VIEW cim_authentication`
    fails with SQLSTATE 2BP01 (dependent_objects_still_exist), the transaction rolls
    back, and NONE of the eleven views refresh — on every restart, for ever. The fix is
    the one `_drop_orphan_cim_views` already applies to exactly this hazard: give each
    model its own transaction, log what blocked it, and keep going. CASCADE would
    "solve" it by deleting the analyst's view without a word, which is why it is not used
    here either.

    What a failed group costs: that model's view keeps whatever definition it already had
    (stale after a `fields:` edit, absent if it never built) while every other model
    refreshes. Atomicity across models is what is traded away, and it bought nothing —
    the views are read-side only, so a half-refreshed set is not a half-migrated
    database, and the previous behaviour did not roll back to a working state either, it
    rolled back to no refresh at all.

    The `cim_meta` stamp is still written after a partial pass, deliberately: it records
    the registry's MEMBERSHIP fingerprint, which drives `backfill_due` for the
    `events.cim_models` column, and that column is stamped in Python at ingest with no
    dependence on whether a view built. `failed` is how a view problem is reported.

    `events.cim_models` and its GIN index are NOT created here — they are declared
    statically in schema.sql (see the CIM section there) and applied by init_schema,
    which must therefore run first.
    """
    reg = registry if registry is not None else get_registry()
    keep = [cim_sql.view_name(m) for m in reg.models]
    applied: list[str] = []
    failed: list[dict[str, str]] = []
    with pool().connection() as conn:
        for _tag, view, stmts in _cim_ddl_groups(reg):
            try:
                # Outermost `transaction()` here, so each model commits on its own; a
                # failure rolls back this model's DROP and nothing else.
                with conn.transaction():
                    for stmt in stmts:
                        conn.execute(stmt)
                applied.append(view)
            except Exception as exc:          # noqa: BLE001 — logged, reported, not fatal
                # psycopg's error alone does not name the model, and the two causes need
                # different actions: a dependent object is the operator's to remove, a
                # bad expression is a models.yaml defect.
                detail = " ".join(str(exc).split())
                failed.append({"view": view, "error": detail})
                log.error(
                    "CIM view %s could not be rebuilt, so it keeps its previous "
                    "definition while the other models refresh. If this is SQLSTATE "
                    "2BP01, an object of yours depends on it (drop or rebuild that "
                    "object; this startup will never CASCADE it away). Error: %s",
                    view, detail)
        dropped = _drop_orphan_cim_views(conn, keep)
        _stamp_cim(conn, reg)
        conn.commit()
    log.info("CIM registry v%s applied: %d/%d model views rebuilt, %d failed, "
             "%d orphan(s) dropped",
             reg.version, len(applied), len(keep), len(failed), len(dropped))
    return {"registry_version": reg.version, "views": applied, "failed": failed,
            "dropped": dropped, "membership_hash": cim_membership_fingerprint(reg)}


# The on-disk registry's membership fingerprint, memoized on the file's CONTENT hash.
# Parsing + validating models.yaml costs ~88ms; hashing its 27KB costs ~0.5ms. Keyed on
# content rather than mtime/size deliberately: an mtime key silently misses a same-size
# edit inside the clock's granularity, and a missed edit here reports "no restart needed"
# when one is — the exact dishonesty this function exists to remove. Content hashing has
# no such window, so the fast path is also the correct one.
_registry_disk_cache: tuple[str, str] | None = None      # (content sha256, membership fp)


def reset_registry_disk_cache() -> None:
    """Forget the memoized on-disk fingerprint.

    Needed only when the LOADER is swapped rather than the file — i.e. by tests that
    monkeypatch `db.load_registry` to simulate an edit. A real edit changes the file's
    content hash and invalidates the entry on its own, which is the whole point of keying
    on content.
    """
    global _registry_disk_cache
    _registry_disk_cache = None


def registry_drift(registry: Optional[CimRegistry] = None) -> dict[str, Any]:
    """Has models.yaml been edited since this process loaded it? Pure — no database.

    `get_registry()` parses and caches for the PROCESS LIFETIME, so between an operator's
    edit and the restart the live rule and the file on disk are two different things.
    This re-reads the file (`registry.load` is deliberately non-caching) and compares
    membership fingerprints, which is what makes that window visible instead of green.

    Returns `disk_hash`, `restart_required` and `disk_error`. A file that will not parse
    is NOT an exception here: the running process is still healthy — it is serving the
    registry it loaded at boot — and the admin page that reports this is exactly where
    someone needs to be told the file is broken. So `restart_required` is None ("cannot
    tell") and `disk_error` carries the message.

    Called on every /admin and /datamodels render, so the expensive half is memoized on
    the file's content hash (see `_registry_disk_cache`) and an unedited file costs one
    read and one sha256. The error path is deliberately NOT memoized — a broken file is
    the state an operator is actively fixing, and re-reading it is how the page starts
    working again the moment they do.
    """
    global _registry_disk_cache
    reg = registry if registry is not None else get_registry()
    live = cim_membership_fingerprint(reg)
    try:
        raw = _REGISTRY_FILE.read_bytes()
        content = hashlib.sha256(raw).hexdigest()
        cached = _registry_disk_cache
        if cached is not None and cached[0] == content:
            disk = cached[1]
        else:
            disk = cim_membership_fingerprint(load_registry())
            _registry_disk_cache = (content, disk)
    except Exception as exc:  # noqa: BLE001 — reported, never raised; see the docstring
        log.warning("could not re-read app/cim/models.yaml to check for registry drift: %s",
                    exc)
        return {"disk_hash": None, "restart_required": None,
                "disk_error": f"{type(exc).__name__}: {exc}"}
    return {"disk_hash": disk, "restart_required": disk != live, "disk_error": None}


def cim_status(registry: Optional[CimRegistry] = None) -> dict[str, Any]:
    """What the database believes about the CIM registry, plus whether history is stale
    and whether the process is running the registry that is actually on disk.

    Two DIFFERENT questions, reported separately because they have different answers and
    different fixes:

    * `restart_required` — models.yaml on disk no longer matches the registry this
      process loaded at boot. Fix: restart. (`get_registry()` caches for the process
      lifetime; nothing re-reads the file.)
    * `backfill_due` — the rows already in `events` were tagged under a different
      membership rule than the one on disk. Fix: `backfill_cim`, AFTER the restart.

    `backfill_due` is measured against the ON-DISK rule, not the cached one, and that is
    the whole point of this function's shape. Against the cached registry an edit made
    before the restart is INVISIBLE — stamped-old vs cached-old compares equal, so the
    page says history is current while the file says otherwise. Worse, a backfill run in
    that window re-derives under the old cached rule and stamps `backfill_hash` with the
    old fingerprint, turning `backfill_due` False and reporting history current under a
    rule that has never been applied to a single row. Comparing against disk keeps it
    True until the restart-then-backfill sequence has actually happened.

    If models.yaml cannot be re-read, both fall back to the live registry (and
    `registry_drift` explains why in `registry_disk_error`) — a broken file on disk must
    not take away the diagnostics on the page that reports it.
    """
    reg = registry if registry is not None else get_registry()
    current = cim_membership_fingerprint(reg)
    drift = registry_drift(reg)
    # The rule history SHOULD be measured against: the file, when it is readable.
    target = drift["disk_hash"] or current
    with pool().connection() as conn:
        row = conn.execute("SELECT * FROM cim_meta WHERE id = true").fetchone()
    out: dict[str, Any] = dict(row) if row else {}
    out["current_version"] = reg.version
    out["current_hash"] = current
    out["current_tags"] = [m.tag for m in reg.models]
    out["backfill_due"] = out.get("backfill_hash") != target
    out["restart_required"] = drift["restart_required"]
    out["registry_disk_error"] = drift["disk_error"]
    return out


def _cim_backfill_query(since: Optional[dt.datetime] = None,
                        until: Optional[dt.datetime] = None) -> tuple[str, dict[str, Any]]:
    """``(sql, params)`` for ONE backfill chunk — pure, so a DB-free test can assert on
    the emitted text. The caller adds `_after` (the keyset resume cursor) and `_limit`.

    Keyset pagination on `id` rather than OFFSET: `id` is generated by one identity
    sequence on the partitioned parent, so it is globally monotonic and every chunk is
    an index range scan whose cost does not grow with how far in the run we are.
    Optional `since`/`until` bound the run to a time range, which also lets the planner
    prune whole partitions.
    """
    where = ["id > %(_after)s"]
    p: dict[str, Any] = {}
    if since is not None:
        where.append("event_time >= %(_since)s")
        p["_since"] = since
    if until is not None:
        where.append("event_time < %(_until)s")
        p["_until"] = until
    sql = (f"SELECT {_CIM_BACKFILL_COLS} FROM events "
           f"WHERE {' AND '.join(where)} ORDER BY id LIMIT %(_limit)s")
    return sql, p


def backfill_cim(*, chunk: int = 2000, start_id: int = 0,
                 max_rows: Optional[int] = None,
                 since: Optional[dt.datetime] = None,
                 until: Optional[dt.datetime] = None,
                 registry: Optional[CimRegistry] = None,
                 progress: Optional[Callable[[dict[str, Any]], None]] = None,
                 ) -> dict[str, Any]:
    """Re-derive `events.cim_models` for rows already in the store — the operator step
    that corrects HISTORY after a membership edit in models.yaml.

    READ-AND-UPDATE IN PYTHON, not a set-based ``UPDATE … WHERE <membership_sql>``.
    `sql.membership_sql` stays runnable and is the readable spec, but executing it here
    would make it a SECOND evaluator, and the two are already documented as differing
    in three places (`match` strips whitespace where `lower(col)` does not; jsonb `#>>`
    can subscript into an array where the Python walker only descends objects; a
    container value renders as JSON text under `->>` and as no-value here). A row
    corrected by SQL could therefore disagree with the identical row corrected at
    ingest, for no reason an operator could ever see. One evaluator — `cim.match` —
    is the whole point of Decision 1, and it costs one round trip per chunk to honour.

    CHUNKED AND RESUMABLE, because `events` retains three years of partitions and an
    unqualified UPDATE over it would hold one transaction (and its locks and its WAL)
    open for the duration. Every chunk is one keyset-paginated SELECT plus one
    executemany, committed before the next chunk starts, so an interrupted run loses at
    most one chunk and resumes with ``start_id=<the returned last_id>``. Rows whose
    tags are unchanged are not written at all, which makes a re-run after a no-op edit
    nearly free instead of rewriting every heap tuple in the table.

    Returns the counts plus `last_id` (the resume cursor) and `done` — False only when
    the run stopped on the caller's `max_rows` bound rather than on the data. The
    `cim_meta` backfill stamp is advanced only by a run that was unbounded AND
    completed; a partial pass must never claim that history is current.

    `progress` is called with a copy of the running counters (including `last_id`) after
    every COMMITTED chunk, and it exists for exactly one reason: the resume cursor is
    only useful to someone who can see it before the run returns. `main._cim_backfill_job`
    passes a sink that publishes it, so the shutdown handler can print a real
    `start_id=` — it used to print the `last_id` of the RESULT, which is None for the
    entire time a run is in flight and therefore always rendered as 0, the one value
    guaranteed to be wrong.
    """
    reg = registry if registry is not None else get_registry()
    chunk = max(1, int(chunk))
    full_pass = (int(start_id) == 0 and max_rows is None
                 and since is None and until is None)
    # RESTART FIRST, THEN BACKFILL. A run started while models.yaml has been edited but
    # not yet loaded re-derives every row under the OLD cached rule — a full-table scan
    # that changes nothing and then stamps `backfill_hash` with the old fingerprint.
    # `cim_status` measures `backfill_due` against the file, so it stays True and the
    # operator is not lied to; this says so at the moment the time is being wasted.
    # Warned, not refused: the caller may legitimately be passing an explicit `registry`.
    if registry_drift(reg)["restart_required"]:
        log.warning(
            "CIM backfill is running under the registry this process loaded at BOOT, but "
            "app/cim/models.yaml has changed since. Rows will be re-derived under the old "
            "rule. Restart LogOcean first, then run the backfill")
    select_sql, base = _cim_backfill_query(since, until)
    cursor_id = int(start_id)
    scanned = updated = unchanged = chunks = 0
    done = True
    started = time.monotonic()
    with pool().connection() as conn:
        while True:
            budget = chunk if max_rows is None else min(chunk, max_rows - scanned)
            if budget <= 0:
                done = False                  # stopped on the bound, not on the data
                break
            rows = conn.execute(select_sql,
                                dict(base, _after=cursor_id, _limit=budget)).fetchall()
            if not rows:
                break
            scanned += len(rows)
            chunks += 1
            cursor_id = int(rows[-1]["id"])   # ORDER BY id, so the last row is the max
            writes = []
            for r in rows:
                tags = cim_models_for(r, reg)  # a stored row IS an EventLike mapping
                if tags != r["cim_models"]:    # both sorted + NULL-for-none: comparable
                    writes.append({"id": r["id"], "event_time": r["event_time"],
                                   "tags": tags})
            unchanged += len(rows) - len(writes)
            if writes:
                with conn.cursor() as cur:
                    cur.executemany(_CIM_UPDATE, writes)
                updated += len(writes)
            conn.commit()                     # bounded WAL + a resumable cursor
            log.info("CIM backfill: scanned=%d updated=%d unchanged=%d last_id=%d",
                     scanned, updated, unchanged, cursor_id)
            if progress is not None:
                # After the commit, never before: `last_id` is only a valid resume
                # cursor once the work up to it is durable.
                try:
                    progress({"scanned": scanned, "updated": updated,
                              "unchanged": unchanged, "chunks": chunks,
                              "last_id": cursor_id})
                except Exception:             # noqa: BLE001 — a progress sink is
                    log.warning("CIM backfill progress callback failed",  # diagnostics;
                                exc_info=True)             # it must never abort the run
            if len(rows) < budget:
                break                         # short page -> the range is exhausted
        if done and full_pass:
            stamped = conn.execute(
                _CIM_BACKFILL_STAMP,
                {"hash": cim_membership_fingerprint(reg)}).rowcount
            conn.commit()
            if not stamped:
                # No cim_meta row means init_cim has never run, so the model VIEWS do
                # not exist either. Say so rather than seeding a row that would claim
                # they had been applied.
                log.warning("CIM backfill completed but could not record the stamp: "
                            "cim_meta is empty - run db.init_cim() first")
    result = {"scanned": scanned, "updated": updated, "unchanged": unchanged,
              "chunks": chunks, "last_id": cursor_id, "done": done,
              "full_pass": full_pass, "registry_version": reg.version,
              "seconds": round(time.monotonic() - started, 2)}
    log.info("CIM backfill finished: %s", result)
    return result


# --------------------------------------------------------------------------- #
#  Batch tracking                                                              #
# --------------------------------------------------------------------------- #
def create_batch(filename: Optional[str], sha: Optional[str], vendor: Optional[str],
                 fmt: str, source_type: str = "upload",
                 source_addr: Optional[str] = None,
                 uploaded_at: Optional[Any] = None) -> int:
    with pool().connection() as conn:
        if uploaded_at is not None:
            row = conn.execute(
                "INSERT INTO ingest_batches "
                "(filename, file_sha256, vendor, fmt, status, source_type, source_addr, uploaded_at) "
                "VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s) RETURNING id",
                (filename, sha, vendor, fmt, source_type, source_addr, uploaded_at)).fetchone()
        else:
            row = conn.execute(
                "INSERT INTO ingest_batches "
                "(filename, file_sha256, vendor, fmt, status, source_type, source_addr) "
                "VALUES (%s, %s, %s, %s, 'pending', %s, %s) RETURNING id",
                (filename, sha, vendor, fmt, source_type, source_addr)).fetchone()
        conn.commit()
        return row["id"]


def update_batch(batch_id: int, **fields: Any) -> None:
    if not fields:
        return
    sets = ", ".join(f"{k} = %({k})s" for k in fields)
    fields["id"] = batch_id
    with pool().connection() as conn:
        conn.execute(f"UPDATE ingest_batches SET {sets} WHERE id = %(id)s", fields)
        conn.commit()


def count_batch_rows(batch_id: int) -> int:
    with pool().connection() as conn:
        row = conn.execute("SELECT count(*) AS n FROM events WHERE batch_id = %s",
                           (batch_id,)).fetchone()
        return int(row["n"])


def find_batch_by_sha(sha: str) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM ingest_batches WHERE file_sha256 = %s AND status = 'done' "
            "ORDER BY uploaded_at DESC LIMIT 1", (sha,)).fetchone()


def recent_batches(limit: int = 50) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM ingest_batches ORDER BY uploaded_at DESC LIMIT %s",
            (limit,)).fetchall()


# --------------------------------------------------------------------------- #
#  API keys (HTTP ingest auth)                                                 #
# --------------------------------------------------------------------------- #
def create_api_key(name: str, source_label: Optional[str] = None) -> dict:
    """Mint a new key. Returns the row plus the plaintext `key` (shown ONCE);
    only the sha256 is stored."""
    raw = "lo_" + secrets.token_urlsafe(32)
    sha = hash_api_key(raw)
    prefix = raw[:11]  # "lo_" + 8 chars — a non-secret label for the UI
    with pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO api_keys (name, key_sha256, key_prefix, source_label) "
            "VALUES (%s, %s, %s, %s) "
            "RETURNING id, name, key_prefix, source_label, enabled, created_at",
            (name, sha, prefix, source_label)).fetchone()
        conn.commit()
    row["key"] = raw
    return row


def verify_api_key(key: str) -> Optional[dict]:
    """Return the key row if `key` matches an enabled key (and stamp last_used),
    else None."""
    sha = hash_api_key(key)
    with pool().connection() as conn:
        row = conn.execute(
            "SELECT id, name, key_prefix, source_label, enabled FROM api_keys "
            "WHERE key_sha256 = %s", (sha,)).fetchone()
        if row is None or not row["enabled"]:
            return None
        conn.execute("UPDATE api_keys SET last_used_at = now() WHERE id = %s", (row["id"],))
        conn.commit()
    return row


def list_api_keys() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT id, name, key_prefix, source_label, enabled, created_at, last_used_at "
            "FROM api_keys ORDER BY created_at DESC").fetchall()


def set_api_key_enabled(key_id: int, enabled: bool) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE api_keys SET enabled = %s WHERE id = %s", (enabled, key_id))
        conn.commit()


# --------------------------------------------------------------------------- #
#  Detection: rule registry + alerts                                          #
# --------------------------------------------------------------------------- #
def sync_rules(rules: Iterable[Any]) -> None:
    """Upsert each loaded rule's metadata, preserving the `enabled` flag."""
    with pool().connection() as conn:
        for r in rules:
            conn.execute(
                "INSERT INTO detection_rules (rule_id, title, level, source, tactics, techniques) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (rule_id) DO UPDATE SET title = EXCLUDED.title, "
                "level = EXCLUDED.level, source = EXCLUDED.source, "
                "tactics = EXCLUDED.tactics, techniques = EXCLUDED.techniques",
                (r.id, r.title, r.level, r.source, r.tactics, r.techniques))
        conn.commit()


def enabled_rule_ids() -> set[str]:
    with pool().connection() as conn:
        rows = conn.execute("SELECT rule_id FROM detection_rules WHERE enabled").fetchall()
    return {row["rule_id"] for row in rows}


def list_rules() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT r.*, COALESCE(a.n, 0) AS fired, a.last_fired "
            "FROM detection_rules r LEFT JOIN ("
            "  SELECT rule_id, count(*) AS n, max(created_at) AS last_fired "
            "  FROM alerts GROUP BY rule_id) a ON a.rule_id = r.rule_id "
            "ORDER BY r.level, r.rule_id").fetchall()


def set_rule_enabled(rule_id: str, enabled: bool) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE detection_rules SET enabled = %s WHERE rule_id = %s",
                     (enabled, rule_id))
        conn.commit()


def rule_stats(days: int = 30) -> list[dict]:
    """Every registered rule with all-time and windowed firing counts, for the
    detection-engineering workbench. `fired_total` / `last_fired` are all-time;
    `fired_window` counts alerts in the last `days` days."""
    q = """
    SELECT r.*, COALESCE(t.n, 0) AS fired_total, t.last_fired,
           COALESCE(w.n, 0) AS fired_window
    FROM detection_rules r
    LEFT JOIN (SELECT rule_id, count(*) AS n, max(created_at) AS last_fired
               FROM alerts GROUP BY rule_id) t ON t.rule_id = r.rule_id
    LEFT JOIN (SELECT rule_id, count(*) AS n FROM alerts
               WHERE created_at >= now() - make_interval(days => %s)
               GROUP BY rule_id) w ON w.rule_id = r.rule_id
    ORDER BY fired_window DESC, r.level, r.rule_id"""
    with pool().connection() as conn:
        return conn.execute(q, (days,)).fetchall()


_ALERT_INSERT = """
INSERT INTO alerts (event_time, rule_id, rule_title, level, tactics, techniques,
    vendor, src_ip, dst_ip, user_name, host_name, message, dedup_hash, batch_id, status)
VALUES (%(event_time)s, %(rule_id)s, %(rule_title)s, %(level)s, %(tactics)s, %(techniques)s,
    %(vendor)s, %(src_ip)s::inet, %(dst_ip)s::inet, %(user_name)s, %(host_name)s,
    %(message)s, %(dedup_hash)s, %(batch_id)s, COALESCE(%(status)s, 'open'))
ON CONFLICT (rule_id, dedup_hash) DO NOTHING
"""


def insert_alerts(conn, alerts: list[dict], return_inserted: bool = False) -> list[dict]:
    """Insert alerts within the caller's transaction (idempotent per rule+event).

    With `return_inserted`, insert row-by-row with RETURNING and return only the
    alerts that were actually new (ON CONFLICT skips dedup) — so callers can
    notify on newly-raised alerts only. Otherwise use a fast executemany."""
    if not alerts:
        return []
    # `status` is the one INSERT parameter with a SQL-side default (COALESCE …
    # 'open'); psycopg still requires the key to be present when binding named
    # params, so default it here — keeps any builder that omits it from crashing
    # the pipeline while preserving explicit values (e.g. 'suppressed').
    for a in alerts:
        a.setdefault("status", "open")
    if not return_inserted:
        with conn.cursor() as cur:
            cur.executemany(_ALERT_INSERT, alerts)
        return []
    new: list[dict] = []
    with conn.cursor() as cur:
        for a in alerts:
            row = cur.execute(_ALERT_INSERT + " RETURNING id", a).fetchone()
            if row:  # None when the ON CONFLICT clause skipped a duplicate
                new.append({**a, "id": row["id"]})
    return new


def _alert_where(f: dict) -> tuple[str, dict]:
    clauses, p = [], {}
    if f.get("status"):
        clauses.append("status = %(status)s"); p["status"] = f["status"]
    else:
        clauses.append("status <> 'suppressed'")   # hide suppressed from the default view
    if f.get("level"):
        clauses.append("lower(level) = lower(%(level)s)"); p["level"] = f["level"]
    if f.get("rule_id"):
        clauses.append("rule_id = %(rule_id)s"); p["rule_id"] = f["rule_id"]
    if f.get("assignee"):
        clauses.append("assignee = %(assignee)s"); p["assignee"] = f["assignee"]
    if f.get("q"):
        clauses.append("(message ILIKE %(q)s OR user_name ILIKE %(q)s OR "
                       "host(src_ip) ILIKE %(q)s)"); p["q"] = f"%{f['q']}%"
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, p


_ALERT_COLS = """id, created_at, event_time, rule_id, rule_title, level, tactics,
    techniques, vendor, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip,
    user_name, host_name, message, dedup_hash, batch_id, status, assignee, case_id"""


def recent_alerts(filters: dict, limit: int, offset: int) -> tuple[list[dict], int]:
    where, p = _alert_where(filters)
    with pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM alerts {where}", p).fetchone()["n"]
        p2 = dict(p, _limit=limit, _offset=offset)
        rows = conn.execute(
            f"SELECT {_ALERT_COLS} FROM alerts {where} "
            f"ORDER BY created_at DESC LIMIT %(_limit)s OFFSET %(_offset)s", p2).fetchall()
    return rows, int(total)


def alerts_iter(filters: dict, cap: int = 100_000):
    """Stream alert rows for CSV export (bounded by cap)."""
    where, p = _alert_where(filters)
    p["_cap"] = cap
    with pool().connection() as conn, conn.cursor(name="alerts_export_cur") as cur:
        cur.execute(f"SELECT {_ALERT_COLS} FROM alerts {where} "
                    f"ORDER BY created_at DESC LIMIT %(_cap)s", p)
        for row in cur:
            yield row


def get_alert(alert_id: int) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE id = %s", (alert_id,)).fetchone()


def set_alert_status(alert_id: int, status: str) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE alerts SET status = %s WHERE id = %s", (status, alert_id))
        conn.commit()


def set_alert_assignee(alert_id: int, assignee: Optional[str]) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE alerts SET assignee = %s WHERE id = %s",
                     (assignee or None, alert_id))
        conn.commit()


def add_alert_note(alert_id: int, author: Optional[str], note: str) -> None:
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO alert_notes (alert_id, author, note) VALUES (%s, %s, %s)",
            (alert_id, author, note))
        conn.commit()


def alert_notes(alert_id: int) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM alert_notes WHERE alert_id = %s ORDER BY created_at",
            (alert_id,)).fetchall()


# --------------------------------------------------------------------------- #
#  Suppression / allowlist rules                                              #
# --------------------------------------------------------------------------- #
def create_suppression(name: str, *, rule_id=None, src_ip=None, user_name=None,
                       host_name=None, vendor=None, reason=None,
                       created_by=None, expires_at=None) -> int:
    with pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO suppressions "
            "(name, rule_id, src_ip, user_name, host_name, vendor, reason, "
            " created_by, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (name, rule_id or None, src_ip or None, user_name or None,
             host_name or None, vendor or None, reason or None, created_by,
             expires_at)).fetchone()
        conn.commit()
        return row["id"]


def enabled_suppressions() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT id, name, rule_id, src_ip, user_name, host_name, vendor "
            "FROM suppressions WHERE enabled "
            "AND (expires_at IS NULL OR expires_at > now())").fetchall()


def list_suppressions() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM suppressions ORDER BY created_at DESC").fetchall()


def set_suppression_enabled(supp_id: int, enabled: bool) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE suppressions SET enabled = %s WHERE id = %s",
                     (enabled, supp_id))
        conn.commit()


def delete_suppression(supp_id: int) -> None:
    with pool().connection() as conn:
        conn.execute("DELETE FROM suppressions WHERE id = %s", (supp_id,))
        conn.commit()


def bump_suppressions(conn, counts: dict) -> None:
    """Increment hit counters for suppressions that fired (within `conn`'s txn)."""
    for supp_id, n in counts.items():
        conn.execute(
            "UPDATE suppressions SET hit_count = hit_count + %s, last_hit = now() "
            "WHERE id = %s", (n, supp_id))


# --------------------------------------------------------------------------- #
#  Cases / incidents (group related alerts)                                   #
# --------------------------------------------------------------------------- #
_CASE_SELECT = """SELECT c.*, COALESCE(n.n, 0) AS alert_count FROM cases c
    LEFT JOIN (SELECT case_id, count(*) AS n FROM alerts WHERE case_id IS NOT NULL
               GROUP BY case_id) n ON n.case_id = c.id"""


def create_case(title: str, summary: Optional[str] = None, severity: str = "medium",
                created_by: Optional[str] = None, assignee: Optional[str] = None,
                source: str = "manual", kc_signature: Optional[str] = None) -> int:
    with pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO cases (title, summary, severity, created_by, assignee, "
            "source, kc_signature) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (title, summary or None, severity, created_by, assignee or None,
             source, kc_signature)).fetchone()
        conn.commit()
        return row["id"]


def get_case(case_id: int) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute(_CASE_SELECT + " WHERE c.id = %s", (case_id,)).fetchone()


def list_cases(filters: dict, limit: int, offset: int) -> tuple[list[dict], int]:
    clauses, p = [], {}
    if filters.get("status"):
        clauses.append("c.status = %(status)s"); p["status"] = filters["status"]
    if filters.get("assignee"):
        clauses.append("c.assignee = %(assignee)s"); p["assignee"] = filters["assignee"]
    if filters.get("q"):
        clauses.append("c.title ILIKE %(q)s"); p["q"] = f"%{filters['q']}%"
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM cases c {where}", p).fetchone()["n"]
        p2 = dict(p, _l=limit, _o=offset)
        rows = conn.execute(
            _CASE_SELECT + f" {where} ORDER BY c.updated_at DESC "
            "LIMIT %(_l)s OFFSET %(_o)s", p2).fetchall()
    return rows, int(total)


def update_case(case_id: int, **fields: Any) -> None:
    sets = ["updated_at = now()"]
    p: dict[str, Any] = {"id": case_id}
    for k in ("title", "summary", "status", "severity", "assignee"):
        if k in fields:
            sets.append(f"{k} = %({k})s")
            p[k] = fields[k] or None
    if "status" in fields:
        sets.append("closed_at = now()" if fields["status"] == "closed" else "closed_at = NULL")
    with pool().connection() as conn:
        conn.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = %(id)s", p)
        conn.commit()


def _escalate_case(conn, case_id: int, levels: Iterable[str]) -> None:
    cur = conn.execute("SELECT severity FROM cases WHERE id = %s", (case_id,)).fetchone()
    if cur is not None:
        new = max_severity([cur["severity"], *levels], default=cur["severity"])
        conn.execute("UPDATE cases SET severity = %s, updated_at = now() WHERE id = %s",
                     (new, case_id))


def add_alerts_to_case(case_id: int, alert_ids: Iterable[Any]) -> None:
    """Attach alerts to a case and roll the case severity up to their max."""
    ids = [int(a) for a in alert_ids]
    if not ids:
        return
    with pool().connection() as conn:
        rows = conn.execute("SELECT level FROM alerts WHERE id = ANY(%s)", (ids,)).fetchall()
        conn.execute("UPDATE alerts SET case_id = %s WHERE id = ANY(%s)", (case_id, ids))
        _escalate_case(conn, case_id, [r["level"] for r in rows])
        conn.commit()


def add_alert_to_case(alert_id: int, case_id: int) -> None:
    add_alerts_to_case(case_id, [alert_id])


def remove_alert_from_case(alert_id: int) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE alerts SET case_id = NULL WHERE id = %s", (alert_id,))
        conn.commit()


def case_alerts(case_id: int) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE case_id = %s "
            "ORDER BY event_time DESC NULLS LAST, created_at DESC", (case_id,)).fetchall()


def related_open_alerts(case_id: int, limit: int = 50) -> list[dict]:
    """Open, un-cased, non-suppressed alerts sharing a src_ip / user / host with
    any alert already in the case — candidates to fold into the investigation."""
    q = f"""
    WITH ent AS (
        SELECT DISTINCT host(src_ip) AS s, user_name AS u, host_name AS h
        FROM alerts WHERE case_id = %(cid)s)
    SELECT {_ALERT_COLS} FROM alerts a
    WHERE a.case_id IS NULL AND a.status <> 'suppressed' AND EXISTS (
        SELECT 1 FROM ent e WHERE
            (a.src_ip   IS NOT NULL AND host(a.src_ip) = e.s) OR
            (a.user_name IS NOT NULL AND a.user_name   = e.u) OR
            (a.host_name IS NOT NULL AND a.host_name   = e.h))
    ORDER BY a.created_at DESC LIMIT %(lim)s"""
    with pool().connection() as conn:
        return conn.execute(q, {"cid": case_id, "lim": limit}).fetchall()


def related_alerts_for(alert_id: int, limit: int = 8) -> list[dict]:
    """Recent non-suppressed alerts sharing a src_ip / user / host with this alert —
    context for the AI copilot's explanation."""
    q = f"""
    WITH me AS (SELECT host(src_ip) AS s, user_name AS u, host_name AS h
                FROM alerts WHERE id = %(id)s)
    SELECT {_ALERT_COLS} FROM alerts a, me
    WHERE a.id <> %(id)s AND a.status <> 'suppressed' AND (
        (a.src_ip   IS NOT NULL AND host(a.src_ip) = me.s) OR
        (a.user_name IS NOT NULL AND a.user_name   = me.u) OR
        (a.host_name IS NOT NULL AND a.host_name   = me.h))
    ORDER BY a.created_at DESC LIMIT %(lim)s"""
    with pool().connection() as conn:
        return conn.execute(q, {"id": alert_id, "lim": limit}).fetchall()


def add_case_note(case_id: int, author: Optional[str], note: str) -> None:
    with pool().connection() as conn:
        conn.execute("INSERT INTO case_notes (case_id, author, note) VALUES (%s, %s, %s)",
                     (case_id, author, note))
        conn.execute("UPDATE cases SET updated_at = now() WHERE id = %s", (case_id,))
        conn.commit()


def case_notes(case_id: int) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM case_notes WHERE case_id = %s ORDER BY created_at",
            (case_id,)).fetchall()


def case_status_counts() -> dict:
    with pool().connection() as conn:
        rows = conn.execute("SELECT status, count(*) AS n FROM cases GROUP BY status").fetchall()
    return {r["status"]: int(r["n"]) for r in rows}


def open_cases(limit: int = 200) -> list[dict]:
    """Non-closed cases, for the 'add to case' picker on an alert."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT id, title, severity, status FROM cases WHERE status <> 'closed' "
            "ORDER BY updated_at DESC LIMIT %s", (limit,)).fetchall()


# --------------------------------------------------------------------------- #
#  Kill-chain reconstruction                                                  #
# --------------------------------------------------------------------------- #
def recent_uncased_alerts(hours: int = 24, cap: int = 5000) -> list[dict]:
    """Open, non-suppressed, un-cased alerts in the last `hours` — the raw
    material the kill-chain reconstructor stitches into attack stories.

    Ordered oldest-first so callers see the chain in chronological order; capped
    to bound reconstruction cost."""
    q = f"""SELECT {_ALERT_COLS} FROM alerts
            WHERE case_id IS NULL AND status NOT IN ('suppressed', 'closed')
              AND COALESCE(event_time, created_at) >= now() - make_interval(hours => %s)
            ORDER BY COALESCE(event_time, created_at) ASC
            LIMIT %s"""
    with pool().connection() as conn:
        return conn.execute(q, (hours, cap)).fetchall()


def open_kc_signatures() -> set[str]:
    """Signatures of non-closed kill-chain cases, so auto-create is idempotent."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT kc_signature FROM cases "
            "WHERE source = 'killchain' AND kc_signature IS NOT NULL "
            "AND status <> 'closed'").fetchall()
    return {r["kc_signature"] for r in rows}


def create_case_from_story(story: dict, created_by: Optional[str] = None) -> int:
    """Persist a reconstructed attack story as a case and fold its alerts in.

    Reuses create_case + add_alerts_to_case so severity rollup and alert linkage
    behave exactly like a manually built case. Returns the new case id."""
    cid = create_case(
        title=story["title"], summary=story.get("narrative"),
        severity=story.get("severity", "medium"), created_by=created_by,
        source="killchain", kc_signature=story.get("signature"))
    add_alerts_to_case(cid, story.get("alert_ids") or [])
    return cid


# --------------------------------------------------------------------------- #
#  UEBA: entity baselines, anomalies, risk scoring                            #
# --------------------------------------------------------------------------- #
_ENTITY_UPSERT = """
INSERT INTO entities (entity_type, entity_value, first_seen, last_seen, event_count)
VALUES (%s, %s, %s, %s, %s)
ON CONFLICT (entity_type, entity_value) DO UPDATE SET
    first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
    last_seen  = GREATEST(entities.last_seen, EXCLUDED.last_seen),
    event_count = entities.event_count + EXCLUDED.event_count
"""
_LINK_UPSERT = """
INSERT INTO entity_links (entity_type, entity_value, peer_type, peer_value,
    first_seen, last_seen, count)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (entity_type, entity_value, peer_type, peer_value) DO UPDATE SET
    first_seen = LEAST(entity_links.first_seen, EXCLUDED.first_seen),
    last_seen  = GREATEST(entity_links.last_seen, EXCLUDED.last_seen),
    count = entity_links.count + EXCLUDED.count
"""


def upsert_entities(conn, rows: list[tuple]) -> None:
    """rows: (entity_type, entity_value, first_seen, last_seen, count). In `conn`'s txn."""
    if rows:
        with conn.cursor() as cur:
            cur.executemany(_ENTITY_UPSERT, rows)


def upsert_entity_links(conn, rows: list[tuple]) -> None:
    if rows:
        with conn.cursor() as cur:
            cur.executemany(_LINK_UPSERT, rows)


def new_entities(hours: int = 24, limit: int = 50) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT entity_type, entity_value, first_seen, event_count FROM entities "
            "WHERE first_seen >= now() - make_interval(hours => %s) "
            "ORDER BY first_seen DESC LIMIT %s", (hours, limit)).fetchall()


def new_associations(hours: int = 24, limit: int = 50) -> list[dict]:
    """Links first seen in the window whose subject entity is older — i.e. an
    established actor showing a new peer (a classic UEBA signal)."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT l.entity_type, l.entity_value, l.peer_type, l.peer_value, l.first_seen "
            "FROM entity_links l JOIN entities e "
            "  ON e.entity_type = l.entity_type AND e.entity_value = l.entity_value "
            "WHERE l.first_seen >= now() - make_interval(hours => %s) "
            "  AND e.first_seen < l.first_seen - interval '1 hour' "
            "ORDER BY l.first_seen DESC LIMIT %s", (hours, limit)).fetchall()


def anomaly_counts(hours: int = 24) -> dict:
    return {"new_entities": len(new_entities(hours, 10_000)),
            "new_associations": len(new_associations(hours, 10_000))}


def top_risk_entities(entity_type: str, days: int = 30, half_life: float = 7.0,
                      limit: int = 10) -> list[dict]:
    """Riskiest entities of a type, scored by their attributed alerts (severity-
    weighted, recency-decayed). Enriched with the entity's first_seen."""
    col = ENTITY_COLUMN.get(entity_type)
    if col is None:
        return []
    value_expr = f"host({col})" if col == "src_ip" else col
    weight = weight_case_sql("level")
    q = f"""
    SELECT v AS value, alerts, score, first_seen,
           (first_seen >= now() - interval '24 hours') AS is_new
    FROM (
        SELECT {value_expr} AS v, count(*) AS alerts,
               round(sum({weight} * power(0.5,
                   extract(epoch from now() - created_at) / (86400 * %(hl)s)))::numeric, 1) AS score
        FROM alerts
        WHERE {col} IS NOT NULL AND status <> 'suppressed'
          AND created_at >= now() - make_interval(days => %(days)s)
        GROUP BY 1
    ) s
    LEFT JOIN entities e ON e.entity_type = %(etype)s AND e.entity_value = s.v
    ORDER BY score DESC LIMIT %(lim)s"""
    with pool().connection() as conn:
        return conn.execute(q, {"hl": half_life, "days": days, "etype": entity_type,
                                "lim": limit}).fetchall()


def get_entity(entity_type: str, value: str) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM entities WHERE entity_type = %s AND entity_value = %s",
            (entity_type, value)).fetchone()


def entity_associations(entity_type: str, value: str, limit: int = 50) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT peer_type, peer_value, first_seen, last_seen, count, "
            "(first_seen >= now() - interval '24 hours') AS is_new "
            "FROM entity_links WHERE entity_type = %s AND entity_value = %s "
            "ORDER BY last_seen DESC LIMIT %s", (entity_type, value, limit)).fetchall()


def entity_alerts(entity_type: str, value: str, limit: int = 50) -> list[dict]:
    col = ENTITY_COLUMN.get(entity_type)
    if col is None:
        return []
    match = f"host({col}) = %(v)s" if col == "src_ip" else f"{col} = %(v)s"
    with pool().connection() as conn:
        return conn.execute(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE {match} "
            "ORDER BY created_at DESC LIMIT %(lim)s", {"v": value, "lim": limit}).fetchall()


def entity_activity(entity_type: str, value: str, days: int = 14) -> list[dict]:
    col = ENTITY_COLUMN.get(entity_type)
    if col is None:
        return []
    match = f"host({col}) = %(v)s" if col == "src_ip" else f"{col} = %(v)s"
    with pool().connection() as conn:
        return conn.execute(
            f"SELECT date_trunc('day', event_time)::date AS day, count(*) AS n FROM events "
            f"WHERE {match} AND event_time >= now() - make_interval(days => %(days)s) "
            "GROUP BY 1 ORDER BY 1", {"v": value, "days": days}).fetchall()


def alert_severity_counts() -> dict:
    """Open-alert counts by level, for the dashboard."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT level, count(*) AS n FROM alerts WHERE status = 'open' "
            "GROUP BY level").fetchall()
    return {r["level"]: int(r["n"]) for r in rows}


def alert_status_counts() -> dict:
    """Alert counts by status (open/ack/closed/suppressed), for analytics."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT status, count(*) AS n FROM alerts GROUP BY status").fetchall()
    return {r["status"]: int(r["n"]) for r in rows}


def alerts_over_time(days: int = 30) -> list[dict]:
    """Daily non-suppressed alert counts over the last `days`."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT date_trunc('day', created_at)::date AS day, count(*) AS n FROM alerts "
            "WHERE created_at >= now() - make_interval(days => %s) AND status <> 'suppressed' "
            "GROUP BY 1 ORDER BY 1", (days,)).fetchall()


def top_rules(days: int = 30, limit: int = 8) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT rule_id, rule_title, count(*) AS n FROM alerts "
            "WHERE created_at >= now() - make_interval(days => %s) AND status <> 'suppressed' "
            "GROUP BY rule_id, rule_title ORDER BY n DESC LIMIT %s", (days, limit)).fetchall()


def top_alert_sources(days: int = 30, limit: int = 8) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT host(src_ip) AS src_ip, count(*) AS n FROM alerts "
            "WHERE created_at >= now() - make_interval(days => %s) "
            "AND src_ip IS NOT NULL AND status <> 'suppressed' "
            "GROUP BY 1 ORDER BY n DESC LIMIT %s", (days, limit)).fetchall()


def top_event_sources(days: int = 7, limit: int = 8) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT host(src_ip) AS src_ip, count(*) AS n FROM events "
            "WHERE event_time >= now() - make_interval(days => %s) AND src_ip IS NOT NULL "
            "GROUP BY 1 ORDER BY n DESC LIMIT %s", (days, limit)).fetchall()


def source_activity(learn_days: int = 7) -> list[dict]:
    """Per-source ``(vendor, log_type)`` activity over the learning window: the
    newest event time and event count. Feeds the log-source health / silent-source
    check. A source last seen longer ago than ``learn_days`` drops out (it is no
    longer an *expected* feed), so a decommissioned source is not flagged forever."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT vendor, log_type, max(event_time) AS last_seen, count(*) AS n "
            "FROM events WHERE event_time >= now() - make_interval(days => %s) "
            "AND vendor IS NOT NULL AND vendor <> '' "
            "GROUP BY vendor, log_type ORDER BY last_seen ASC", (learn_days,)).fetchall()


def alert_technique_counts(days: int = 30) -> dict:
    """Recent alert counts per MITRE technique (techniques is a text[]), for the
    compliance view."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT t AS technique, count(*) AS n FROM alerts, unnest(techniques) t "
            "WHERE created_at >= now() - make_interval(days => %s) GROUP BY t",
            (days,)).fetchall()
    return {r["technique"]: int(r["n"]) for r in rows}


# --------------------------------------------------------------------------- #
#  OT / ICS analytics (read-only aggregation over `events`)                    #
# --------------------------------------------------------------------------- #
def ot_assets(days: int = 30, limit: int = 100) -> list[dict]:
    """OT controllers (PLCs / RTUs) seen on the wire: the protocols they speak, how
    many distinct masters talk to each, control-op volume, and first/last seen. The
    controller is the server side of an OT conversation (`dst_ip`)."""
    with pool().connection() as conn:
        return conn.execute(
            """
            SELECT host(dst_ip) AS controller,
                   array_agg(DISTINCT log_type ORDER BY log_type) AS protocols,
                   count(*) AS events,
                   count(DISTINCT src_ip) AS masters,
                   count(*) FILTER (
                       WHERE raw->'ot'->>'operation' IN ('write', 'control')) AS control_ops,
                   min(event_time) AS first_seen, max(event_time) AS last_seen
            FROM events
            WHERE log_type = ANY(%(p)s) AND dst_ip IS NOT NULL
              AND event_time >= now() - make_interval(days => %(d)s)
            GROUP BY host(dst_ip)
            ORDER BY events DESC LIMIT %(l)s
            """,
            {"p": list(OT_PROTOCOLS), "d": days, "l": limit}).fetchall()


def ot_conversations(days: int = 30, limit: int = 200) -> list[dict]:
    """Master→controller conversations: per (src_ip, dst_ip) the protocols, event
    count, write/control counts, first/last seen, and whether the pair is new in the
    last 24h — the basis for flagging an unexpected client commanding a controller."""
    with pool().connection() as conn:
        return conn.execute(
            """
            SELECT host(src_ip) AS master, host(dst_ip) AS controller,
                   array_agg(DISTINCT log_type ORDER BY log_type) AS protocols,
                   count(*) AS events,
                   count(*) FILTER (WHERE raw->'ot'->>'is_write' = 'true') AS writes,
                   count(*) FILTER (WHERE raw->'ot'->>'operation' = 'control') AS controls,
                   min(event_time) AS first_seen, max(event_time) AS last_seen,
                   (min(event_time) >= now() - interval '24 hours') AS is_new
            FROM events
            WHERE log_type = ANY(%(p)s) AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
              AND event_time >= now() - make_interval(days => %(d)s)
            GROUP BY host(src_ip), host(dst_ip)
            ORDER BY is_new DESC, writes DESC, events DESC LIMIT %(l)s
            """,
            {"p": list(OT_PROTOCOLS), "d": days, "l": limit}).fetchall()


def ot_activity_summary(days: int = 30) -> list[dict]:
    """Per-protocol OT activity: total events split into read / write / control."""
    with pool().connection() as conn:
        return conn.execute(
            """
            SELECT log_type AS protocol, count(*) AS events,
                   count(*) FILTER (WHERE raw->'ot'->>'operation' = 'read') AS reads,
                   count(*) FILTER (WHERE raw->'ot'->>'operation' = 'write') AS writes,
                   count(*) FILTER (WHERE raw->'ot'->>'operation' = 'control') AS controls
            FROM events
            WHERE log_type = ANY(%(p)s)
              AND event_time >= now() - make_interval(days => %(d)s)
            GROUP BY log_type ORDER BY events DESC
            """,
            {"p": list(OT_PROTOCOLS), "d": days}).fetchall()


# Columns a correlation rule may filter / group on (whitelist: never f-string
# user-supplied column names into SQL without this gate).
_CORR_COLS = {"vendor", "product", "log_type", "severity", "action", "src_ip",
              "dst_ip", "src_port", "dst_port", "protocol", "app", "user_name",
              "host_name", "rule_name"}
_CORR_IP_COLS = {"src_ip", "dst_ip"}


# --------------------------------------------------------------------------- #
#  Users & sessions (auth)                                                     #
# --------------------------------------------------------------------------- #
def count_users() -> int:
    with pool().connection() as conn:
        return int(conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"])


def create_user(username: str, password_hash: str, role: str) -> int:
    with pool().connection() as conn:
        row = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) "
            "RETURNING id", (username, password_hash, role)).fetchone()
        conn.commit()
        return row["id"]


def get_user_by_name(username: str) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute("SELECT * FROM users WHERE username = %s", (username,)).fetchone()


def list_users() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT id, username, role, enabled, created_at, last_login "
            "FROM users ORDER BY username").fetchall()


def set_user_enabled(user_id: int, enabled: bool) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE users SET enabled = %s WHERE id = %s", (enabled, user_id))
        conn.commit()


def set_user_role(user_id: int, role: str) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
        conn.commit()


def is_last_admin(user_id: int) -> bool:
    """True if `user_id` is an enabled admin and no OTHER enabled admin exists —
    so demoting / disabling them would lock everyone out of admin."""
    with pool().connection() as conn:
        me = conn.execute("SELECT role, enabled FROM users WHERE id = %s",
                          (user_id,)).fetchone()
        others = conn.execute(
            "SELECT count(*) AS n FROM users "
            "WHERE role = 'admin' AND enabled = true AND id <> %s", (user_id,)).fetchone()
    is_admin_now = bool(me) and me["role"] == "admin" and me["enabled"]
    return is_admin_now and int(others["n"]) == 0


def set_user_password(user_id: int, password_hash: str) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                     (password_hash, user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))  # force re-login
        conn.commit()


def update_last_login(user_id: int) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE users SET last_login = now() WHERE id = %s", (user_id,))
        conn.commit()


def create_session(token: str, user_id: int, expires_at) -> None:
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
            (token, user_id, expires_at))
        conn.commit()


def get_session_user(token: str) -> Optional[dict]:
    """Return the enabled user for a non-expired session token, else None."""
    if not token:
        return None
    with pool().connection() as conn:
        return conn.execute(
            "SELECT u.id, u.username, u.role, u.enabled FROM sessions s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE s.token = %s AND s.expires_at > now() AND u.enabled", (token,)).fetchone()


def delete_session(token: str) -> None:
    with pool().connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()


def add_audit(username: Optional[str], action: str,
              detail: Optional[str] = None, ip: Optional[str] = None) -> None:
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (username, action, detail, ip) VALUES (%s, %s, %s, %s)",
            (username, action, detail, ip))
        conn.commit()


def recent_audit(limit: int = 200) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s", (limit,)).fetchall()


# --------------------------------------------------------------------------- #
#  Threat intelligence (IOCs)                                                  #
# --------------------------------------------------------------------------- #
_IOC_INSERT = """
INSERT INTO iocs (indicator, ioc_type, source, severity, description)
VALUES (%(indicator)s, %(ioc_type)s, %(source)s, %(severity)s, %(description)s)
ON CONFLICT (indicator, ioc_type) DO UPDATE SET
    source = EXCLUDED.source, severity = EXCLUDED.severity,
    description = EXCLUDED.description, added_at = now(), enabled = true
"""


def _ioc_row(ioc: Any) -> dict:
    return {"indicator": ioc.indicator, "ioc_type": ioc.ioc_type, "source": ioc.source,
            "severity": ioc.severity, "description": ioc.description or None}


def upsert_iocs(iocs: Iterable[Any]) -> int:
    rows = [_ioc_row(i) for i in iocs]
    if not rows:
        return 0
    with pool().connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(_IOC_INSERT, rows)
        conn.commit()
    return len(rows)


def replace_source_iocs(source: str, iocs: Iterable[Any]) -> int:
    """Swap in a feed's indicators: drop this source's rows, insert the fresh set."""
    rows = [_ioc_row(i) for i in iocs]
    with pool().connection() as conn:
        conn.execute("DELETE FROM iocs WHERE source = %s", (source,))
        if rows:
            with conn.cursor() as cur:
                cur.executemany(_IOC_INSERT, rows)
        conn.commit()
    return len(rows)


def enabled_iocs() -> list[dict]:
    """Indicators the matcher should load (enabled and not expired)."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT indicator, ioc_type, source, severity, description FROM iocs "
            "WHERE enabled AND (expires_at IS NULL OR expires_at > now())").fetchall()


def ioc_counts() -> dict:
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT ioc_type, count(*) AS n FROM iocs WHERE enabled GROUP BY ioc_type"
        ).fetchall()
    d = {r["ioc_type"]: int(r["n"]) for r in rows}
    d["total"] = sum(d.values())
    return d


def list_iocs(limit: int = 100) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM iocs ORDER BY added_at DESC LIMIT %s", (limit,)).fetchall()


def delete_ioc(indicator: str, ioc_type: str) -> None:
    with pool().connection() as conn:
        conn.execute("DELETE FROM iocs WHERE indicator = %s AND ioc_type = %s",
                     (indicator, ioc_type))
        conn.commit()


def sync_collectors(names: Iterable[str]) -> None:
    """Ensure a state row exists for each available collector (preserving cursor)."""
    with pool().connection() as conn:
        for n in names:
            conn.execute("INSERT INTO collectors (name) VALUES (%s) "
                         "ON CONFLICT (name) DO NOTHING", (n,))
        conn.commit()


def get_collector(name: str) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute("SELECT * FROM collectors WHERE name = %s", (name,)).fetchone()


def update_collector(name: str, **fields: Any) -> None:
    """Update a collector's state; `last_run` is always stamped to now()."""
    sets = "last_run = now()" + "".join(f", {k} = %({k})s" for k in fields)
    fields["name"] = name
    with pool().connection() as conn:
        conn.execute(f"UPDATE collectors SET {sets} WHERE name = %(name)s", fields)
        conn.commit()


def list_collectors() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute("SELECT * FROM collectors ORDER BY name").fetchall()


def enabled_collector_names() -> set[str]:
    with pool().connection() as conn:
        rows = conn.execute("SELECT name FROM collectors WHERE enabled").fetchall()
    return {r["name"] for r in rows}


def set_collector_enabled(name: str, enabled: bool) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE collectors SET enabled = %s WHERE name = %s", (enabled, name))
        conn.commit()


def add_saved_search(owner: str, name: str, path: str, query: str) -> None:
    """Save (or overwrite) a named query for one owner+path."""
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO saved_searches (owner, name, path, query) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (owner, name, path) DO UPDATE "
            "SET query = EXCLUDED.query, created_at = now()",
            (owner, name, path, query))
        conn.commit()


def list_saved_searches(owner: str, path: str | None = None) -> list[dict]:
    """An owner's saved searches, optionally scoped to one page."""
    sql = "SELECT * FROM saved_searches WHERE owner = %s"
    args: list = [owner]
    if path:
        sql += " AND path = %s"
        args.append(path)
    sql += " ORDER BY path, name"
    with pool().connection() as conn:
        return conn.execute(sql, args).fetchall()


def delete_saved_search(search_id: int, owner: str) -> None:
    """Delete by id, scoped to owner so one user can't remove another's."""
    with pool().connection() as conn:
        conn.execute("DELETE FROM saved_searches WHERE id = %s AND owner = %s",
                     (search_id, owner))
        conn.commit()


def insert_response_action(rec: dict) -> None:
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO response_actions "
            "(alert_id, playbook_id, action_type, target, status, detail, revert_at) "
            "VALUES (%(alert_id)s, %(playbook_id)s, %(action_type)s, %(target)s, "
            "%(status)s, %(detail)s, %(revert_at)s)", rec)
        conn.commit()


def recent_responses(limit: int = 200) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM response_actions ORDER BY created_at DESC LIMIT %s",
            (limit,)).fetchall()


def responses_for_alert(alert_id: int) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM response_actions WHERE alert_id = %s ORDER BY created_at DESC",
            (alert_id,)).fetchall()


def due_reverts(now: dt.datetime, limit: int = 200) -> list[dict]:
    """Successful, time-boxed response actions whose revert_at has passed and
    that have not been reverted yet — the ones the revert scheduler must undo."""
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM response_actions "
            "WHERE reverted_at IS NULL AND revert_at IS NOT NULL "
            "AND revert_at <= %s AND status = 'success' "
            "ORDER BY revert_at LIMIT %s", (now, limit)).fetchall()


def mark_reverted(action_id: int, when: dt.datetime) -> None:
    with pool().connection() as conn:
        conn.execute("UPDATE response_actions SET reverted_at = %s WHERE id = %s",
                     (when, action_id))
        conn.commit()


def correlate(match: dict, group_by: list[str], window_seconds: int,
              threshold: int, distinct_col: Optional[str] = None) -> list[dict]:
    """Aggregate events in the last `window_seconds`, grouped by `group_by`,
    returning groups whose count reaches `threshold`. By default the count is of
    events; if `distinct_col` (a whitelisted column not already grouped on) is
    given, it is instead the number of *distinct* values of that column — so a
    rule can fire on "one src_ip → N distinct user_name failed logons" (password
    spray) or "N distinct dst_port" (port scan). Column names are whitelisted;
    all values are parameterized."""
    cols = [c for c in group_by if c in _CORR_COLS]
    if not cols:
        return []
    dc = distinct_col if (distinct_col in _CORR_COLS and distinct_col not in cols) else None
    count_expr = f"count(distinct {dc})" if dc else "count(*)"
    select = [f"host({c}) AS {c}" if c in _CORR_IP_COLS else c for c in cols]
    where = ["event_time >= now() - make_interval(secs => %(_win)s)"]
    p: dict[str, Any] = {"_win": int(window_seconds), "_th": int(threshold)}
    for i, (col, val) in enumerate(match.items()):
        if col not in _CORR_COLS:
            continue
        key = f"m{i}"
        if isinstance(val, list):
            where.append(f"lower({col}::text) = ANY(%({key})s)")
            p[key] = [str(v).lower() for v in val]
        else:
            where.append(f"lower({col}::text) = lower(%({key})s)")
            p[key] = str(val)
    where += [f"{c} IS NOT NULL" for c in cols]
    if dc:
        where.append(f"{dc} IS NOT NULL")
    q = (f"SELECT {', '.join(select)}, {count_expr} AS n, "
         f"min(event_time) AS first_seen, max(event_time) AS last_seen "
         f"FROM events WHERE {' AND '.join(where)} "
         f"GROUP BY {', '.join(cols)} HAVING {count_expr} >= %(_th)s")
    with pool().connection() as conn:
        return conn.execute(q, p).fetchall()


# --------------------------------------------------------------------------- #
#  Search                                                                      #
# --------------------------------------------------------------------------- #
def _ip_clause(col: str, value: str, params: dict, key: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        params[key] = f"%{v}%"
        return f"host({col}) ILIKE %({key})s"
    if "/" in v:
        params[key] = v
        return f"{col} <<= %({key})s::inet"
    params[key] = v
    return f"{col} = %({key})s::inet"


def _where(f: dict) -> tuple[str, dict]:
    clauses: list[str] = []
    p: dict[str, Any] = {}
    if f.get("vendor"):
        clauses.append("vendor = %(vendor)s"); p["vendor"] = f["vendor"]
    if f.get("log_type"):
        clauses.append("log_type = %(log_type)s"); p["log_type"] = f["log_type"]
    if f.get("severity"):
        clauses.append("lower(severity) = lower(%(severity)s)"); p["severity"] = f["severity"]
    if f.get("action"):
        clauses.append("lower(action) = lower(%(action)s)"); p["action"] = f["action"]
    if f.get("src_ip"):
        clauses.append(_ip_clause("src_ip", f["src_ip"], p, "src_ip"))
    if f.get("dst_ip"):
        clauses.append(_ip_clause("dst_ip", f["dst_ip"], p, "dst_ip"))
    if f.get("user"):
        clauses.append("user_name ILIKE %(user)s"); p["user"] = f"%{f['user']}%"
    if f.get("host"):
        clauses.append("host_name ILIKE %(host)s"); p["host"] = f"%{f['host']}%"
    if f.get("time_from"):
        clauses.append("event_time >= %(time_from)s"); p["time_from"] = f["time_from"]
    if f.get("time_to"):
        clauses.append("event_time <= %(time_to)s"); p["time_to"] = f["time_to"]
    if f.get("q"):
        clauses.append("search_tsv @@ websearch_to_tsquery('simple', %(q)s)"); p["q"] = f["q"]
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, p


def search(filters: dict, limit: int, offset: int) -> tuple[list[dict], int]:
    where, p = _where(filters)
    with pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM events {where}", p).fetchone()["n"]
        p2 = dict(p, _limit=limit, _offset=offset)
        rows = conn.execute(
            f"SELECT {_SEARCH_COLS} FROM events {where} "
            f"ORDER BY event_time DESC LIMIT %(_limit)s OFFSET %(_offset)s", p2).fetchall()
    return rows, int(total)


def search_iter(filters: dict, cap: int = 100_000):
    """Stream rows for CSV export (bounded by cap)."""
    where, p = _where(filters)
    p["_cap"] = cap
    with pool().connection() as conn, conn.cursor(name="export_cur") as cur:
        cur.execute(f"SELECT {_SEARCH_COLS} FROM events {where} "
                    f"ORDER BY event_time DESC LIMIT %(_cap)s", p)
        for row in cur:
            yield row


def get_event(event_id: int) -> Optional[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT id, event_time, ingested_at, vendor, product, log_type, severity, "
            "action, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port, "
            "protocol, app, user_name, host_name, rule_name, bytes_total, message, raw, "
            "batch_id FROM events WHERE id = %s", (event_id,)).fetchone()


def event_id_for(dedup_hash: str, event_time) -> Optional[int]:
    """Resolve the originating event id for an alert (events are keyed by
    dedup_hash + event_time), for drill-down. None if not found."""
    with pool().connection() as conn:
        row = conn.execute(
            "SELECT id FROM events WHERE dedup_hash = %s AND event_time = %s LIMIT 1",
            (dedup_hash, event_time)).fetchone()
    return row["id"] if row else None


def distinct_values(column: str, days: int = 365) -> list[str]:
    if column not in ("vendor", "log_type", "severity", "action"):
        return []
    with pool().connection() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT {column} AS v FROM events "
            f"WHERE event_time >= now() - make_interval(days => %s) AND {column} IS NOT NULL "
            f"ORDER BY 1 LIMIT 200", (days,)).fetchall()
    return [r["v"] for r in rows]


# --------------------------------------------------------------------------- #
#  Stats (dashboard)                                                           #
# --------------------------------------------------------------------------- #
def stats() -> dict:
    with pool().connection() as conn:
        total = conn.execute(
            "SELECT COALESCE(sum(inserted_rows), 0) AS n FROM ingest_batches "
            "WHERE status = 'done'").fetchone()["n"]
        by_vendor = conn.execute(
            "SELECT vendor, COALESCE(sum(inserted_rows),0) AS n FROM ingest_batches "
            "WHERE status='done' GROUP BY vendor ORDER BY 2 DESC").fetchall()
        span = conn.execute(
            "SELECT min(event_time) AS first, max(event_time) AS last FROM events").fetchone()
        daily = conn.execute(
            "SELECT date_trunc('day', event_time)::date AS day, count(*) AS n FROM events "
            "WHERE event_time >= now() - interval '30 days' GROUP BY 1 ORDER BY 1").fetchall()
        by_logtype = conn.execute(
            "SELECT log_type, count(*) AS n FROM events "
            "WHERE event_time >= now() - interval '30 days' GROUP BY 1 ORDER BY 2 DESC LIMIT 12"
        ).fetchall()
        size = conn.execute(
            "SELECT pg_size_pretty(COALESCE(sum(pg_total_relation_size(inhrelid)),0)) AS sz "
            "FROM pg_inherits WHERE inhparent = 'events'::regclass").fetchone()["sz"]
        parts = conn.execute(
            "SELECT c.relname AS name, c.reltuples::bigint AS est_rows, "
            "pg_size_pretty(pg_total_relation_size(c.oid)) AS size "
            "FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass ORDER BY c.relname DESC").fetchall()
    return {"total": int(total), "by_vendor": by_vendor, "first": span["first"],
            "last": span["last"], "daily": daily, "by_logtype": by_logtype,
            "size": size, "partitions": parts}


# --------------------------------------------------------------------------- #
#  Retention                                                                   #
# --------------------------------------------------------------------------- #
def retention_cutoff_key(today: dt.date, years: int, floor_years: int) -> int:
    """The YYYYMM below which partitions may be purged: the first month `years`
    (clamped up to `floor_years`) *calendar* years ago. Pure + testable; uses
    calendar arithmetic (not day deltas) so it never drifts off a month boundary."""
    years = max(int(years), int(floor_years))
    cutoff = today.replace(day=1, year=today.year - years)
    return cutoff.year * 100 + cutoff.month


def purge_older_than(years: int) -> list[str]:
    """Drop monthly partitions whose month is entirely older than `years` calendar
    years. The RETENTION_YEARS floor is enforced *here* (not just by callers), so
    this can never purge below policy. events_default is never dropped."""
    cutoff_key = retention_cutoff_key(dt.date.today(), years, settings.retention_years)
    dropped: list[str] = []
    with pool().connection() as conn:
        parts = conn.execute(
            "SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'events'::regclass AND c.relname ~ '^events_[0-9]{6}$'"
        ).fetchall()
        for row in parts:
            name = row["name"]
            try:
                key = int(name.split("_")[1])  # YYYYMM
            except (ValueError, IndexError):
                continue
            if key < cutoff_key:
                conn.execute(f"DROP TABLE IF EXISTS {name}")
                dropped.append(name)
        conn.commit()
    return dropped


# ------------------------------------------------------------- custom parsers
def list_custom_parsers() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM custom_parsers ORDER BY title").fetchall()


def enabled_custom_parsers() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT parser_id, match_key, match_value, field_map, vendor, product, "
            "kv_source, kv_sep FROM custom_parsers WHERE enabled").fetchall()


def upsert_custom_parser(parser_id: str, title: str, match_key: str,
                         match_value: str, field_map: dict,
                         vendor=None, product=None, enabled: bool = True,
                         kv_source=None, kv_sep=None) -> None:
    import json as _json
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO custom_parsers "
            "(parser_id, title, match_key, match_value, field_map, vendor, product, enabled, "
            "kv_source, kv_sep) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (parser_id) DO UPDATE SET title = EXCLUDED.title, "
            "match_key = EXCLUDED.match_key, match_value = EXCLUDED.match_value, "
            "field_map = EXCLUDED.field_map, vendor = EXCLUDED.vendor, "
            "product = EXCLUDED.product, enabled = EXCLUDED.enabled, "
            "kv_source = EXCLUDED.kv_source, kv_sep = EXCLUDED.kv_sep",
            (parser_id, title, match_key, match_value, _json.dumps(field_map),
             vendor, product, enabled, kv_source, kv_sep))
        conn.commit()


def delete_custom_parser(parser_id: str) -> None:
    with pool().connection() as conn:
        conn.execute("DELETE FROM custom_parsers WHERE parser_id = %s", (parser_id,))
        conn.commit()


# ------------------------------------------------------------- custom rules
def list_custom_rules() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT * FROM custom_rules ORDER BY title").fetchall()


def all_custom_rule_yaml() -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT rule_id, yaml_text FROM custom_rules").fetchall()


def upsert_custom_rule(rule_id: str, title: str, yaml_text: str,
                       enabled: bool = True) -> None:
    with pool().connection() as conn:
        conn.execute(
            "INSERT INTO custom_rules (rule_id, title, yaml_text, enabled) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (rule_id) DO UPDATE SET title = EXCLUDED.title, "
            "yaml_text = EXCLUDED.yaml_text, enabled = EXCLUDED.enabled",
            (rule_id, title, yaml_text, enabled))
        conn.commit()


def delete_custom_rule(rule_id: str) -> None:
    with pool().connection() as conn:
        conn.execute("DELETE FROM custom_rules WHERE rule_id = %s", (rule_id,))
        conn.execute("DELETE FROM detection_rules WHERE rule_id = %s", (rule_id,))
        conn.commit()


def recent_events_for_test(limit: int = 200) -> list[dict]:
    with pool().connection() as conn:
        return conn.execute(
            "SELECT event_time, vendor, product, log_type, severity, action, "
            "host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, src_port, dst_port, "
            "protocol, app, user_name, host_name, rule_name, message, raw "
            "FROM events ORDER BY event_time DESC LIMIT %s", (limit,)).fetchall()

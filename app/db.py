"""PostgreSQL access layer: pool, schema/partition management, insert, search,
stats, batch tracking, and retention purge."""
from __future__ import annotations

import datetime as dt
import ipaddress
import secrets
from pathlib import Path
from typing import Any, Iterable, Optional

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .config import settings
from .models import NormalizedEvent
from .normalize import dedup_hash, tsv_text
from .util import hash_api_key

_pool: Optional[ConnectionPool] = None
_SCHEMA = (Path(__file__).resolve().parent.parent / "schema.sql").read_text(encoding="utf-8")

_INSERT = """
INSERT INTO events (event_time, vendor, product, log_type, severity, action,
    src_ip, dst_ip, src_port, dst_port, protocol, app, user_name, host_name,
    rule_name, bytes_total, message, raw, search_tsv, batch_id, dedup_hash)
VALUES (%(event_time)s, %(vendor)s, %(product)s, %(log_type)s, %(severity)s, %(action)s,
    %(src_ip)s::inet, %(dst_ip)s::inet, %(src_port)s, %(dst_port)s, %(protocol)s, %(app)s,
    %(user_name)s, %(host_name)s, %(rule_name)s, %(bytes_total)s, %(message)s,
    %(raw)s, to_tsvector('simple', %(tsv)s), %(batch_id)s, %(dedup_hash)s)
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


def init_schema() -> None:
    """Run schema.sql (split into statements; no functions/DO blocks present)."""
    with pool().connection() as conn:
        for stmt in (s.strip() for s in _SCHEMA.split(";")):
            if stmt:
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
#  Ingest                                                                      #
# --------------------------------------------------------------------------- #
def _row(evt: NormalizedEvent, batch_id: int) -> dict[str, Any]:
    return {
        "event_time": evt.event_time, "vendor": evt.vendor, "product": evt.product,
        "log_type": evt.log_type, "severity": evt.severity, "action": evt.action,
        "src_ip": evt.src_ip, "dst_ip": evt.dst_ip, "src_port": evt.src_port,
        "dst_port": evt.dst_port, "protocol": evt.protocol, "app": evt.app,
        "user_name": evt.user_name, "host_name": evt.host_name, "rule_name": evt.rule_name,
        "bytes_total": evt.bytes_total, "message": evt.message,
        "raw": Jsonb(evt.raw), "tsv": tsv_text(evt), "batch_id": batch_id,
        "dedup_hash": dedup_hash(evt),
    }


def insert_events(conn, events: list[NormalizedEvent], batch_id: int) -> None:
    if not events:
        return
    months = {(e.event_time.year, e.event_time.month) for e in events if e.event_time}
    ensure_partitions(conn, months)
    rows = [_row(e, batch_id) for e in events]
    with conn.cursor() as cur:
        cur.executemany(_INSERT, rows)


# --------------------------------------------------------------------------- #
#  Batch tracking                                                              #
# --------------------------------------------------------------------------- #
def create_batch(filename: Optional[str], sha: Optional[str], vendor: Optional[str],
                 fmt: str, source_type: str = "upload",
                 source_addr: Optional[str] = None) -> int:
    with pool().connection() as conn:
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
def purge_older_than(years: int) -> list[str]:
    """Drop monthly partitions whose month is entirely older than `years`.
    Returns the names of dropped partitions. events_default is never dropped."""
    cutoff = (dt.date.today().replace(day=1) - dt.timedelta(days=int(years * 365.25)))
    cutoff_key = cutoff.year * 100 + cutoff.month
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

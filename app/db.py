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
    user_name, host_name, message, dedup_hash, batch_id, status, assignee"""


def recent_alerts(filters: dict, limit: int, offset: int) -> tuple[list[dict], int]:
    where, p = _alert_where(filters)
    with pool().connection() as conn:
        total = conn.execute(f"SELECT count(*) AS n FROM alerts {where}", p).fetchone()["n"]
        p2 = dict(p, _limit=limit, _offset=offset)
        rows = conn.execute(
            f"SELECT {_ALERT_COLS} FROM alerts {where} "
            f"ORDER BY created_at DESC LIMIT %(_limit)s OFFSET %(_offset)s", p2).fetchall()
    return rows, int(total)


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


def alert_severity_counts() -> dict:
    """Open-alert counts by level, for the dashboard."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT level, count(*) AS n FROM alerts WHERE status = 'open' "
            "GROUP BY level").fetchall()
    return {r["level"]: int(r["n"]) for r in rows}


def alert_technique_counts(days: int = 30) -> dict:
    """Recent alert counts per MITRE technique (techniques is a text[]), for the
    compliance view."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT t AS technique, count(*) AS n FROM alerts, unnest(techniques) t "
            "WHERE created_at >= now() - make_interval(days => %s) GROUP BY t",
            (days,)).fetchall()
    return {r["technique"]: int(r["n"]) for r in rows}


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


def correlate(match: dict, group_by: list[str], window_seconds: int,
              threshold: int) -> list[dict]:
    """Aggregate events in the last `window_seconds`, grouped by `group_by`,
    returning groups with at least `threshold` events. Column names are
    whitelisted; all values are parameterized."""
    cols = [c for c in group_by if c in _CORR_COLS]
    if not cols:
        return []
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
    q = (f"SELECT {', '.join(select)}, count(*) AS n, "
         f"min(event_time) AS first_seen, max(event_time) AS last_seen "
         f"FROM events WHERE {' AND '.join(where)} "
         f"GROUP BY {', '.join(cols)} HAVING count(*) >= %(_th)s")
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

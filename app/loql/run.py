# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The LOQL execution boundary — the only part of the package that touches Postgres.

It compiles the query (pure), then runs the emitted parameterized SQL under
guardrails so one heavy analyst query can never starve ingest on the shared
instance: a ``statement_timeout``, a hard ``LIMIT`` baked into the SQL, and a
``fetchmany`` row cap. A query that is compile-valid but fails at execution (e.g. a
numeric op on a text field) is surfaced as a clean, bounded ``LoqlError`` — never a
raw traceback. Timestamps are rendered in the display timezone (IST) like the rest
of the app; Decimals become floats so the result is JSON-serialisable as-is.

The timeout is applied with ``SELECT set_config('statement_timeout', %s, true)`` and
NOT with ``SET LOCAL statement_timeout = %s``. psycopg3 binds server-side, so the
latter reaches PostgreSQL as ``SET LOCAL statement_timeout = $1`` — and ``SET`` is a
utility statement whose grammar (``var_value: opt_boolean_or_string | NumericOnly``)
has no ParamRef production at all, so the parse fails with SQLSTATE 42601 before the
query itself is ever sent. ``set_config(text, text, bool)`` is an ordinary function
call in an ordinary ``SELECT``, so it takes a parameter like anything else; the third
argument ``true`` is what makes it ``LOCAL`` (reverted when the transaction ends).
Two statements execute here and that is the only one that is not a plain ``SELECT`` —
if a third is ever added, check it is not a utility statement (``SET``/``RESET``/
``SHOW``/``LISTEN``…) before parameterizing it.
"""
from __future__ import annotations

import time
from datetime import datetime
from decimal import Decimal

from psycopg.rows import dict_row

from ..util import to_ist
from .compiler import compile_query
from .errors import LoqlError

# `SET LOCAL` cannot be parameterized (see the module docstring); this can.
_TIMEOUT_SQL = "SELECT set_config('statement_timeout', %s, true)"


def _cell(v):
    if isinstance(v, datetime):
        return to_ist(v).isoformat()
    if isinstance(v, Decimal):
        return float(v)
    return v


def _clean(msg: str) -> str:
    return " ".join(str(msg).split())[:300]


def run_query(query, *, limit: int = 1000, max_rows: int = 100_000,
              timeout_ms: int = 30_000, base_where: str = "", base_params=None) -> dict:
    """Compile + execute a LOQL query, guarded. Returns
    ``{query, fields, rows, count, elapsed_ms, truncated}``."""
    from .. import db
    from ..config import settings

    lim = max(1, min(int(limit), int(max_rows)))
    sql, params = compile_query(query, base_where=base_where, base_params=base_params,
                                default_limit=lim, max_agg_elems=settings.loql_max_agg_elems)
    # set_config takes TEXT; 0 is PostgreSQL's own spelling for "no timeout", and a
    # negative value is out of range, so it clamps to 0 rather than erroring server-side.
    timeout = str(max(0, int(timeout_ms)))
    t0 = time.monotonic()
    try:
        with db.pool().connection() as conn:
            with conn.transaction():
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(_TIMEOUT_SQL, (timeout,))
                    # `params` is passed even when it is EMPTY: psycopg only un-escapes a
                    # doubled `%%` (the modulo operator's emission) when it is given a
                    # parameter sequence, so `cur.execute(sql)` would ship `%%` literally.
                    cur.execute(sql, params)
                    fields = [d.name for d in cur.description] if cur.description else []
                    rows = cur.fetchmany(int(max_rows))
    except LoqlError:
        raise
    except Exception as exc:  # noqa: BLE001 — a valid compile can still fail at run
        raise LoqlError(f"query failed: {_clean(exc)}")
    out = [{k: _cell(v) for k, v in r.items()} for r in rows]
    return {"query": query if isinstance(query, str) else "", "fields": fields,
            "rows": out, "count": len(out), "elapsed_ms": int((time.monotonic() - t0) * 1000),
            "truncated": len(out) >= lim}

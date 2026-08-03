# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""LOQL — LogOcean Query Language.

A pipelined search/transform language (``search | where | stats | timechart | ...``)
that compiles to **parameterized SQL** over the month-partitioned ``events`` table.
LOQL is Backbone #1 of the Splunk-class transformation (see
``docs/SPLUNK_TRANSFORMATION_ROADMAP.md``): analyst hunting, dashboards, saved
searches, and — crucially — the single, un-bypassable place a per-role row filter
(``srchFilter``) and field masking will later be injected all hang off this compiler.

Design invariants (charter):
  * **No string-interpolated user input, ever.** Every literal, field key, and glob
    the user supplies becomes a bound parameter; the compiler emits only fixed SQL
    skeletons + a params list. This is the whole security story.
  * **No ``eval``/``exec``.** ``where``/``eval`` expressions are a closed, typed grammar
    compiled to SQL — never Python evaluated.
  * **Pure + snapshot-testable.** ``compile_query`` is a pure function
    (query text → parse tree → ``(sql, params)``); it needs no database, so the SQL
    it emits is unit-tested by assertion. Only ``run_query`` touches Postgres.
  * **Schema-on-read.** A referenced field that is not a known ``events`` column is
    read from the ``raw`` jsonb (``raw ->> key``) with the key bound as a parameter.

Batch 1 command set: search · where · eval · fields · rename · sort · head · dedup ·
stats · top · rare · bin · timechart · datamodel. The last of those is the CIM source
(``| datamodel Authentication`` / ``from datamodel:Authentication``), which landed with
Backbone #2 — it projects a model's vendor-agnostic field names over the GIN-indexed
``cim_models`` membership column (see ``app/cim/`` and ``docs/CIM.md``). (Window verbs
eventstats/streamstats/transaction, rex/spath, macros, and lookup follow in batch 2.)
"""
from __future__ import annotations

from .errors import LoqlError
from .parser import parse
from .compiler import compile_query

__all__ = ["LoqlError", "parse", "compile_query", "run_query"]


def run_query(query: str, *, limit: int = 1000, max_rows: int = 100_000,
              timeout_ms: int = 30_000, base_where: str = "", base_params=None):
    """Compile + execute a LOQL query against Postgres, guarded. Impure boundary —
    imported lazily so the pure compiler + its tests never require a database."""
    from .run import run_query as _run
    return _run(query, limit=limit, max_rows=max_rows, timeout_ms=timeout_ms,
                base_where=base_where, base_params=base_params)

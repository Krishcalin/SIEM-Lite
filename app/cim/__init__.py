# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""CIM (Common Information Model) — LogOcean's versioned, vendor-agnostic data models.

A data model is a named schema (Authentication, Network, Web, DNS, Endpoint, Change,
Malware, IDS, Email, Vulnerability, Industrial) plus a membership rule that decides which
events belong to it. Detections and ``datamodel:`` searches bind to a model, not a
vendor, so onboarding a new source is a registry edit — not a code change.

Layers:
  * :mod:`app.cim.spec`     — the frozen dataclasses (the contract).
  * :mod:`app.cim.registry` — loads + validates ``models.yaml`` into that contract.
  * :mod:`app.cim.match`    — the Python evaluator: ``tags_for(evt)`` returns the model
                              tags an event belongs to.
  * :mod:`app.cim.sql`      — turns the registry into one ``cim_<tag>`` view per model
                              (injection-safe DDL).

Membership is materialized in ``events.cim_models text[]`` — a PLAIN column declared in
``schema.sql`` and filled per row at ingest from ``match.tags_for(evt)``, exactly the way
``search_tsv`` is filled from ``normalize.tsv_text(evt)``. Doing it in Python (rather
than as a generated column) is what lets detection see model membership *before* the row
is inserted, and keeps the rule rewritable on PostgreSQL 16.

The DDL apply step lives in :func:`app.db.init_cim` and re-derives existing rows via
``app.db.backfill_cim``; the LOQL ``datamodel:`` search source consumes
:func:`get_registry` directly (pure — no database needed to compile a query).
"""
from __future__ import annotations

from . import registry, sql                       # submodules (keep the names un-shadowed)
from .match import cim_models_for, clause_matches, model_matches, tags_for, term_matches
from .registry import get_registry, load, reload
from .spec import (CimClause, CimError, CimField, CimModel, CimRegistry, CimSource,
                   CimTerm)
from .sql import (create_view_ddl, ddl_statements, field_value_sql, membership_predicate,
                  membership_sql, source_sql, view_name)

__all__ = ["registry", "sql", "match", "get_registry", "load", "reload",
           "tags_for", "cim_models_for", "term_matches", "clause_matches", "model_matches",
           "CimError", "CimSource", "CimField", "CimTerm", "CimClause", "CimModel",
           "CimRegistry", "membership_sql", "membership_predicate", "source_sql",
           "field_value_sql", "view_name", "create_view_ddl", "ddl_statements"]

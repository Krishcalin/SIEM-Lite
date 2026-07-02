"""OT / ICS analysis helpers (pure, unit-testable).

Phase D of the OT capability set: turn the OT events LogOcean already stores (the
Zeek-ICSNPP-enriched `modbus` / `dnp3` / `s7comm` / `cip` … records — see
``app/parsers/zeek_ics.py``) into operator-facing analytics for the ``/ot`` page:

* **asset inventory** — the controllers (PLCs / RTUs) seen on the wire, the OT
  protocols they speak, how many masters talk to each, and their control-op volume;
* **master ↔ controller conversations** — who talks to each controller, with a
  behavioural class so a *new* source issuing writes/control to a PLC stands out
  (the highest-value OT signal: an unexpected engineering client);
* **activity summary** — read / write / control volume per protocol.

The SQL aggregation lives in ``db.ot_*`` (grouping over the ``events`` table); this
module holds the DB-free classification/summarisation so it can be unit-tested
without a database, mirroring ``app/risk.py`` / ``app/killchain.py``.
"""
from __future__ import annotations

from typing import Any, Iterable

# Canonical OT/ICS protocol tags (the `log_type` the Zeek-ICSNPP enrichment sets).
# Single source of truth: `db.ot_*` filters `events.log_type` on this list.
OT_PROTOCOLS: tuple[str, ...] = (
    "modbus", "dnp3", "s7comm", "cip", "enip", "bacnet",
    "iec104", "opcua", "profinet",
)


def is_ot_protocol(log_type: Any) -> bool:
    return str(log_type or "").lower() in OT_PROTOCOLS


def classify_conversation(conv: dict) -> str:
    """Behavioural class for a master→controller conversation.

    * ``new-writer`` — a source first seen in the window that is issuing **writes
      or control** commands to a controller. An unexpected client reprogramming or
      commanding a PLC is the signal an OT analyst most wants surfaced.
    * ``new`` — a first-seen conversation that is read-only so far.
    * ``known`` — an established conversation (baseline traffic).
    """
    is_new = bool(conv.get("is_new"))
    active = int(conv.get("writes") or 0) + int(conv.get("controls") or 0)
    if is_new and active:
        return "new-writer"
    if is_new:
        return "new"
    return "known"


def annotate_conversations(rows: Iterable[dict]) -> list[dict]:
    """Attach a behavioural ``class`` to each conversation row (see
    ``classify_conversation``). New writers are floated to the top."""
    out = [{**r, "class": classify_conversation(r)} for r in rows]
    order = {"new-writer": 0, "new": 1, "known": 2}
    out.sort(key=lambda r: (order.get(r["class"], 3),
                            -(int(r.get("writes") or 0) + int(r.get("controls") or 0)),
                            -int(r.get("events") or 0)))
    return out


def summarize_activity(rows: Iterable[dict]) -> dict:
    """Roll per-protocol activity rows up into totals for the summary cards."""
    total = {"events": 0, "reads": 0, "writes": 0, "controls": 0, "protocols": 0}
    for r in rows:
        events = int(r.get("events") or 0)
        total["events"] += events
        total["reads"] += int(r.get("reads") or 0)
        total["writes"] += int(r.get("writes") or 0)
        total["controls"] += int(r.get("controls") or 0)
        if events:
            total["protocols"] += 1
    return total

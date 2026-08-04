# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""CSV import/export for the asset & identity registry.

CSV because that is what a CMDB, an AD export and a spreadsheet all produce, and
because it is the format an operator can diff in review before applying. Pure: these
functions turn text into row dicts and back, and `app/db.py` does the writing — so
the parsing rules are unit-testable with no database.

THE IMPORT IS ALL-OR-NOTHING BY DEFAULT, and that is the important decision. A
half-applied asset import leaves the registry in a state nobody chose: some hosts
carry their new criticality, some do not, and `context_tags` on everything ingested
afterwards is a mixture of both. The plan/apply split below exists so an operator sees
exactly what would change — including which rows would be REFUSED for claiming another
entry's alias — before anything is written.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .models import ASSET_ALIAS_TYPES, IDENTITY_ALIAS_TYPES, normalize_level
from .normalize import norm_alias

#: Columns an asset import understands. `asset_id` is required; everything else is
#: optional, so a two-column file (id + criticality) is a valid import.
ASSET_COLUMNS = ("asset_id", "display_name", "criticality", "category", "owner",
                 "business_unit", "environment", "watchlist", "enabled", "notes")
IDENTITY_COLUMNS = ("identity_id", "display_name", "priority", "department",
                    "manager", "title", "email", "watchlist", "enabled", "notes")

#: Multi-valued cells are separated by these. Semicolon FIRST because a comma inside a
#: CSV cell needs the cell quoted, and half the exports in the world get that wrong.
_SEPARATORS = (";", "|", ",")


class CsvError(ValueError):
    """A malformed import — reported with the 1-based row number an operator sees."""


@dataclass
class ImportPlan:
    """What an import would do. Nothing is written to produce this."""

    rows: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: 1-based row numbers that carry no alias at all. Not an error — an operator may
    #: legitimately be editing criticality on rows declared elsewhere — but it IS
    #: worth surfacing, because such a row resolves nothing on its own.
    aliasless: list[int] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _split(cell: Any) -> list[str]:
    """A multi-valued cell -> clean lower-cased labels.

    The first separator PRESENT in the cell wins, rather than splitting on all three:
    a value that legitimately contains a comma (``Finance, EMEA``) would otherwise be
    shredded by a file that uses semicolons everywhere else.
    """
    s = str(cell or "").strip()
    if not s:
        return []
    for sep in _SEPARATORS:
        if sep in s:
            return [p.strip().lower() for p in s.split(sep) if p.strip()]
    return [s.lower()]


def _bool(cell: Any, default: bool = True) -> bool:
    s = str(cell or "").strip().lower()
    if not s:
        return default
    return s not in ("false", "0", "no", "n", "off", "disabled")


def _aliases_from_row(row: dict, types: tuple[str, ...], line: int) -> list[tuple[str, str]]:
    """Alias columns -> normalized ``(type, value)`` pairs.

    One column PER alias type (``hostname``, ``ip``, ``email`` …), each allowed to
    hold several values. That shape is what a CMDB export looks like, and it keeps the
    header self-describing — an operator can see which column feeds which identifier
    without reading a manual.
    """
    out: list[tuple[str, str]] = []
    for kind in types:
        for raw in _split(row.get(kind)):
            value = norm_alias(kind, raw)
            if value is None:
                raise CsvError(f"row {line}: {raw!r} is not a valid {kind}")
            out.append((kind, value))
    return out


def _read(text: str, *, key: str, columns: tuple[str, ...],
          alias_types: tuple[str, ...], level_field: str) -> ImportPlan:
    plan = ImportPlan()
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        plan.errors.append("the file has no header row")
        return plan

    header = {str(h or "").strip().lower() for h in reader.fieldnames}
    if key not in header:
        plan.errors.append(
            f"the header has no {key!r} column (found: {', '.join(sorted(header)) or 'nothing'})")
        return plan
    unknown = header - set(columns) - set(alias_types)
    if unknown:
        # Reported, never ignored: a mistyped `criticallity` column would otherwise be
        # dropped in silence and every row would import at the default level.
        plan.errors.append(
            f"unknown column(s): {', '.join(sorted(unknown))} — expected any of "
            f"{', '.join(columns + alias_types)}")
        return plan

    seen: dict[str, int] = {}
    for line, raw_row in enumerate(reader, start=2):        # 2 = the first data row
        row = {str(k or "").strip().lower(): v for k, v in raw_row.items() if k}
        ident = str(row.get(key) or "").strip()
        if not ident and not any(str(v or "").strip() for v in row.values()):
            continue                                        # a blank line
        if not ident:
            plan.errors.append(f"row {line}: {key} is empty")
            continue
        if ident in seen:
            # Two rows for one id is ambiguous — last-write-wins would silently pick
            # one, and which one depends on file order.
            plan.errors.append(
                f"row {line}: {key} {ident!r} appears twice (also on row {seen[ident]})")
            continue
        seen[ident] = line
        try:
            aliases = _aliases_from_row(row, alias_types, line)
        except CsvError as exc:
            plan.errors.append(str(exc))
            continue
        if not aliases:
            plan.aliasless.append(line)

        fields: dict[str, Any] = {key: ident, "aliases": aliases, "source": "csv"}
        for col in columns:
            if col == key:
                continue
            if col in ("category", "watchlist"):
                fields[col] = _split(row.get(col))
            elif col == "enabled":
                fields[col] = _bool(row.get(col))
            elif col == level_field:
                fields[col] = normalize_level(row.get(col) or "medium")
            else:
                fields[col] = str(row.get(col) or "").strip()
        plan.rows.append(fields)

    if not plan.rows and not plan.errors:
        plan.errors.append("the file has a valid header but no data rows")
    return plan


def read_assets(text: str) -> ImportPlan:
    return _read(text, key="asset_id", columns=ASSET_COLUMNS,
                 alias_types=ASSET_ALIAS_TYPES, level_field="criticality")


def read_identities(text: str) -> ImportPlan:
    return _read(text, key="identity_id", columns=IDENTITY_COLUMNS,
                 alias_types=IDENTITY_ALIAS_TYPES, level_field="priority")


# --------------------------------------------------------------------------- #
#  Export                                                                      #
# --------------------------------------------------------------------------- #
def _write(rows: Iterable[dict], *, key: str, columns: tuple[str, ...],
           alias_types: tuple[str, ...]) -> str:
    """Rows (as `db.list_assets` / `db.list_identities` return them) -> CSV text.

    ROUND-TRIPPABLE: the export writes exactly the columns the import reads, so
    `read_assets(export_assets(list_assets()))` reproduces the registry. That is what
    makes "export, edit in a spreadsheet, re-import" a supported workflow rather than
    a lossy one, and it is asserted by a test.
    """
    buf = io.StringIO()
    header = list(columns) + list(alias_types)
    writer = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        out: dict[str, Any] = {}
        for col in columns:
            value = row.get(col)
            if isinstance(value, (list, tuple)):
                out[col] = ";".join(str(v) for v in value)
            elif isinstance(value, bool):
                out[col] = "true" if value else "false"
            else:
                out[col] = "" if value is None else str(value)
        # `aliases` arrives from the DB as "type:value" strings; split them back into
        # one column per type, joined with the separator the reader prefers.
        by_type: dict[str, list[str]] = {t: [] for t in alias_types}
        for alias in row.get("aliases") or ():
            kind, _, value = str(alias).partition(":")
            if kind in by_type and value:
                by_type[kind].append(value)
        for kind, values in by_type.items():
            out[kind] = ";".join(values)
        writer.writerow(out)
    return buf.getvalue()


def export_assets(rows: Iterable[dict]) -> str:
    return _write(rows, key="asset_id", columns=ASSET_COLUMNS,
                  alias_types=ASSET_ALIAS_TYPES)


def export_identities(rows: Iterable[dict]) -> str:
    return _write(rows, key="identity_id", columns=IDENTITY_COLUMNS,
                  alias_types=IDENTITY_ALIAS_TYPES)


#: A ready-to-edit template, offered from the console so an operator starts from a
#: correct header instead of guessing at column names.
ASSET_TEMPLATE = _write([{
    "asset_id": "srv-db-01", "display_name": "Primary customer database",
    "criticality": "critical", "category": ["server", "pci"], "owner": "dbteam",
    "business_unit": "payments", "environment": "prod",
    "watchlist": ["crown-jewel"], "enabled": True, "notes": "",
    "aliases": ["hostname:srv-db-01", "fqdn:srv-db-01.corp.example",
                "ip:10.1.2.50"],
}], key="asset_id", columns=ASSET_COLUMNS, alias_types=ASSET_ALIAS_TYPES)

IDENTITY_TEMPLATE = _write([{
    "identity_id": "u-jdoe", "display_name": "John Doe", "priority": "high",
    "department": "finance", "manager": "a-smith", "title": "Controller",
    "email": "john.doe@corp.example", "watchlist": ["vip"], "enabled": True,
    "notes": "", "aliases": ["email:john.doe@corp.example",
                             "upn:jdoe@corp.example", "sam:corp\\jdoe"],
}], key="identity_id", columns=IDENTITY_COLUMNS, alias_types=IDENTITY_ALIAS_TYPES)

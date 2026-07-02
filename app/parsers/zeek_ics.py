"""ICS/OT protocol enrichment for Zeek logs (ICSNPP).

Zeek with the `ICSNPP <https://github.com/cisagov/icsnpp>`_ (Industrial Control
Systems Network Protocol Parsers, from CISA / INL) analyzers writes per-protocol
logs — ``modbus.log``, ``dnp3.log``, ``s7comm.log``, ``cip.log`` … — in the same
``#fields`` TSV / JSON shape as ``conn`` / ``dns`` / ``http``. The generic Zeek
parsers already read those, but the *meaning* of an OT record lives in
protocol-specific columns (Modbus function, DNP3 request, S7 block download, CIP
service) that don't map onto the network-oriented common schema.

This module is a small, pure enrichment layer the Zeek parsers call: given the
log's ``#path`` and the raw row, ``enrich`` returns a **normalized ``action``**
describing the control-plane operation (``write-registers`` / ``plc-stop`` /
``program-download`` / ``cold-restart`` …) and a compact ``ot`` sub-dict
(``protocol`` / ``operation`` / ``function_code`` / ``is_write`` + a few
protocol-specific fields) that the Zeek parser stashes under ``raw["ot"]`` — so
every OT field is searchable and rule-matchable (e.g. ``ot.function_code``,
``ot.is_write``) without a schema change.

Operations are classed into ``read`` / ``write`` / ``control`` / ``other`` so a
single detection rule can reason across protocols (``ot.operation: control`` or
``ot.is_write: 'true'``). Everything is best-effort and never raises: an unknown
function still yields a protocol tag so the record is recognisably OT.
"""
from __future__ import annotations

from typing import Any, Optional

# Zeek `#path` (lowercased) -> canonical OT protocol. Several ICSNPP analyzers
# emit more than one log per protocol (e.g. modbus + modbus_detailed); they all
# fold onto the same protocol tag so rules can target `log_type: modbus`.
PATH_PROTOCOL: dict[str, str] = {
    "modbus": "modbus",
    "modbus_detailed": "modbus",
    "modbus_mask_write_register": "modbus",
    "modbus_read_write_multiple_registers": "modbus",
    "dnp3": "dnp3",
    "dnp3_control": "dnp3",
    "dnp3_objects": "dnp3",
    "s7comm": "s7comm",
    "s7comm_plus": "s7comm",
    "s7comm_read_szl": "s7comm",
    "s7comm_upload_download": "s7comm",
    "cip": "cip",
    "cip_io": "cip",
    "enip": "enip",
    "bacnet": "bacnet",
    "bacnet_property": "bacnet",
    "iec104": "iec104",
    "iec104_apci": "iec104",
    "iec104_asdu": "iec104",
    "opcua": "opcua",
    "opcua_binary": "opcua",
    "profinet": "profinet",
    "profinet_dce_rpc": "profinet",
}

# Paths that are OT — the Zeek parser checks this to decide whether to enrich.
OT_PATHS = frozenset(PATH_PROTOCOL)

# Modbus numeric function code -> (action, operation). ICSNPP normally emits a
# string func name (matched by keyword below); this table covers the numeric
# `func` shape and is the authoritative code list.
_MODBUS_FUNC = {
    1: ("read-coils", "read"), 2: ("read-coils", "read"),
    3: ("read-registers", "read"), 4: ("read-registers", "read"),
    5: ("write-coils", "write"), 6: ("write-registers", "write"),
    7: ("read-status", "read"), 8: ("diagnostic", "control"),
    11: ("read-status", "read"), 12: ("read-status", "read"),
    15: ("write-coils", "write"), 16: ("write-registers", "write"),
    17: ("read-status", "read"), 20: ("read-file", "read"),
    21: ("write-file", "write"), 22: ("write-registers", "write"),
    23: ("write-registers", "write"), 24: ("read-fifo", "read"),
    43: ("encapsulated", "other"),
}


def _s(v: Any) -> str:
    """Lowercased, stripped string ('' for None/empty)."""
    return str(v).strip().lower() if v not in (None, "") else ""


def _first(row: dict, *names: str) -> Any:
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            return v
    return None


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "")}


# --------------------------------------------------------------------------- #
#  Per-protocol handlers: (row) -> (action, operation, extra_ot_fields)        #
# --------------------------------------------------------------------------- #
def _modbus(row: dict) -> tuple[str, str, dict]:
    func = _first(row, "func", "function_code", "function")
    fn = _s(func)
    if fn.isdigit():
        action, op = _MODBUS_FUNC.get(int(fn), ("modbus-request", "other"))
    elif "diagnostic" in fn:
        action, op = "diagnostic", "control"
    elif "write" in fn:
        action, op = ("write-coils" if "coil" in fn else "write-registers"), "write"
    elif "read" in fn:
        action, op = ("read-coils" if "coil" in fn else "read-registers"), "read"
    elif fn:
        action, op = f"modbus-{fn}".replace("_", "-"), "other"
    else:
        action, op = "modbus-request", "other"
    extra = {"unit_id": _first(row, "unit_id", "uid_modbus"),
             "address": _first(row, "address", "start_address", "reference_number"),
             "quantity": _first(row, "quantity", "word_count", "bit_count")}
    return action, op, extra


def _dnp3(row: dict) -> tuple[str, str, dict]:
    fc = _first(row, "fc_request", "function_code", "func", "fc")
    f = _s(fc)
    table = {
        "read": ("read", "read"), "write": ("write", "write"),
        "select": ("operate", "write"), "operate": ("operate", "write"),
        "direct_operate": ("operate", "write"),
        "direct_operate_nr": ("operate", "write"),
        "cold_restart": ("cold-restart", "control"),
        "warm_restart": ("warm-restart", "control"),
        "stop_appl": ("stop-application", "control"),
        "disable_unsolicited": ("disable-unsolicited", "control"),
        "enable_unsolicited": ("enable-unsolicited", "control"),
    }
    if f in table:
        action, op = table[f]
    elif "cold" in f and "restart" in f:
        action, op = "cold-restart", "control"
    elif "warm" in f and "restart" in f:
        action, op = "warm-restart", "control"
    elif "disable" in f and "unsolicited" in f:
        action, op = "disable-unsolicited", "control"
    elif "operate" in f or "select" in f:
        action, op = "operate", "write"
    elif "write" in f:
        action, op = "write", "write"
    elif "read" in f:
        action, op = "read", "read"
    elif f:
        action, op = f"dnp3-{f}".replace("_", "-"), "other"
    else:
        action, op = "dnp3-request", "other"
    return action, op, _clean({"iin": _first(row, "iin", "iin_flags")})


def _s7comm(row: dict) -> tuple[str, str, dict]:
    name = _s(_first(row, "function_name", "function", "func"))
    if "download" in name:
        action, op = "program-download", "write"
    elif "upload" in name:
        action, op = "program-upload", "read"
    elif "write" in name:
        action, op = "write-var", "write"
    elif "read" in name and ("szl" in name or "read_szl" in name):
        action, op = "read-szl", "read"
    elif "read" in name:
        action, op = "read-var", "read"
    elif "stop" in name:
        action, op = "plc-stop", "control"
    elif any(k in name for k in ("plc control", "plc_control", "start", "restart")):
        action, op = "plc-control", "control"
    elif "setup communication" in name or "setup_communication" in name:
        action, op = "setup", "other"
    elif name:
        action, op = f"s7-{name}".replace(" ", "-").replace("_", "-"), "other"
    else:
        action, op = "s7-request", "other"
    return action, op, _clean({"rosctr": _first(row, "rosctr", "rosctr_name")})


def _cip(row: dict) -> tuple[str, str, dict]:
    svc = _s(_first(row, "cip_service", "service", "cip_service_name"))
    if "set attribute" in svc or "set_attribute" in svc:
        action, op = "write-attribute", "write"
    elif "get attribute" in svc or "get_attribute" in svc:
        action, op = "read-attribute", "read"
    elif "forward open" in svc or "forward_open" in svc:
        action, op = "forward-open", "control"
    elif "forward close" in svc or "forward_close" in svc:
        action, op = "forward-close", "control"
    elif "write" in svc:
        action, op = "write-attribute", "write"
    elif "read" in svc:
        action, op = "read-attribute", "read"
    elif svc:
        action, op = f"cip-{svc}".replace(" ", "-").replace("_", "-"), "other"
    else:
        action, op = "cip-request", "other"
    return action, op, _clean({"cip_service": _first(row, "cip_service", "service")})


def _bacnet(row: dict) -> tuple[str, str, dict]:
    svc = _s(_first(row, "bacnet_service", "service", "pdu_service"))
    if "writeproperty" in svc or "write" in svc:
        action, op = "write-property", "write"
    elif "readproperty" in svc or "read" in svc:
        action, op = "read-property", "read"
    elif "reinitialize" in svc or "devicecommunicationcontrol" in svc:
        action, op = "device-control", "control"
    elif svc:
        action, op = f"bacnet-{svc}", "other"
    else:
        action, op = "bacnet-request", "other"
    return action, op, _clean({"bacnet_service": _first(row, "bacnet_service", "service")})


def _generic(row: dict) -> tuple[str, str, dict]:
    """Fallback for OT protocols without a dedicated handler (opcua/iec104/…)."""
    return "ot-request", "other", {}


_HANDLERS = {
    "modbus": _modbus, "dnp3": _dnp3, "s7comm": _s7comm,
    "cip": _cip, "enip": _cip, "bacnet": _bacnet,
}


def enrich(path: Optional[str], row: dict) -> Optional[tuple[str, dict]]:
    """If ``path`` is an ICS protocol, return ``(action, ot_dict)`` for the row.

    ``action`` is the normalized control-plane operation; ``ot_dict`` always
    carries ``protocol`` / ``operation`` / ``is_write`` and any protocol-specific
    fields the handler extracted (function code, unit id, address …). Returns
    ``None`` for a non-OT path so the caller keeps its default handling.
    """
    proto = PATH_PROTOCOL.get(_s(path))
    if not proto:
        return None
    handler = _HANDLERS.get(proto, _generic)
    action, operation, extra = handler(row)
    ot = {"protocol": proto, "operation": operation,
          "is_write": "true" if operation == "write" else "false"}
    ot.update(extra)
    return action, _clean(ot)

# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""NetFlow v5 / v9 / IPFIX flow parser (decoded-flow JSON).

Input is the JSON `app/receivers/netflow.py` emits: a bare array of decoded flow
dicts (also accepted wrapped as ``{"flows": [...]}`` or as NDJSON, so a saved
decode can be re-uploaded through the console). The wire decoding lives entirely
in the receiver — this module only shapes already-decoded scalars, which keeps
`struct` out of the parse path and both halves independently testable.

CIM
---
Every event is emitted with ``log_type="netflow"``, which is already a member
term of the shipped Network clause in ``app/cim/models.yaml``
(``log_type: [traffic, forward, flow, flows, conn, connection, netflow, ...]``),
so flows land in the **Network** data model with no registry edit.

``vendor`` is the flow family, ``netflow``, and ``product`` the wire version —
``v5`` | ``v9`` | ``ipfix`` — giving a ``vendor_product`` of ``netflow:ipfix``.
IPFIX is filed under the netflow vendor deliberately: it is the IETF
standardisation of NetFlow v9, exporters emit the two interchangeably, and a
split vendor would fragment source-health (``sourcehealth.source_key`` is
``(vendor, log_type)``) for what is one collector.

``action`` is deliberately left NULL. A flow record is an observation, not a
policy decision; stamping something like "flow" into the Network model's
``action`` field (documented "allowed | blocked | ...") would make every
allow/deny query lie.

``raw`` is the decoded flow dict verbatim. Every key is a lower_snake_case scalar
at the TOP level because CIM membership reads jsonb byte-exactly and cannot
descend into arrays (``app/cim/match.py``).
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_int, to_port


def _bytes_total(rec: dict) -> Optional[int]:
    """Forward + reverse octets. A biflow template carries both; a uniflow one
    only `bytes`, so summing the present ones is correct for either.

    The sum is re-bounded through `to_int`. Each operand is already bounded to signed
    64-bit, but the SUM of two in-range values is not: an exporter (or a spoofed UDP
    datagram — NetFlow has no authentication) sending 0x7FFF_FFFF_FFFF_FFFF in both
    octetDeltaCount and postOctetDeltaCount produced a value the `bigint` column
    cannot hold, and the resulting NumericValueOutOfRange escapes `write_stream` into
    `IngestQueue._flush`, which discards the WHOLE buffered group — up to 2000
    legitimate flows per packet, with `undecodable` and `parse_errors` both still 0.
    Out of range becomes None (unknown) rather than a truncated number, matching what
    `to_int` does everywhere else."""
    sizes = [n for n in (to_int(rec.get("bytes")), to_int(rec.get("out_bytes")))
             if n is not None]
    return to_int(sum(sizes)) if sizes else None


def _endpoint(ip, port) -> str:
    host = ip if ip else "?"
    return f"{host}:{port}" if port is not None else str(host)


def _message(rec: dict, src_ip, dst_ip, src_port, dst_port, protocol) -> str:
    parts = [f"{protocol or 'flow'} {_endpoint(src_ip, src_port)} -> "
             f"{_endpoint(dst_ip, dst_port)}"]
    packets = to_int(rec.get("packets"))
    octets = _bytes_total(rec)
    if packets is not None:
        parts.append(f"{packets} pkts")
    if octets is not None:
        parts.append(f"{octets} bytes")
    return " ".join(parts)


def _protocol(rec: dict) -> Optional[str]:
    """The transport name the decoder resolved, else the bare IP protocol
    number, so an exotic protocol still reaches the Network model's `transport`."""
    name = rec.get("protocol")
    if name not in (None, ""):
        return str(name).lower()
    number = to_int(rec.get("protocol_number"))
    return str(number) if number is not None else None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "flows"):
        src_ip = clean_ip(rec.get("src_ip"))
        dst_ip = clean_ip(rec.get("dst_ip"))
        src_port = to_port(rec.get("src_port"))
        dst_port = to_port(rec.get("dst_port"))
        protocol = _protocol(rec)
        version = rec.get("flow_version")

        yield NormalizedEvent(
            # end of the flow, falling back to the start and then to the packet's
            # export time — a template carrying no timestamp IE at all leaves only
            # the last of these, which is still the right order of magnitude.
            event_time=parse_ts(first(rec.get("end_time"), rec.get("start_time"),
                                      rec.get("export_time"))),
            vendor="netflow",
            product=str(version).lower() if version else None,
            log_type="netflow",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            app=first(rec.get("application_name")),
            # The exporting device: CIM Network maps host_name -> `dvc`.
            host_name=first(rec.get("exporter")),
            bytes_total=_bytes_total(rec),
            message=_message(rec, src_ip, dst_ip, src_port, dst_port, protocol),
            raw=rec,
        )

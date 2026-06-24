"""Syslog receiver: UDP, TCP, and TCP-over-TLS (Phase 1 live ingestion).

Each received message is parsed with the configured format (or auto-detected,
falling back to generic syslog) and the resulting events are handed to the async
ingest queue — the receiver never touches the database directly.

TCP framing follows RFC 6587: both octet-counting (``MSG-LEN SP <PRI>...``) and
non-transparent (newline-delimited) framings are supported. `iter_tcp_messages`
does the framing and is pure, so it is unit-tested without sockets.
"""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
from typing import Optional

from .. import pipeline
from ..config import settings
from ..detect import detect_format
from ..ingest import _VENDOR_OF
from ..parsers import PARSERS
from ..streaming import IngestItem, IngestQueue

log = logging.getLogger("logocean")

# A datagram / single TCP message bigger than this is almost certainly a sender
# that never framed its stream — cap it so a buffer can't grow unbounded.
_MAX_MSG = 1024 * 1024
_OCTET_RE = re.compile(rb"^(\d+) ")


def iter_tcp_messages(buffer: bytes) -> tuple[list[bytes], bytes]:
    """Split a TCP byte buffer into complete syslog messages + a remainder.

    Octet-counted frames (`<len> <PRI>...`) are recognised only when the count is
    immediately followed by a `<` (a real syslog PRI), so a non-transparent line
    that merely starts with a number (e.g. ``12 Jun ...``) is not mis-framed.
    """
    messages: list[bytes] = []
    while buffer:
        m = _OCTET_RE.match(buffer)
        if m and len(buffer) > m.end() and buffer[m.end():m.end() + 1] == b"<":
            start, length = m.end(), int(m.group(1))
            end = start + length
            if len(buffer) < end:
                break  # frame not fully arrived yet
            messages.append(buffer[start:end])
            buffer = buffer[end:]
        else:
            idx = buffer.find(b"\n")
            if idx == -1:
                break  # no complete line yet
            messages.append(buffer[:idx])
            buffer = buffer[idx + 1:]
    return messages, buffer


def resolve_format(text: str, configured: str) -> Optional[str]:
    """Pick the parser for a message: a fixed configured format, or auto-detect
    with a generic-syslog fallback. Returns None if a fixed format is invalid."""
    if configured and configured != "auto":
        return configured if configured in PARSERS else None
    return detect_format("", text) or "generic_syslog"


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: "SyslogReceiver"):
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr) -> None:
        self._receiver.ingest_message(data[:_MAX_MSG], addr[0] if addr else None)


class SyslogReceiver:
    """Owns the UDP endpoint and TCP server, feeding messages to the queue."""

    def __init__(self, queue: IngestQueue):
        self.queue = queue
        self._udp_transport = None
        self._tcp_server: Optional[asyncio.AbstractServer] = None

    def ingest_message(self, raw: bytes, peer: Optional[str]) -> None:
        text = raw.decode("utf-8", "replace").strip()
        if not text:
            return
        fmt = resolve_format(text, settings.syslog_format)
        if fmt is None:
            return
        try:
            events = list(pipeline.parse_events(text, fmt))
        except Exception:  # noqa: BLE001 — never let one bad message kill the receiver
            return
        if events:
            self.queue.submit(IngestItem(events, fmt, "syslog", peer, _VENDOR_OF.get(fmt)))

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else None
        buffer = b""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                buffer += data
                msgs, buffer = iter_tcp_messages(buffer)
                for m in msgs:
                    self.ingest_message(m, peer_ip)
                if len(buffer) > _MAX_MSG:   # unframed/runaway sender — drop the backlog
                    buffer = b""
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not (settings.syslog_tls_cert and settings.syslog_tls_key):
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(settings.syslog_tls_cert, settings.syslog_tls_key)
        return ctx

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        host = settings.syslog_host
        if settings.syslog_udp_port:
            self._udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self), local_addr=(host, settings.syslog_udp_port))
            log.info("syslog UDP listening on %s:%d", host, settings.syslog_udp_port)
        if settings.syslog_tcp_port:
            ssl_ctx = self._ssl_context()
            self._tcp_server = await asyncio.start_server(
                self._handle_tcp, host, settings.syslog_tcp_port, ssl=ssl_ctx)
            log.info("syslog TCP%s listening on %s:%d",
                     " (TLS)" if ssl_ctx else "", host, settings.syslog_tcp_port)

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
            self._tcp_server = None

"""Bulk-import a large [.gz] log file into LogOcean via the ingest API.

Streams the file in size-bounded, line-aligned chunks and POSTs each to
``/api/v1/ingest``, so a multi-GB export (e.g. a 3-year IBM QRadar LEEF backup)
loads without exceeding the server's per-request limit (``MAX_UPLOAD_MB``) or the
client's memory. Ingest is idempotent on the server (per-event dedup hash), so
re-running after an interruption is safe — already-stored events are skipped.
Stdlib only; copy it anywhere Python 3 runs.

    python logocean_import.py --url http://logocean:8000 --key lo_... \
        --format leef --max-mb 400 qradar_3yr.leef.gz

`.gz` input is decompressed locally (streaming). ``--gzip`` compresses each POST
body too (the server gunzips it transparently) to save bandwidth. ``--max-mb``
must be <= the server's ``MAX_UPLOAD_MB`` (default 512).

Tip: for a historical backfill, disable detection + UEBA on the server
(``DETECTION_ENABLED=false``, ``UEBA_ENABLED=false``) to avoid a flood of stale
alerts and to speed ingest.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Iterator, Optional


def open_maybe_gzip(path: str):
    """Open `path` for line iteration, transparently decompressing gzip (detected
    by a .gz extension or the magic bytes). ``-`` means stdin."""
    if path == "-":
        return sys.stdin
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if path.endswith(".gz") or magic == b"\x1f\x8b":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def chunk_lines(lines: Iterable[str], max_bytes: int) -> Iterator[str]:
    """Group `lines` into chunk strings of at most ~`max_bytes` UTF-8 bytes,
    never splitting a line. A single line larger than `max_bytes` becomes its own
    oversized chunk (the server may still reject it)."""
    buf: list[str] = []
    size = 0
    for line in lines:
        if not line.endswith("\n"):
            line += "\n"
        b = len(line.encode("utf-8"))
        if buf and size + b > max_bytes:
            yield "".join(buf)
            buf, size = [], 0
        buf.append(line)
        size += b
    if buf:
        yield "".join(buf)


def post_chunk(base_url: str, api_key: str, fmt: str, filename: Optional[str],
               body: str, *, gzip_body: bool = False, timeout: int = 120,
               retries: int = 3) -> dict:
    """POST one chunk to the ingest API, retrying transient errors. Returns the
    JSON result; raises RuntimeError after exhausting retries or on a client
    error (4xx that won't change on retry)."""
    data = body.encode("utf-8")
    headers = {"Content-Type": "text/plain", "X-API-Key": api_key}
    if gzip_body:
        data = gzip.compress(data)
        headers["Content-Encoding"] = "gzip"     # server also sniffs the magic bytes
    qs = {"format": fmt}
    if filename:
        qs["filename"] = filename
    url = f"{base_url.rstrip('/')}/api/v1/ingest?" + urllib.parse.urlencode(qs)

    last = ""
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=data, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
            if e.code in (400, 401, 413, 422):     # not transient — stop retrying
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = str(e)
        if attempt < retries:
            time.sleep(min(2 ** attempt, 10))
    raise RuntimeError(last or "post failed")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Bulk-import a large log file into LogOcean.")
    ap.add_argument("file", help="path to the log file (.gz supported), or - for stdin")
    ap.add_argument("--url", required=True, help="LogOcean base URL, e.g. http://logocean:8000")
    ap.add_argument("--key", required=True, help="ingest API key (lo_...)")
    ap.add_argument("--format", default="leef",
                    help="parser format key or 'auto' (default: leef)")
    ap.add_argument("--filename", default=None, help="filename tag recorded on each batch")
    ap.add_argument("--max-mb", type=int, default=400,
                    help="max chunk size in MB; must be <= server MAX_UPLOAD_MB (default 400)")
    ap.add_argument("--gzip", action="store_true",
                    help="gzip each POST body (server decompresses it) to save bandwidth")
    ap.add_argument("--dry-run", action="store_true",
                    help="chunk and report sizes without sending anything")
    ap.add_argument("--timeout", type=int, default=120, help="per-request timeout (s)")
    args = ap.parse_args(argv)

    max_bytes = args.max_mb * 1024 * 1024
    name = args.filename or (args.file.rsplit("/", 1)[-1] if args.file != "-" else "stdin")
    totals = {"chunks": 0, "lines": 0, "inserted": 0, "duplicates": 0}
    start = time.time()

    def counting(it):
        for ln in it:
            totals["lines"] += 1
            yield ln

    fh = open_maybe_gzip(args.file)
    try:
        for i, chunk in enumerate(chunk_lines(counting(fh), max_bytes), 1):
            totals["chunks"] = i
            mb = len(chunk.encode("utf-8")) / 1024 / 1024
            if args.dry_run:
                print(f"[chunk {i}] {mb:.1f} MB (dry-run, not sent)")
                continue
            try:
                res = post_chunk(args.url, args.key, args.format, name, chunk,
                                 gzip_body=args.gzip, timeout=args.timeout)
            except RuntimeError as e:
                print(f"[chunk {i}] FAILED: {e}", file=sys.stderr)
                return 1
            totals["inserted"] += res.get("inserted", 0)
            totals["duplicates"] += res.get("duplicates", 0)
            print(f"[chunk {i}] {mb:.1f} MB -> inserted={res.get('inserted')} "
                  f"duplicates={res.get('duplicates')} (batch {res.get('batch_id')})")
    finally:
        if fh is not sys.stdin:
            fh.close()

    dur = time.time() - start
    print(f"done: {totals['chunks']} chunk(s), {totals['lines']} line(s), "
          f"{totals['inserted']} inserted, {totals['duplicates']} duplicate(s) in {dur:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

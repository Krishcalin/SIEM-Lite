"""Tests for gzip ingest support + the bulk-import client's chunker (no DB)."""
import gzip
import importlib.util
from pathlib import Path

from app.util import gunzip_capped, looks_gzip

ROOT = Path(__file__).resolve().parent.parent


# ── server-side gunzip (used by the upload + ingest-API paths) ───────────────
def test_gunzip_roundtrip_and_passthrough():
    text = ("LEEF:1.0|IBM|QRadar|7.5|1|src=1.2.3.4\tsev=5\n" * 1000).encode()
    gz = gzip.compress(text)
    assert looks_gzip(gz) and not looks_gzip(text)
    assert gunzip_capped(gz, 10 * 1024 * 1024) == text     # decompresses
    assert gunzip_capped(text, 10 * 1024 * 1024) == text   # non-gzip passes through


def test_gunzip_bomb_and_corrupt_are_rejected():
    payload = b"A" * (2 * 1024 * 1024)                     # 2 MB decompressed
    gz = gzip.compress(payload)
    assert gunzip_capped(gz, 1024 * 1024) is None          # over a 1 MB cap -> rejected
    assert gunzip_capped(gz, 4 * 1024 * 1024) == payload   # under the cap -> ok
    assert gunzip_capped(b"\x1f\x8b\x08corrupt", 4096) is None   # bad gzip -> None


def test_gunzip_concatenated_members():
    a, b = gzip.compress(b"one\n"), gzip.compress(b"two\n")
    assert gunzip_capped(a + b, 4096) == b"one\ntwo\n"      # multi-member stream


# ── client-side chunker (clients/logocean_import.py) ─────────────────────────
def _load_importer():
    spec = importlib.util.spec_from_file_location(
        "logocean_import", ROOT / "clients" / "logocean_import.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_chunk_lines_respects_size_and_line_boundaries():
    imp = _load_importer()
    lines = [f"line-{i} " + "x" * 88 + "\n" for i in range(100)]   # ~98 bytes each
    chunks = list(imp.chunk_lines(lines, max_bytes=1000))
    assert len(chunks) >= 10
    assert all(len(c.encode("utf-8")) <= 1000 for c in chunks)     # never overflows the cap
    assert all(c.endswith("\n") for c in chunks)                   # never splits a line
    assert "".join(chunks) == "".join(lines)                       # nothing lost / reordered


def test_chunk_lines_keeps_an_oversize_line_whole():
    imp = _load_importer()
    big = "z" * 5000 + "\n"
    chunks = list(imp.chunk_lines([big, "small\n"], max_bytes=1000))
    assert chunks[0] == big                                        # oversize line kept intact
    assert "".join(chunks) == big + "small\n"

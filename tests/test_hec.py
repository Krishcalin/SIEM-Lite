# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the Splunk HEC wire shim (no database, no network).

The whole module is pure functions over strings plus four thin route handlers, so
everything here runs against fixture strings. The HTTP tests mount ONLY `hec.router`
on a bare FastAPI app and stub `db.verify_api_key` / `ingest.ingest`, which keeps the
wire contract — status codes, response bodies, auth scheme — testable without a
database and without the rest of the application.
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

# A COLLECTION ERROR, DELIBERATELY NOT A SKIP. `starlette.testclient.TestClient`
# refuses to construct without `httpx`, and the 22 HTTP-surface tests below go
# through it. Absent that package they used to fail one at a time with a RuntimeError
# raised deep inside starlette, which is how the unit CI job stayed red for two
# commits while the same suite was green on a developer machine (where httpx arrives
# transitively). Raising here names the missing package once, at collection.
#
# Not `pytest.skip`: these tests cover a public HTTP surface that accepts credentials,
# and a run that silently stops exercising it must not report success. Importing this
# module is what triggers the check, so `pytest tests/test_assets.py` on a machine
# without httpx is unaffected.
try:
    import httpx  # noqa: F401
except ImportError as exc:                       # pragma: no cover - env guard
    raise RuntimeError(
        "tests/test_hec.py needs `httpx` — starlette's TestClient cannot be built "
        "without it. Install it with `pip install httpx` (it is test tooling, so it "
        "lives on the CI pip line next to pytest, not in requirements.txt)."
    ) from exc

from app import hec
from app.hec import (envelope_entry, envelope_record, format_for_sourcetype,
                     group_envelopes, hec_body, hec_status, hec_token, looks_json,
                     raw_envelopes, split_hec_envelopes)
from app.parsers import PARSERS


# ── Splunk response codes ───────────────────────────────────────────────────── #

def test_hec_body_is_splunks_exact_success_shape():
    """A sender switch-cases on `code` and rejects anything else, so the success body
    is `{"text": "Success", "code": 0}` verbatim — not LogOcean's batch summary."""
    assert hec_body(0) == {"text": "Success", "code": 0}
    assert hec_status(0) == 200


def test_hec_body_covers_the_documented_error_codes():
    assert hec_body(2) == {"text": "Token is required", "code": 2}
    assert hec_body(4) == {"text": "Invalid token", "code": 4}
    assert hec_body(5) == {"text": "No data", "code": 5}
    assert hec_body(6) == {"text": "Invalid data format", "code": 6}
    assert hec_body(14) == {"text": "ACK is disabled", "code": 14}
    assert hec_body(17) == {"text": "HEC is healthy", "code": 17}
    assert (hec_status(2), hec_status(4), hec_status(5)) == (401, 403, 400)
    assert (hec_status(6), hec_status(8), hec_status(17)) == (400, 500, 200)


def test_hec_body_of_an_unknown_code_degrades_instead_of_raising():
    """An unmapped code must not KeyError inside a response path."""
    assert hec_body(999)["code"] == 999
    assert hec_status(999) == 500


# ── Authorization: Splunk <token> ───────────────────────────────────────────── #

def test_hec_token_parses_the_splunk_scheme_case_insensitively():
    assert hec_token("Splunk abc123") == "abc123"
    assert hec_token("splunk abc123") == "abc123"
    assert hec_token("SPLUNK   abc123  ") == "abc123"
    assert hec_token("  Splunk abc123") == "abc123"


def test_hec_token_rejects_every_other_scheme():
    """`util.extract_api_key` handles Bearer; this extractor must not, or a Bearer
    key would silently take the HEC path and blur which auth surface was used."""
    assert hec_token("Bearer abc123") is None
    assert hec_token("Basic abc123") is None
    assert hec_token("abc123") is None            # no scheme at all
    assert hec_token("Splunk") is None            # scheme with no token
    assert hec_token("Splunk    ") is None
    assert hec_token("") is None
    assert hec_token(None) is None


# ── body splitting: the shape a real sender emits ───────────────────────────── #

def test_split_hec_envelopes_handles_concatenation_without_a_separator():
    """THE case this module exists for. HEC senders batch by writing objects back to
    back with no separator; that is not valid JSON, not an array and not NDJSON, so
    `json.loads` and `util.iter_json_records` both yield nothing from it."""
    body = '{"event":"a"}{"event":"b"}{"event":"c"}'
    assert [e["event"] for e in split_hec_envelopes(body)] == ["a", "b", "c"]

    # And it is genuinely beyond the existing helper — this is the mutation guard.
    from app.util import iter_json_records
    assert list(iter_json_records(body)) == []


def test_split_hec_envelopes_handles_ndjson_pretty_printed_and_arrays():
    ndjson = '{"event":"a"}\n{"event":"b"}\n'
    assert len(split_hec_envelopes(ndjson)) == 2

    pretty = '{\n  "event": "a",\n  "host": "h1"\n}\n{\n  "event": "b"\n}'
    out = split_hec_envelopes(pretty)
    assert [e["event"] for e in out] == ["a", "b"] and out[0]["host"] == "h1"

    assert len(split_hec_envelopes('{"event":"a"},{"event":"b"}')) == 2      # comma
    assert len(split_hec_envelopes('[{"event":"a"},{"event":"b"}]')) == 2    # array
    assert split_hec_envelopes('{"event":"only"}') == [{"event": "only"}]    # single


def test_split_hec_envelopes_resyncs_past_a_corrupt_envelope():
    """One malformed envelope costs one envelope, not the whole batch."""
    body = '{"event":"a"}{ this is not json }{"event":"c"}'
    assert [e["event"] for e in split_hec_envelopes(body)] == ["a", "c"]


def test_split_hec_envelopes_rejects_empty_and_hostile_payloads():
    assert split_hec_envelopes("") == []
    assert split_hec_envelopes("   \n  ") == []
    assert split_hec_envelopes("not json at all") == []
    assert split_hec_envelopes('["a","b"]') == []          # array of non-dicts
    # A deep-nesting bomb is dropped before the decoder can recurse on it.
    assert split_hec_envelopes('{"a":' * 500 + "1" + "}" * 500) == []


def test_split_hec_envelopes_terminates_on_unclosed_and_trailing_junk():
    """The resync must always advance, or a hostile body becomes an infinite loop."""
    assert split_hec_envelopes('{"event":"a"}{"event":') == [{"event": "a"}]
    assert split_hec_envelopes("{{{{{{{{") == []
    assert split_hec_envelopes('{"event":"a"}%%%%') == [{"event": "a"}]


def test_split_hec_envelopes_honours_the_count_limit():
    """The transport cap bounds bytes; this bounds the list a body can materialise."""
    body = '{"event":"x"}' * 50
    assert len(split_hec_envelopes(body, limit=10)) == 10
    assert len(split_hec_envelopes(body)) == 50


# ── sourcetype -> format routing ────────────────────────────────────────────── #

def test_format_for_sourcetype_maps_real_splunk_sourcetypes():
    """The sourcetypes shipped by the Splunk TAs a migrating customer already runs."""
    cases = {
        "cisco:asa": "cisco_asa",
        # cisco_ftd reads the unified 430001-430005 ids AND delegates Lina lines to
        # cisco_asa, so it handles the whole FTD stream; routing these to cisco_asa
        # sent every unified security event to the wrong grammar.
        "cisco:ftd": "cisco_ftd",
        "cisco:ftd:securityevent": "cisco_ftd",
        "cisco:sourcefire": "cisco_ftd",
        "cisco:ios": "cisco_ios",
        # The Phase-2 sources. Every one of these used to fall through to
        # generic_json (or, for FTD, to the wrong Cisco grammar), which is the one
        # thing the sourcetype table exists to prevent.
        "aws:guardduty": "aws_guardduty",
        "aws:securityhub": "aws_securityhub",
        "ms:defender:atp:alerts": "defender_xdr",
        "ms365:defender:incident": "defender_xdr",
        "qualys:vmdr": "qualys",
        "tenable:vuln": "tenable",
        "nessus:scan": "tenable",
        "rapid7:insightvm": "rapid7",
        "nexpose:asset": "rapid7",
        "netflow:flow": "netflow",
        "ipfix": "netflow",
        "meraki:flows": "meraki",
        "pan:traffic": "paloalto_syslog",
        "pan:threat": "paloalto_syslog",
        "fgt_traffic": "fortinet_fortigate",
        "WinEventLog:Security": "windows_security",
        "linux_audit": "linux_auditd",
        "access_combined": "web_access",
        "suricata": "suricata_eve",
        "json_suricata": "suricata_eve",
        "cef": "cef",
        "leef": "leef",
        "bro:conn:json": "zeek_json",
        "aws:cloudtrail": "aws_cloudtrail",
        "o365:management:activity": "m365_audit",
        "OktaIM2:log": "okta_system_log",
        "azure:aad:signin": "entra_signin",
        "azure:activity": "azure_activity",
        "google:gcp:pubsub:message": "gcp_audit",
        "github:cloud:audit": "github_audit",
        "gitlab:audit": "gitlab_audit",
        "crowdstrike:events:sensor": "crowdstrike_json",
        "nutanix:files": "nutanix_files",
        "nutanix:audit": "nutanix_pc",
        "syslog": "generic_syslog",
    }
    for sourcetype, expected in cases.items():
        assert format_for_sourcetype(sourcetype) == expected, sourcetype


def test_format_for_sourcetype_sysmon_beats_the_wineventlog_prefix():
    """Splunk's Sysmon sourcetype is an XmlWinEventLog one, so the substring rule has
    to be consulted before the family prefixes or Sysmon lands in windows_security."""
    assert format_for_sourcetype(
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") == "sysmon"
    assert format_for_sourcetype("XmlWinEventLog:Security") == "windows_security"


def test_format_for_sourcetype_falls_back_for_unknown_blank_and_missing():
    assert format_for_sourcetype("acme:widget:v3") == "generic_json"
    assert format_for_sourcetype("") == "generic_json"
    assert format_for_sourcetype(None) == "generic_json"
    assert format_for_sourcetype("acme:widget", default="generic_syslog") == "generic_syslog"
    assert format_for_sourcetype("acme:widget", default=None) is None


def test_format_for_sourcetype_degrades_when_the_parser_is_not_registered():
    """A mapping whose parser this build does not register must degrade to the
    default, never return a key `PARSERS` cannot resolve."""
    thin = {"generic_json", "generic_syslog"}
    assert format_for_sourcetype("cisco:asa", available=thin) == "generic_json"
    assert format_for_sourcetype("cisco:asa", available=thin,
                                 default="generic_syslog") == "generic_syslog"
    assert format_for_sourcetype("cisco:asa", available=thin | {"cisco_asa"}) == "cisco_asa"


def test_sourcetype_tables_only_name_registered_parsers():
    """Structural guard: every entry in the routing tables and the two payload-shape
    sets must be a live `PARSERS` key, so a typo cannot ship as a silent fallback."""
    targets = (set(hec._SOURCETYPE_EXACT.values())
               | {f for _, f in hec._SOURCETYPE_PREFIXES}
               | {f for _, f in hec._SOURCETYPE_CONTAINS}
               | hec.NEEDS_JSON | hec.NEEDS_TEXT)
    assert targets <= set(PARSERS), sorted(targets - set(PARSERS))
    assert not (hec.NEEDS_JSON & hec.NEEDS_TEXT)     # a format cannot be both
    assert "generic_json" in PARSERS and "generic_syslog" in PARSERS


def test_looks_json_distinguishes_a_document_from_a_log_line():
    assert looks_json('{"a":1}') and looks_json("  [1,2]")
    assert not looks_json("%ASA-6-302013: Built connection")
    assert not looks_json("")


# ── envelope -> parser input ────────────────────────────────────────────────── #

def test_envelope_entry_routes_a_raw_string_to_its_vendor_parser_verbatim():
    """The point of sourcetype mapping: `cisco:asa` reaches the ASA parser with its
    own text untouched, so the sender keeps real src/dst/port columns."""
    line = "%ASA-6-302013: Built outbound TCP connection"
    assert envelope_entry({"sourcetype": "cisco:asa", "event": line}) == ("cisco_asa", line)
    assert envelope_entry({"sourcetype": "pan:traffic", "event": "1,2,3"}) == (
        "paloalto_syslog", "1,2,3")


def test_envelope_entry_wraps_an_unmapped_string_so_the_metadata_survives():
    """With no vendor parser to gain from, the envelope is preserved as a JSON record
    instead — otherwise host/source/index/fields/time are lost to a bare syslog line."""
    fmt, line = envelope_entry({
        "event": "something happened", "time": 1690000000.5, "host": "web01",
        "source": "/var/log/app.log", "sourcetype": "acme:app", "index": "main",
        "fields": {"env": "prod"},
    })
    assert fmt == "generic_json"
    rec = json.loads(line)
    assert rec["message"] == "something happened"
    assert rec["host"] == "web01" and rec["index"] == "main"
    assert rec["source"] == "/var/log/app.log" and rec["sourcetype"] == "acme:app"
    assert rec["env"] == "prod" and rec["time"] == 1690000000.5


def test_envelope_entry_merges_an_object_event_with_envelope_metadata():
    fmt, line = envelope_entry({
        "sourcetype": "aws:cloudtrail", "host": "h1", "index": "cloud",
        "time": 1690000000, "event": {"eventSource": "s3.amazonaws.com", "awsRegion": "us-east-1"},
        "fields": {"team": "sec"},
    })
    assert fmt == "aws_cloudtrail"
    rec = json.loads(line)
    assert rec["eventSource"] == "s3.amazonaws.com" and rec["awsRegion"] == "us-east-1"
    assert rec["host"] == "h1" and rec["index"] == "cloud" and rec["team"] == "sec"


def test_envelope_metadata_wins_over_a_same_named_key_in_the_body():
    """Splunk's own precedence: host/source/sourcetype/index/time are indexed
    metadata, not payload, so they override a colliding body key. `fields` are the
    other way round — they only fill gaps."""
    rec = envelope_record({"host": "envelope-host", "time": 99, "fields": {"host": "field-host",
                                                                          "extra": "kept"}},
                          event={"host": "body-host", "time": 1, "other": "x"})
    assert rec["host"] == "envelope-host"
    assert rec["time"] == 99
    assert rec["other"] == "x" and rec["extra"] == "kept"


def test_envelope_record_keeps_the_body_when_the_envelope_omits_the_key():
    rec = envelope_record({}, event={"host": "body-host", "time": 7})
    assert rec == {"host": "body-host", "time": 7}


def test_envelope_fractional_time_reaches_the_parser_as_utc_with_microseconds():
    """End-to-end through the real parser: a fractional epoch `time` must become an
    aware UTC `event_time` with its sub-second part intact, not a write-time fallback."""
    fmt, line = envelope_entry({"event": {"msg": "hi"}, "time": 1690000000.125})
    events = list(PARSERS[fmt].parse(line))
    assert len(events) == 1
    assert events[0].event_time == datetime(2023, 7, 22, 4, 26, 40, 125000,
                                            tzinfo=timezone.utc)


def test_envelope_string_event_reaches_the_parser_as_a_message_with_its_host():
    """The wrapped-string path must survive `generic_json` as a real event."""
    fmt, line = envelope_entry({"event": "login failed for bob", "host": "srv1",
                                "time": 1690000000})
    events = list(PARSERS[fmt].parse(line))
    assert len(events) == 1
    assert events[0].message == "login failed for bob"
    assert events[0].host_name == "srv1"
    assert events[0].event_time == datetime(2023, 7, 22, 4, 26, 40, tzinfo=timezone.utc)


def test_vendor_routed_asa_line_reaches_the_parser_with_real_columns():
    """The headline claim, end to end: a sender's existing `sourcetype=cisco:asa`
    yields src/dst/port/action columns, not an opaque blob. The line carries its own
    timestamp, which is why the envelope `time` is not needed on this path — the
    documented trade-off costs sub-second precision and nothing else."""
    line = ("<166>Jul 22 2023 04:26:40 fw1 : %ASA-6-302013: Built outbound TCP "
            "connection 1 for outside:10.0.0.5/443 (10.0.0.5/443) to "
            "inside:192.168.1.7/5000")
    fmt, content = group_envelopes(
        [{"time": 1690000000.25, "sourcetype": "cisco:asa", "event": line}])[0]
    assert fmt == "cisco_asa" and content == line
    event = list(PARSERS[fmt].parse(content))[0]
    assert event.vendor == "cisco"
    assert (event.src_ip, event.dst_ip, event.dst_port) == ("192.168.1.7", "10.0.0.5", 443)
    assert event.event_time == datetime(2023, 7, 22, 4, 26, 40, tzinfo=timezone.utc)


def test_envelope_entry_downgrades_when_the_payload_shape_does_not_fit_the_parser():
    """Routing must never hand a parser something it provably cannot read — that is
    silent zero-event loss, the worst possible outcome for a migration wedge."""
    # plain text declared as a JSON-only sourcetype -> wrapped, not fed to CloudTrail
    fmt, line = envelope_entry({"sourcetype": "aws:cloudtrail", "event": "not json at all"})
    assert fmt == "generic_json" and json.loads(line)["message"] == "not json at all"

    # an object declared as a syslog sourcetype -> JSON, not fed to the ASA parser
    fmt, line = envelope_entry({"sourcetype": "cisco:asa", "event": {"a": 1}})
    assert fmt == "generic_json" and json.loads(line)["a"] == 1

    # a JSON *string* declared as a JSON sourcetype is fine as-is
    assert envelope_entry({"sourcetype": "aws:cloudtrail",
                           "event": '{"eventSource":"s3"}'}) == (
        "aws_cloudtrail", '{"eventSource":"s3"}')


def test_envelope_entry_skips_what_carries_nothing_and_keeps_fields_only():
    assert envelope_entry({}) is None
    assert envelope_entry({"event": ""}) is None
    assert envelope_entry({"event": "   "}) is None
    assert envelope_entry({"host": "h"}) is None            # metadata with no payload
    assert envelope_entry("not a mapping") is None
    fmt, line = envelope_entry({"fields": {"metric": 3}, "host": "h"})
    assert fmt == "generic_json" and json.loads(line)["metric"] == 3


def test_envelope_entry_stringifies_a_non_string_non_object_event():
    fmt, line = envelope_entry({"event": 42})
    assert fmt == "generic_json" and json.loads(line)["message"] == "42"
    fmt, line = envelope_entry({"event": ["a", "b"]})
    assert fmt == "generic_json" and json.loads(line)["message"] == '["a","b"]'


def test_envelope_entry_never_emits_an_embedded_newline():
    """Grouped batches are newline-joined, so a JSON line with a literal newline in it
    would split one event into two unparseable halves."""
    fmt, line = envelope_entry({"event": {"msg": "line1\nline2"}})
    assert "\n" not in line
    assert list(PARSERS[fmt].parse(line))[0].message == "line1\nline2"


# ── grouping into per-format batches ────────────────────────────────────────── #

def test_group_envelopes_splits_mixed_sourcetypes_in_first_seen_order():
    """One HEC POST can carry mixed sourcetypes while `ingest.ingest` binds one format
    per batch, so a request becomes N batches — ordered, not arbitrary."""
    # `generic_json` is seen first and sorts second, so a sorted/arbitrary order would
    # look different here — an alphabetically-ascending fixture would not.
    batches = group_envelopes([
        {"event": "plain one"},
        {"sourcetype": "cisco:asa", "event": "%ASA-6-1: a"},
        {"event": "plain two"},
        {"sourcetype": "cisco:asa", "event": "%ASA-6-2: b"},
    ])
    assert [f for f, _ in batches] == ["generic_json", "cisco_asa"]
    assert batches[1][1] == "%ASA-6-1: a\n%ASA-6-2: b"
    assert len(batches[0][1].splitlines()) == 2


def test_group_envelopes_drops_empty_envelopes_and_an_empty_batch():
    assert group_envelopes([]) == []
    assert group_envelopes([{}, {"event": ""}]) == []
    assert len(group_envelopes([{"event": "a"}, {}, {"event": "b"}])[0][1].splitlines()) == 2


# ── /services/collector/raw ─────────────────────────────────────────────────── #

def test_raw_envelopes_makes_one_envelope_per_line_with_query_metadata():
    envs = raw_envelopes("line one\n\nline two\n",
                         {"sourcetype": "cisco:asa", "host": "fw1", "index": "net"})
    assert [e["event"] for e in envs] == ["line one", "line two"]
    assert envs[0]["host"] == "fw1" and envs[0]["index"] == "net"
    assert group_envelopes(envs)[0][0] == "cisco_asa"


def test_raw_envelopes_of_an_empty_body_is_empty():
    assert raw_envelopes("", {}) == []
    assert raw_envelopes("  \n \n", {}) == []


def test_raw_envelopes_is_bounded_like_the_json_path():
    """The raw endpoint is the LINE-oriented one — what Fluent Bit, Vector and a plain
    curl point at — and it built one dict per line with no cap at all while the JSON
    path was explicitly bounded. A 1 MB body of one-character lines expanded roughly
    100x in memory; at the default 512 MB transport cap that is a worker killed by one
    authenticated POST."""
    body = "x\n" * 5000
    assert len(raw_envelopes(body, {})) == 5000            # unbounded shape, bounded
    assert len(raw_envelopes(body, {}, limit=100)) == 100
    # the bound is on ENVELOPES, so blank lines still cost nothing
    assert len(raw_envelopes("a\n\n\nb\n", {}, limit=10)) == 2


def test_parse_envelopes_reports_truncation_only_when_the_body_really_is_larger():
    """Exactly MAX_ENVELOPES is a complete read; one more is a truncated one. Parsing
    one over the cap is what makes those two distinguishable — without it a sender
    posting exactly the cap would be refused forever."""
    from app import hec

    monkey = hec.MAX_ENVELOPES
    try:
        hec.MAX_ENVELOPES = 5
        exact, truncated = hec._parse_envelopes("y\n" * 5, True, {})
        assert len(exact) == 5 and truncated is False
        over, truncated = hec._parse_envelopes("y\n" * 6, True, {})
        assert len(over) == 5 and truncated is True
        # same rule on the JSON path
        body = "".join('{"event":"e"}' for _ in range(6))
        over, truncated = hec._parse_envelopes(body, False, {})
        assert len(over) == 5 and truncated is True
    finally:
        hec.MAX_ENVELOPES = monkey


# ── the HTTP surface (bare app, stubbed db + ingest) ────────────────────────── #

def _client(monkeypatch, *, valid_token="tok", fail_ingest=False):
    """A TestClient over ONLY `hec.router`, with the two I/O seams stubbed.
    Returns (client, calls) where `calls` records every `ingest.ingest` invocation."""
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    calls: list[tuple] = []

    def fake_verify(key):
        return {"id": 1, "key_prefix": key[:4], "enabled": True} if key == valid_token else None

    def fake_ingest(content, fmt, *, filename=None, source_type="upload", source_addr=None):
        if fail_ingest:
            raise RuntimeError("boom")
        calls.append((content, fmt, source_type, source_addr))
        return {"batch_id": len(calls), "format": fmt, "total": 1}

    monkeypatch.setattr(hec.db, "verify_api_key", fake_verify)
    monkeypatch.setattr(hec.ingest, "ingest", fake_ingest)

    app = FastAPI()
    app.include_router(hec.router)
    return TestClient(app), calls


_AUTH = {"Authorization": "Splunk tok"}


def test_hec_event_accepts_a_concatenated_batch_and_answers_splunk_success(monkeypatch):
    client, calls = _client(monkeypatch)
    body = '{"event":"a","sourcetype":"cisco:asa"}{"event":"b"}'
    r = client.post("/services/collector/event", headers=_AUTH, content=body)
    assert r.status_code == 200
    assert r.json() == {"text": "Success", "code": 0}      # exact shape, nothing extra
    assert {c[1] for c in calls} == {"cisco_asa", "generic_json"}
    assert {c[2] for c in calls} == {"hec"}                # attributed as a HEC batch
    assert r.headers["X-LogOcean-Batch-Ids"] == "1,2"      # detail rides in a header


@pytest.mark.parametrize("path", ["/services/collector",
                                  "/services/collector/event",
                                  "/services/collector/event/1.0"])
def test_hec_event_is_mounted_on_every_path_senders_hard_code(monkeypatch, path):
    client, calls = _client(monkeypatch)
    r = client.post(path, headers=_AUTH, content='{"event":"a"}')
    assert r.status_code == 200 and r.json()["code"] == 0
    assert len(calls) == 1


@pytest.mark.parametrize("path,body", [
    ("/services/collector/event", '{"event":"e"}' * 6),
    ("/services/collector/raw", "line\n" * 6),
])
def test_an_oversized_request_is_refused_retryably_and_ingests_nothing(
        monkeypatch, path, body):
    """The cap must not be a silent delete.

    Answering 200 / `code: 0` here was unrecoverable loss: a HEC sender switch-cases
    on `code`, and 0 means "indexed, you may advance", so it dropped its buffer over
    the events we discarded. Nothing surfaced — no error to the sender, no
    `dropped_rows` on any batch, nothing on /health, one WARNING in the server log.

    It is reachable by ordinary means, not just abuse: the cap counts ENVELOPES while
    the transport cap counts BYTES, and 300,000 minimal envelopes is ~13 MB against a
    512 MB budget — i.e. a forwarder catching up after an outage, which is exactly
    when losing the batch matters most.

    Code 9 / HTTP 503 is the retryable class, so the sender backs off and KEEPS its
    buffer. All-or-nothing: a partial ingest plus a retry would duplicate the prefix,
    and HEC has no way to say "I took the first N".
    """
    monkeypatch.setattr(hec, "MAX_ENVELOPES", 5)
    client, calls = _client(monkeypatch)
    r = client.post(path, headers=_AUTH, content=body)
    assert r.status_code == 503
    assert r.json() == {"text": "Server is busy", "code": 9}
    assert r.headers.get("Retry-After") == "30"
    assert calls == []                       # NOTHING was ingested


@pytest.mark.parametrize("path,body", [
    ("/services/collector/event", '{"event":"e"}' * 5),
    ("/services/collector/raw", "line\n" * 5),
])
def test_a_request_of_exactly_the_cap_still_succeeds(monkeypatch, path, body):
    # The boundary matters: refusing at exactly the cap would wedge a sender that
    # legitimately batches that many, forever.
    monkeypatch.setattr(hec, "MAX_ENVELOPES", 5)
    client, calls = _client(monkeypatch)
    r = client.post(path, headers=_AUTH, content=body)
    assert r.status_code == 200 and r.json()["code"] == 0
    assert len(calls) == 1


def test_hec_event_without_a_token_is_401_code_2(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event", content='{"event":"a"}')
    assert r.status_code == 401 and r.json() == {"text": "Token is required", "code": 2}
    assert calls == []                                     # nothing was ingested


def test_hec_event_with_a_bad_or_wrongly_schemed_token_is_403_code_4(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event",
                    headers={"Authorization": "Splunk nope"}, content='{"event":"a"}')
    assert r.status_code == 403 and r.json() == {"text": "Invalid token", "code": 4}

    # A Bearer header is not a HEC token; it falls through to "required", not "invalid".
    r = client.post("/services/collector/event",
                    headers={"Authorization": "Bearer tok"}, content='{"event":"a"}')
    assert r.status_code == 401 and r.json()["code"] == 2
    assert calls == []


def test_hec_event_accepts_an_x_api_key_for_operator_smoke_tests(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event", headers={"X-API-Key": "tok"},
                    content='{"event":"a"}')
    assert r.status_code == 200 and len(calls) == 1


def test_hec_event_empty_body_is_400_code_5(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event", headers=_AUTH, content="   ")
    assert r.status_code == 400 and r.json() == {"text": "No data", "code": 5}
    assert calls == []


def test_hec_event_unparseable_body_is_400_code_6_not_a_500(monkeypatch):
    client, calls = _client(monkeypatch)
    for body in ("this is not json", "<xml/>", '["a","b"]', '{"a":' * 500 + "1" + "}" * 500):
        r = client.post("/services/collector/event", headers=_AUTH, content=body)
        assert r.status_code == 400, body[:40]
        assert r.json() == {"text": "Invalid data format", "code": 6}
    assert calls == []


def test_hec_event_envelopes_with_no_event_field_are_400_code_12(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event", headers=_AUTH,
                    content='{"host":"h"}{"host":"h2"}')
    assert r.status_code == 400 and r.json() == {"text": "Event field is required", "code": 12}
    assert calls == []


def test_hec_event_tolerates_the_channel_param_and_header(monkeypatch):
    """Real senders always send these. Declaring them would 422 a correct sender."""
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/event?channel=B5A5FDDA-1AAB-4F27-9C87-000000000000",
                    headers={**_AUTH, "X-Splunk-Request-Channel": "B5A5FDDA-1AAB"},
                    content='{"event":"a"}')
    assert r.status_code == 200 and r.json()["code"] == 0
    assert len(calls) == 1


def test_hec_event_accepts_a_gzip_body(monkeypatch):
    client, calls = _client(monkeypatch)
    body = gzip.compress(b'{"event":"a"}{"event":"b"}')
    r = client.post("/services/collector/event", headers=_AUTH, content=body)
    assert r.status_code == 200 and len(calls) == 1
    assert len(calls[0][0].splitlines()) == 2


def test_hec_event_rejects_an_oversized_body_with_413(monkeypatch):
    client, calls = _client(monkeypatch)
    # `settings` is a frozen dataclass, so the module global is swapped rather than
    # mutated — the same reason conftest reaches for `object.__setattr__`.
    monkeypatch.setattr(hec, "settings", SimpleNamespace(max_upload_mb=0))
    r = client.post("/services/collector/event", headers=_AUTH, content='{"event":"a"}')
    assert r.status_code == 413 and r.json() == {"text": "Invalid data format", "code": 6}
    assert calls == []


def test_hec_event_ingest_failure_is_a_clean_code_8(monkeypatch):
    """A sender must get a shaped body, never a stack trace or FastAPI's `{"detail"}`."""
    client, _ = _client(monkeypatch, fail_ingest=True)
    r = client.post("/services/collector/event", headers=_AUTH, content='{"event":"a"}')
    assert r.status_code == 500
    assert r.json() == {"text": "Internal server error", "code": 8}


def test_hec_raw_takes_its_metadata_from_the_query_string(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/raw?sourcetype=cisco:asa&host=fw1",
                    headers=_AUTH, content="%ASA-6-1: a\n%ASA-6-2: b\n")
    assert r.status_code == 200 and r.json()["code"] == 0
    assert calls[0][1] == "cisco_asa"
    assert calls[0][0] == "%ASA-6-1: a\n%ASA-6-2: b"


def test_hec_raw_wraps_unmapped_text_so_the_query_metadata_survives(monkeypatch):
    client, calls = _client(monkeypatch)
    r = client.post("/services/collector/raw?host=web01&index=main",
                    headers=_AUTH, content="hello world")
    assert r.status_code == 200
    content, fmt, _, _ = calls[0]
    assert fmt == "generic_json"
    rec = json.loads(content)
    assert rec["message"] == "hello world" and rec["host"] == "web01" and rec["index"] == "main"


def test_hec_health_needs_no_token(monkeypatch):
    """A sender polls health to decide whether to send at all, so it must not be able
    to fail for a reason unrelated to the endpoint accepting posts."""
    client, _ = _client(monkeypatch)
    for path in ("/services/collector/health", "/services/collector/health/1.0"):
        r = client.get(path)
        assert r.status_code == 200
        assert r.json() == {"text": "HEC is healthy", "code": 17}


def test_hec_ack_is_explicitly_disabled(monkeypatch):
    """`useACK` needs a durable queue LogOcean does not have; failing fast beats a
    sender blocking forever on an acknowledgement that is never coming."""
    client, _ = _client(monkeypatch)
    r = client.post("/services/collector/ack", headers=_AUTH, content='{"acks":[1]}')
    assert r.status_code == 400
    assert r.json() == {"text": "ACK is disabled", "code": 14}

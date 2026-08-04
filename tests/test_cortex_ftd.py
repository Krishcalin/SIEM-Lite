# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the Cortex Data Lake collector and the Cisco FTD parser.

DB-free and network-free: every URL, body, response unwrap and record reshape is a
pure function called with a fixture string, and the two ``fetch`` walks are driven
by patching the thin ``_token`` / ``_post`` / ``_get`` methods on the instance.

The CIM assertions are MEASURED, not assumed — they were produced by running
``app.cim.match.tags_for`` over the parsed output of these exact fixtures against
the shipped ``models.yaml``, and they are the reason no registry edit is needed for
either source.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pytest

from app.cim import match
from app.collectors import cortex
from app.collectors.cortex import (CortexDataLakeCollector, _epoch, cdl_access_token,
                                   cdl_csv, cdl_host, cdl_job_id, cdl_page_records,
                                   cdl_query_body, cdl_query_url, cdl_results_url,
                                   cdl_row, cdl_table_type, cdl_tables,
                                   cdl_token_form)
from app.parsers import cisco_ftd, paloalto_csv
from app.parsers.cisco_ftd import kv_pairs

# ── fixtures ──────────────────────────────────────────────────────────────────
# A Cortex Data Lake `firewall.traffic` record. `log_type` is an INTEGER here on
# purpose: that is how CDL returns the enum, and it is the value that would hijack
# the CIM COALESCE if the reshape let it through as a raw key (see test below).
CDL_TRAFFIC = {
    "receive_time": 1781690701, "time_generated": 1781690698, "log_type": 1,
    "sub_type": "end", "source_ip": "10.20.30.40", "dest_ip": "93.184.216.34",
    "source_port": 52344, "dest_port": 443, "protocol": "tcp", "app": "ssl",
    "action": "allow", "rule": "Allow-Outbound-Web", "source_user": "corp\\jdoe",
    "bytes": 84213, "severity": "informational",
    "category": "computer-and-internet-info", "device_name": "PrismaAccess-GW-01",
    "tunnel_id": 991, "session_id": 771234, "source_location": "US",
    "flags": {"nat": True, "pcap": False},
}
CDL_THREAT = {
    "receive_time": 1781690820, "time_generated": 1781690815, "log_type": 2,
    "sub_type": "vulnerability", "source_ip": "203.0.113.9",
    "dest_ip": "10.20.30.40", "source_port": 40221, "dest_port": 445,
    "protocol": "tcp", "app": "ms-ds-smb", "action": "reset-both",
    "rule": "Block-Inbound", "severity": "critical",
    "threat_name": "SMB: Microsoft Windows SMB RCE Vulnerability",
    "threat_id": 30845, "category": "code-execution",
    "device_name": "PrismaAccess-GW-01",
}
CDL_URL = {
    "receive_time": 1781690880, "time_generated": 1781690875, "log_type": 2,
    "sub_type": "url", "source_ip": "10.20.30.41", "dest_ip": "151.101.1.69",
    "source_port": 51602, "dest_port": 443, "protocol": "tcp",
    "app": "web-browsing", "action": "alert", "rule": "Allow-Outbound-Web",
    "source_user": "corp\\asmith", "severity": "informational",
    "url": "cdn.example.com/report.pdf", "category": "business-and-economy",
    "device_name": "PrismaAccess-GW-01",
}

FTD_CONNECTION = (
    r"<134>Jun 15 2026 10:00:31 ftd01 : %FTD-6-430003: EventPriority: Low, "
    r"DeviceUUID: 1a2b3c4d-0000-0000-0000-aabbccddeeff, InstanceID: 1, "
    r"FirstPacketSecond: 2026-06-15T10:00:28Z, ConnectionID: 4711, "
    r"AccessControlRuleAction: Allow, SrcIP: 10.20.30.40, DstIP: 93.184.216.34, "
    r"SrcPort: 51514, DstPort: 443, Protocol: tcp, IngressInterface: inside, "
    r"EgressInterface: outside, ACPolicy: Corp-ACP, "
    r"AccessControlRuleName: Allow-Outbound-Web, Prefilter Policy: Unknown, "
    r"User: corp\jdoe, Client: SSL client, ApplicationProtocol: HTTPS, "
    r"WebApplication: Example, InitiatorBytes: 1834, ResponderBytes: 9271, "
    r"NAPPolicy: Balanced Security and Connectivity, Version 2")
FTD_INTRUSION = (
    r"<129>Jun 15 2026 10:01:12 ftd01 : %FTD-1-430001: EventPriority: High, "
    r"FirstPacketSecond: 2026-06-15T10:01:10Z, ConnectionID: 4712, "
    r"AccessControlRuleAction: Block, SrcIP: 45.83.122.7, DstIP: 10.20.30.40, "
    r"SrcPort: 40331, DstPort: 445, Protocol: tcp, "
    r"AccessControlRuleName: Block-Inbound-SMB, User: No Authentication Required, "
    r"ApplicationProtocol: NetBIOS-ssn (SMB), InlineResult: Blocked, "
    r"GID: 1, SID: 2019401, Revision: 5, "
    r'Message: "OS-WINDOWS Microsoft Windows SMB remote code execution attempt", '
    r"Classification: Attempted Administrator Privilege Gain, Priority: 1")
FTD_FILE = (
    r"<134>Jun 15 2026 10:02:44 ftd01 : %FTD-6-430004: EventPriority: Low, "
    r"FirstPacketSecond: 2026-06-15T10:02:40Z, SrcIP: 10.20.30.41, "
    r"DstIP: 151.101.1.69, SrcPort: 51602, DstPort: 80, Protocol: tcp, "
    r"FileName: quarterly-report.pdf, FileType: PDF, FileSize: 102400, "
    r"FileDirection: Download, FileAction: Detect, FilePolicy: Corp-File-Policy, "
    r"FileSHA256: 3b7c1f4e9a2d5c8b6e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f, "
    r"ApplicationProtocol: HTTP, User: corp\asmith")
FTD_MALWARE = (
    r"<129>Jun 15 2026 10:03:19 ftd01 : %FTD-1-430005: EventPriority: High, "
    r"FirstPacketSecond: 2026-06-15T10:03:15Z, SrcIP: 10.20.30.55, "
    r"DstIP: 45.83.122.7, SrcPort: 33444, DstPort: 8080, Protocol: 6, "
    r"FileName: invoice_2026.exe, FileType: MSEXE, FileDirection: Download, "
    r"FileAction: Block, FileDisposition: Malware, "
    r"ThreatName: W32.Trojan.Emotet.tht, FilePolicy: Corp-File-Policy, "
    r"FileSHA256: 9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665544332211aabbccddeeff00, "
    r"ApplicationProtocol: HTTP, User: corp\bwayne")
FTD_SNORT = (
    '<129>Jun 15 2026 10:04:02 fmc01 SFIMS: [1:2019401:5] '
    '"OS-WINDOWS Microsoft Windows SMB remote code execution attempt" '
    '[Impact: Vulnerable] From "ftd01" at Mon Jun 15 10:04:02 2026 UTC '
    '[Classification: Attempted Administrator Privilege Gain] [Priority: 1] '
    '{tcp} 45.83.122.7:40332 -> 10.20.30.40:445')
FTD_SNORT_BLOCKED = (
    '<133>Jun 15 2026 10:05:20 fmc01 SFIMS: [1:2100498:9] '
    '"GPL ATTACK_RESPONSE id check returned root" '
    '[Classification: Potentially Bad Traffic] [Priority: 2] '
    '{tcp} 10.20.30.40:80 -> 203.0.113.9:44112 [Blocked]')
# A Lina data-plane message: FTD emits it, but `cisco_asa` owns that grammar.
FTD_LINA = ("<166>Jun 15 2026 10:06:00 ftd01 : %FTD-6-302013: Built outbound TCP "
            "connection 99 for outside:1.2.3.4/443 to inside:10.20.30.40/51999")

FTD_LOG = "\n".join([FTD_CONNECTION, FTD_INTRUSION, FTD_FILE, FTD_MALWARE,
                     FTD_SNORT, FTD_SNORT_BLOCKED, FTD_LINA]) + "\n"


def _ftd_by_class() -> dict:
    """First event of each class from the mixed log (two lines are `intrusion`)."""
    out: dict = {}
    for e in cisco_ftd.parse(FTD_LOG):
        out.setdefault(e.log_type, e)
    return out


def _cdl_events(*pairs):
    """Records -> reshaped CSV -> whatever `paloalto_csv` makes of them."""
    rows = [cdl_row(rec, cdl_table_type(table)) for table, rec in pairs]
    return list(paloalto_csv.parse(cdl_csv(rows)))


# ══════════════════════════════════════════════════════════════════════════════
#  Cortex Data Lake — OAuth2 refresh-token grant
# ══════════════════════════════════════════════════════════════════════════════
def test_cdl_token_form_is_a_refresh_token_grant():
    form = cdl_token_form("cid", "s3cr3t", "rt-abc")
    assert "grant_type=refresh_token" in form
    assert "client_id=cid" in form and "client_secret=s3cr3t" in form
    assert "refresh_token=rt-abc" in form
    # CDL is NOT client_credentials — that is the Microsoft flow in cloud.py.
    assert "client_credentials" not in form
    assert cdl_access_token('{"access_token":"AT","expires_in":900}') == "AT"
    assert cdl_access_token('{"error":"invalid_grant"}') is None
    assert cdl_access_token("not json") is None


# ══════════════════════════════════════════════════════════════════════════════
#  Cortex Data Lake — URLs, query bodies, response unwrapping
# ══════════════════════════════════════════════════════════════════════════════
def test_cdl_host_resolves_a_region_and_refuses_an_unknown_one():
    assert cdl_host("americas") == "api.us.cdl.paloaltonetworks.com"
    assert cdl_host("US") == "api.us.cdl.paloaltonetworks.com"
    assert cdl_host("europe") == "api.nl.cdl.paloaltonetworks.com"
    assert cdl_host("") == "api.us.cdl.paloaltonetworks.com"     # default
    # a literal hostname passes through (private / preview endpoints)
    assert cdl_host("https://api.test.cdl.example.com/") == "api.test.cdl.example.com"
    # An unknown region must RAISE, not silently default: the wrong region returns a
    # valid empty result set forever, which reads as "nothing happened".
    with pytest.raises(ValueError):
        cdl_host("atlantis")


def test_cdl_query_and_results_urls_are_built_off_the_host():
    assert cdl_query_url("api.us.cdl.paloaltonetworks.com") == \
        "https://api.us.cdl.paloaltonetworks.com/query/v2/jobs"
    u = cdl_results_url("api.us.cdl.paloaltonetworks.com", "job/1 2", page=3)
    assert u.startswith("https://api.us.cdl.paloaltonetworks.com/query/v2/jobResults/")
    assert "job%2F1%202" in u          # the id is escaped into the path
    assert "pageNumber=3" in u and "maxWait=" in u and "pageSize=" in u


def test_cdl_query_body_windows_one_table_and_refuses_an_unsafe_name():
    body = cdl_query_body("firewall.traffic", 100, 200, limit=50)
    payload = json.loads(body)
    assert payload["startTime"] == 100 and payload["endTime"] == 200
    assert payload["query"] == ("SELECT * FROM `firewall.traffic` WHERE time_generated "
                                "BETWEEN 100 AND 200 ORDER BY time_generated ASC LIMIT 50")
    # A table name is interpolated into SQL, so this is the function that must refuse
    # anything that is not a dotted identifier.
    for bad in ("firewall.traffic`; DROP TABLE x --", "fire wall", "", "a;b"):
        with pytest.raises(ValueError):
            cdl_query_body(bad, 1, 2)


def test_cdl_tables_parses_the_setting_and_drops_unsafe_entries():
    assert cdl_tables("firewall.traffic, firewall.threat") == \
        ("firewall.traffic", "firewall.threat")
    assert cdl_tables("firewall.traffic, bad name") == ("firewall.traffic",)
    # empty or fully-invalid -> the shipped default, never an empty poll list
    assert cdl_tables("") == cortex._DEFAULT_TABLES
    assert cdl_tables("!!!") == cortex._DEFAULT_TABLES


def test_cdl_job_id_and_page_unwrap():
    assert cdl_job_id('{"jobId":"J1"}') == "J1"
    assert cdl_job_id('{"jobId":""}') is None
    assert cdl_job_id('{"nope":1}') is None
    assert cdl_job_id("not json") is None

    page = json.dumps({"state": "DONE", "rowsInPage": 2,
                       "page": {"result": {"data": [{"a": 1}, {"b": 2}, "junk"]}}})
    recs, state = cdl_page_records(page)
    assert recs == [{"a": 1}, {"b": 2}] and state == "DONE"      # non-dicts dropped
    assert cdl_page_records('{"state":"RUNNING","page":{}}') == ([], "RUNNING")
    assert cdl_page_records("not json") == ([], None)
    assert cdl_page_records("[1,2]") == ([], None)


def test_cdl_table_type_files_url_and_wildfire_under_threat():
    # PAN's own convention: URL / WildFire / data-filtering records are Type=THREAT
    # with a distinguishing subtype. `paloalto_csv` (and the registry) expect that.
    assert cdl_table_type("firewall.traffic") == "TRAFFIC"
    assert cdl_table_type("firewall.threat") == "THREAT"
    assert cdl_table_type("firewall.url") == "THREAT"
    assert cdl_table_type("firewall.wildfire") == "THREAT"
    assert cdl_table_type("firewall.system") == "SYSTEM"
    assert cdl_table_type("panw.config") == "CONFIG"
    assert cdl_table_type("firewall.something_new") == "SOMETHING_NEW"


# ══════════════════════════════════════════════════════════════════════════════
#  Cortex Data Lake — the reshape into a PAN CSV export
# ══════════════════════════════════════════════════════════════════════════════
def test_cdl_row_stamps_the_queried_tables_type_over_the_records_own():
    """The `Type` cell decides PAN's CIM Network membership, so it may not come from
    the record: CDL returns `log_type` as an integer enum."""
    row = cdl_row(CDL_TRAFFIC, "TRAFFIC")
    assert row["Type"] == "TRAFFIC"                     # not the record's `1`
    # every spelling of the type is CONSUMED, so none of them can reappear as an
    # extra column and win the registry's COALESCE `raw: [log_type, type, Type]`
    assert "log_type" not in row and "type" not in row
    assert row["Threat/Content Type"] == "end"
    assert row["Source address"] == "10.20.30.40" and row["Destination Port"] == "443"
    assert row["Source User"] == "corp\\jdoe" and row["Bytes"] == "84213"
    # with no table type, the record's own value is used unchanged
    assert cdl_row({"log_type": "TRAFFIC"})["Type"] == "TRAFFIC"


def test_cdl_row_keeps_unconsumed_fields_and_encodes_containers():
    row = cdl_row(CDL_TRAFFIC, "TRAFFIC")
    # Prisma Access extras survive into `raw` instead of being dropped on the floor
    assert row["tunnel_id"] == "991" and row["source_location"] == "US"
    # a nested object is JSON-encoded, not discarded (CIM cannot read a container,
    # but full-text search and the jsonb index can)
    assert row["flags"] == '{"nat":true,"pcap":false}'
    # ...and a consumed field never doubles up under its CDL name
    for consumed in ("source_ip", "dest_ip", "sub_type", "source_user", "bytes"):
        assert consumed not in row
    # an absent field is an empty cell, which `paloalto_csv._g` skips
    assert cdl_row({}, "TRAFFIC")["Severity"] == ""


def test_cdl_csv_is_empty_for_nothing_and_header_mapped_otherwise():
    # '' (not '[]', not a header-only doc) is the "nothing new" signal: run_collector
    # skips ingest but still advances the cursor. A header-only string would ingest a
    # zero-row batch on every idle poll forever.
    assert cdl_csv([]) == ""
    text = cdl_csv([cdl_row(CDL_TRAFFIC, "TRAFFIC"), cdl_row(CDL_THREAT, "THREAT")])
    header = next(csv.reader(io.StringIO(text)))
    assert header[:4] == ["Receive Time", "Generate Time", "Type", "Threat/Content Type"]
    # union header over mixed log types: the traffic-only extras still get a column
    assert "tunnel_id" in header and header.index("tunnel_id") > header.index("Category")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == 2
    assert rows[0]["Type"] == "TRAFFIC" and rows[1]["Type"] == "THREAT"
    assert rows[1]["tunnel_id"] == ""          # missing value, not a ragged row


def test_cdl_records_reach_the_palo_alto_csv_parser_unchanged():
    """No third PAN parser: the reshape lands on `paloalto_csv`'s header mapping."""
    events = _cdl_events(("firewall.traffic", CDL_TRAFFIC),
                         ("firewall.threat", CDL_THREAT),
                         ("firewall.url", CDL_URL))
    assert [e.vendor for e in events] == ["paloalto"] * 3
    assert [e.product for e in events] == ["ngfw"] * 3
    # log_type is the SUBTYPE — that is what both PAN parsers do, and what the
    # corrected registry is written against.
    assert [e.log_type for e in events] == ["end", "vulnerability", "url"]
    traffic = events[0]
    # epoch seconds survive `parse_ts` (CDL does not send ISO timestamps)
    assert traffic.event_time is not None and traffic.event_time.year == 2026
    assert traffic.src_ip == "10.20.30.40" and traffic.dst_port == 443
    assert traffic.action == "allow" and traffic.app == "ssl"
    assert traffic.bytes_total == 84213 and traffic.user_name == "corp\\jdoe"
    assert traffic.rule_name == "Allow-Outbound-Web"
    assert traffic.host_name == "PrismaAccess-GW-01"
    assert events[1].severity == "critical"
    assert events[1].message == "SMB: Microsoft Windows SMB RCE Vulnerability"
    assert events[2].message == "cdn.example.com/report.pdf"


def test_cortex_events_land_in_the_corrected_pan_cim_models():
    """MEASURED with `match.tags_for` against the shipped registry.

    The CIM audit corrected PAN membership to read the real TYPE out of `raw`
    (`pan_type: {raw: [log_type, type, Type], values: [traffic]}`) because both PAN
    parsers put the SUBTYPE in `log_type`. These are the tags that rule produces for
    Cortex-sourced records — traffic in Network, an IPS hit in IDS only, a URL
    record in Web only."""
    traffic, threat, url = _cdl_events(("firewall.traffic", CDL_TRAFFIC),
                                       ("firewall.threat", CDL_THREAT),
                                       ("firewall.url", CDL_URL))
    assert match.tags_for(traffic) == ["network"]
    assert match.tags_for(threat) == ["ids"]        # NOT vulnerability, NOT network
    assert match.tags_for(url) == ["web"]

    # ...and the `Type` cell is what carries Network membership. Drop it and the
    # traffic record falls out of the model — which is exactly the failure the audit
    # found, and the reason the reshape may not let `log_type: 1` through.
    blinded = cdl_row(CDL_TRAFFIC, "TRAFFIC")
    blinded.pop("Type")
    (evt,) = list(paloalto_csv.parse(cdl_csv([blinded])))
    assert match.tags_for(evt) == []


# ══════════════════════════════════════════════════════════════════════════════
#  Cortex Data Lake — the collector itself
# ══════════════════════════════════════════════════════════════════════════════
def test_cortex_configured_needs_the_oauth_triple_only():
    ok = CortexDataLakeCollector("americas", "cid", "sec", "rt", "", 24)
    assert ok.configured()
    assert not CortexDataLakeCollector("americas", "", "sec", "rt", "", 24).configured()
    assert not CortexDataLakeCollector("americas", "cid", "", "rt", "", 24).configured()
    assert not CortexDataLakeCollector("americas", "cid", "sec", "", "", 24).configured()
    # region and tables have defaults, so a blank region is still "configured"
    assert CortexDataLakeCollector("", "cid", "sec", "rt", "", 24).configured()
    assert ok.tables == cortex._DEFAULT_TABLES
    assert ok.fmt == "paloalto_csv"       # an ALREADY-registered parser key


def test_cortex_epoch_reads_both_cursor_spellings_this_column_holds():
    """`iso_lookback` writes `...T00:00:00.000Z`; `max_time_iso` writes `...+00:00`.
    Both live in the same text column, so both must window identically."""
    from datetime import datetime, timezone
    fallback = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert _epoch("2026-06-25T10:00:00.000Z", fallback) == \
        _epoch("2026-06-25T10:00:00+00:00", fallback)
    assert _epoch(None, fallback) == int(fallback.timestamp())
    assert _epoch("nonsense", fallback) == int(fallback.timestamp())


def _fake_page(records, state="DONE"):
    return json.dumps({"state": state, "page": {"result": {"data": records}}})


def test_cortex_fetch_reshapes_a_page_and_advances_the_cursor(monkeypatch):
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    monkeypatch.setattr(c, "_get",
                        lambda token, url: _fake_page([CDL_TRAFFIC, CDL_THREAT]))
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.count == 2
    assert res.content.startswith("Receive Time,")          # a PAN CSV export
    assert "TRAFFIC" in res.content
    # cursor = the newest `time_generated` epoch (1781690815), rendered ISO — note
    # it is NOT the newest `receive_time`, which is 5s later.
    assert res.cursor == "2026-06-17T10:06:55+00:00"


def test_cortex_fetch_returns_empty_content_but_keeps_the_cursor(monkeypatch):
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    monkeypatch.setattr(c, "_get", lambda token, url: _fake_page([]))
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.content == "" and res.count == 0
    # NOT None: run_collector writes the cursor unconditionally, so a None here
    # would NULL the checkpoint and restart from the whole lookback window.
    assert res.cursor == "2026-06-25T00:00:00.000Z"


def test_a_truncated_table_holds_the_shared_cursor_back_for_every_other_table(
        monkeypatch):
    """One checkpoint, N independently-truncated tables.

    Each table is queried with its own `LIMIT`, but all of them share a single cursor
    column. Advancing it to the maximum over the UNION let a quiet table that reached
    the window end drag the checkpoint past a busy table's cut-off, and every row in
    that gap was skipped permanently — the next poll's `BETWEEN start AND end` begins
    after them. That fires on the shipped default table set, where `firewall.traffic`
    outruns `firewall.threat`/`firewall.url` by orders of magnitude.

    Here traffic is truncated at an OLD timestamp while threat reaches a much newer
    one; the cursor must follow traffic, not threat.
    """
    monkeypatch.setattr(cortex, "_PAGE_SIZE", 2)
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt",
                                "firewall.traffic,firewall.threat", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')

    busy_old = [dict(CDL_TRAFFIC, time_generated=1781690000),
                dict(CDL_TRAFFIC, time_generated=1781690100)]     # full page -> cut off
    quiet_new = [dict(CDL_THREAT, time_generated=1781999999)]     # short page -> drained
    pages = iter([_fake_page(busy_old), _fake_page(busy_old),     # traffic, 2 full pages
                  _fake_page(busy_old), _fake_page(busy_old),
                  _fake_page(busy_old),                           # ... to _MAX_PAGES
                  _fake_page(quiet_new)])                         # threat, one short page
    monkeypatch.setattr(c, "_get", lambda token, url: next(pages))

    res = c.fetch("2026-06-25T00:00:00.000Z")
    # 1781690100 = traffic's newest FETCHED row, not 1781999999 (threat's newest).
    assert res.cursor == datetime.fromtimestamp(1781690100, timezone.utc).isoformat()


def test_cortex_fetch_walks_pages_and_stops_on_a_short_one(monkeypatch):
    monkeypatch.setattr(cortex, "_PAGE_SIZE", 2)
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    # exhaustible: a third GET would raise StopIteration, so an over-fetch fails loudly
    pages = iter([_fake_page([CDL_TRAFFIC, CDL_THREAT]), _fake_page([CDL_URL])])
    monkeypatch.setattr(c, "_get", lambda token, url: next(pages))
    res = c.fetch(None)
    assert res.count == 3


def test_cortex_fetch_is_bounded_by_max_pages(monkeypatch):
    """One poll must not hold the serial scheduler thread forever."""
    monkeypatch.setattr(cortex, "_PAGE_SIZE", 1)
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    seen = []
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    monkeypatch.setattr(c, "_get",
                        lambda token, url: seen.append(url) or _fake_page([CDL_TRAFFIC]))
    res = c.fetch(None)
    assert len(seen) == cortex._MAX_PAGES
    assert res.count == cortex._MAX_PAGES


def test_cortex_fetch_raises_on_a_failed_job(monkeypatch):
    """Never swallowed: run_collector turns the exception into last_status='error'
    and leaves the cursor untouched, so the window is retried, not skipped."""
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    monkeypatch.setattr(c, "_get", lambda token, url: _fake_page([], state="FAILED"))
    with pytest.raises(RuntimeError):
        c.fetch("2026-06-25T00:00:00.000Z")


def test_cortex_fetch_raises_when_the_job_never_completed(monkeypatch):
    """A still-RUNNING job has rows we have not read. Advancing the cursor past them
    would skip that window for good, so the poll fails and retries instead."""
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt", "firewall.traffic", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_post", lambda token, url, body: '{"jobId":"J1"}')
    monkeypatch.setattr(c, "_get",
                        lambda token, url: _fake_page([CDL_TRAFFIC], state="RUNNING"))
    with pytest.raises(RuntimeError):
        c.fetch("2026-06-25T00:00:00.000Z")
    # a response that carries no state at all is unknowable, not a failure
    monkeypatch.setattr(
        c, "_get", lambda token, url: json.dumps({"page": {"result": {"data": []}}}))
    assert c.fetch("2026-06-25T00:00:00.000Z").count == 0


def test_cortex_fetch_surfaces_a_bad_region_instead_of_querying_the_wrong_one(monkeypatch):
    # __init__ must never raise (build_collectors constructs every candidate), so the
    # bad value surfaces from fetch and lands in last_status/last_error.
    c = CortexDataLakeCollector("atlantis", "cid", "sec", "rt", "firewall.traffic", 24)
    assert c.configured()
    monkeypatch.setattr(c, "_token", lambda: "AT")
    with pytest.raises(ValueError):
        c.fetch(None)


def test_cortex_fetch_skips_a_table_whose_job_was_not_accepted(monkeypatch):
    c = CortexDataLakeCollector("americas", "cid", "sec", "rt",
                                "firewall.traffic,firewall.threat", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    submits = iter(['{"error":"quota"}', '{"jobId":"J2"}'])
    monkeypatch.setattr(c, "_post", lambda token, url, body: next(submits))
    monkeypatch.setattr(c, "_get", lambda token, url: _fake_page([CDL_THREAT]))
    res = c.fetch(None)
    assert res.count == 1 and "THREAT" in res.content


# ══════════════════════════════════════════════════════════════════════════════
#  Cisco FTD — the key/value grammar
# ══════════════════════════════════════════════════════════════════════════════
def test_ftd_kv_pairs_keeps_vendor_spelling_and_survives_commas_in_values():
    kv = kv_pairs('SrcIP: 10.0.0.1, Prefilter Policy: Unknown, '
                  'NAPPolicy: Balanced Security, Version 2, Message: "a, b", User: ')
    # keys byte-exact (CIM reads `raw` keys byte-exact — no lower-casing here)
    assert kv["SrcIP"] == "10.0.0.1"
    assert kv["Prefilter Policy"] == "Unknown"          # a key may contain a space
    # the value is taken up to the next `, Key:` boundary, not the next comma
    assert kv["NAPPolicy"] == "Balanced Security, Version 2"
    assert kv["Message"] == "a, b"                      # quotes stripped
    assert kv["User"] == ""
    assert kv_pairs("") == {} and kv_pairs("no pairs here") == {}


def test_ftd_connection_event_normalizes_the_flow():
    e = _ftd_by_class()["connection"]
    assert (e.vendor, e.product) == ("cisco", "firepower")
    assert e.src_ip == "10.20.30.40" and e.src_port == 51514
    assert e.dst_ip == "93.184.216.34" and e.dst_port == 443
    assert e.protocol == "tcp" and e.action == "allow"
    assert e.app == "HTTPS" and e.user_name == "corp\\jdoe"
    assert e.host_name == "ftd01"                       # from the syslog header
    assert e.rule_name == "Allow-Outbound-Web"
    assert e.bytes_total == 1834 + 9271                 # initiator + responder
    # the payload timestamp beats the syslog header's
    assert e.event_time.isoformat() == "2026-06-15T10:00:28+00:00"
    assert e.raw["message_id"] == "430003" and e.raw["event_class"] == "connection"


def test_ftd_intrusion_event_carries_the_signature_and_classification():
    e = _ftd_by_class()["intrusion"]
    assert e.rule_name == "OS-WINDOWS Microsoft Windows SMB remote code execution attempt"
    assert e.severity == "high"                         # Priority: 1
    assert e.action == "block"                          # InlineResult: Blocked
    # FTD's placeholder for "no authenticated identity" must not become a username
    assert e.user_name is None
    # `Classification` aliased to the key the shipped IDS `category` field reads
    assert e.raw["category"] == "Attempted Administrator Privilege Gain"
    assert e.raw["Classification"] == "Attempted Administrator Privilege Gain"
    assert e.raw["SID"] == "2019401"


def test_ftd_file_and_malware_events_alias_the_file_hash():
    events = _ftd_by_class()
    f, m = events["file-transfer"], events["malware"]
    assert f.rule_name == "Corp-File-Policy" and f.action == "detect"
    assert f.raw["FileName"] == "quarterly-report.pdf"
    # `raw` keys are byte-exact, so `FileSHA256` alone is invisible to the shipped
    # `file_hash: raw: [Hashes, SHA256, …]` mapping — hence the write-back.
    assert f.raw["SHA256"] == f.raw["FileSHA256"]
    assert m.rule_name == "W32.Trojan.Emotet.tht"       # the detection name
    assert m.action == "block" and m.severity == "high"
    assert m.raw["SHA256"].startswith("9f8e7d6c")
    assert m.protocol == "tcp"                          # numeric `Protocol: 6`


def test_ftd_snort_alert_line_is_parsed():
    events = [e for e in cisco_ftd.parse(FTD_SNORT)]
    assert len(events) == 1
    e = events[0]
    assert e.log_type == "intrusion" and e.severity == "high"
    assert e.rule_name == "OS-WINDOWS Microsoft Windows SMB remote code execution attempt"
    assert e.src_ip == "45.83.122.7" and e.src_port == 40332
    assert e.dst_ip == "10.20.30.40" and e.dst_port == 445
    assert e.protocol == "tcp"
    assert e.host_name == "ftd01"                       # the sensor, not the FMC
    assert e.raw["signature_id"] == "1:2019401:5"
    assert e.raw["category"] == "Attempted Administrator Privilege Gain"
    assert e.raw["impact"] == "Vulnerable"
    assert e.action == "detect"                         # no inline-drop verdict


def test_ftd_snort_inline_drop_is_a_bare_bracket_not_the_word_block():
    """`[Blocked]` has no `key:`, so the tag regex cannot see it — and scanning the
    whole line for "block" would call every alert whose NAME contains the word a
    block."""
    (blocked,) = list(cisco_ftd.parse(FTD_SNORT_BLOCKED))
    assert blocked.action == "block" and blocked.severity == "medium"
    # the header is cut at the `SFIMS:` program tag, so the host is the FMC and not
    # the program name that follows it
    assert blocked.host_name == "fmc01"
    named = FTD_SNORT_BLOCKED.replace(" [Blocked]", "").replace(
        "GPL ATTACK_RESPONSE id check returned root", "POLICY block-page redirect")
    (detected,) = list(cisco_ftd.parse(named))
    assert detected.action == "detect"


def test_ftd_delegates_the_lina_messages_that_cisco_asa_owns():
    """Only 430001-430005 and the Snort line are this parser's own grammar, but a Lina
    data-plane message must not be DROPPED for that — `detect_format` is a whole-file
    decision and an FTD box emits both down one stream, so discarding the losing half
    silently deleted a third of a real firewall log with `errors: 0` on the batch.

    `cisco_asa` owns the grammar, so the line is handed to it rather than thrown away:
    every input line still produces an event, and it is the SAME parse cisco_asa would
    have given it — not a second, different one.
    """
    from app.parsers import cisco_asa

    (delegated,) = list(cisco_ftd.parse(FTD_LINA))
    (direct,) = list(cisco_asa.parse(FTD_LINA))
    assert delegated.log_type == direct.log_type       # one line, one parse
    assert delegated.src_ip == direct.src_ip and delegated.message == direct.message

    lines = [ln for ln in FTD_LOG.splitlines() if ln.strip()]
    assert len(list(cisco_ftd.parse(FTD_LOG))) == len(lines)     # nothing dropped


def test_ftd_never_raises_on_garbage():
    junk = ("\n\n   \nnot a log line at all\n"
            "<134>Jun 15 2026 10:00:31 ftd01 : %FTD-6-430003:\n"     # empty payload
            "[1:2:3] no flow here\n"
            "10.0.0.1:1 -> 10.0.0.2:2 but no signature id\n")
    events = list(cisco_ftd.parse(junk))
    # the empty-payload 430003 is still a real event; nothing else qualifies
    assert [e.log_type for e in events] == ["connection"]
    assert events[0].src_ip is None and events[0].message is None


def test_ftd_events_land_in_the_shipped_cim_models():
    """MEASURED with `match.tags_for` against the shipped registry — no models.yaml
    edit is required for any of the four event classes.

    `log_type` carries the EVENT CLASS rather than `cisco_asa`'s numeric message id
    precisely so these four generic `log_type` clauses can reach four models. Every
    event is also a Network member through `{vendor: [cisco], product: [asa,
    firepower, ios]}`, which is correct: all four carry a full 5-tuple."""
    events = _ftd_by_class()
    assert match.tags_for(events["connection"]) == ["network"]
    assert match.tags_for(events["intrusion"]) == ["ids", "network"]
    # NOT Endpoint: 430004 is an inline network file-transfer observation, seen by
    # the firewall, with no host agent involved — see the models.yaml note. It used
    # to spell its log_type `file`, the token the Endpoint clause carries for a FIM
    # source, which also split it from its sibling 430005 for no semantic reason.
    assert match.tags_for(events["file-transfer"]) == ["network"]
    assert match.tags_for(events["malware"]) == ["malware", "network"]
    # the Snort line reaches IDS through the same `intrusion` handle
    (snort,) = list(cisco_ftd.parse(FTD_SNORT))
    assert match.tags_for(snort) == ["ids", "network"]
    # ...and the class really is the handle: retag it and IDS membership is lost,
    # leaving only the vendor/product Network clause.
    snort.log_type = "430001"
    assert match.tags_for(snort) == ["network"]


def test_ftd_cim_fields_resolve_off_the_measured_raw_keys():
    """The membership above is worthless if the models project nulls. These are the
    exact `raw` alternatives the shipped IDS / Malware / Endpoint fields read."""
    events = _ftd_by_class()
    ids = events["intrusion"]
    assert ids.rule_name                       # IDS.signature  <- rule_name
    assert ids.raw.get("category")             # IDS.category   <- raw:[category, …]
    assert ids.src_ip and ids.dst_ip and ids.dst_port and ids.protocol
    mal = events["malware"]
    assert mal.rule_name                       # Malware.signature <- rule_name
    assert mal.raw.get("FileName")             # Malware.file_name <- raw:[…, FileName, …]
    assert mal.raw.get("SHA256")               # Malware.file_hash <- raw:[Hashes, SHA256, …]
    assert mal.host_name                       # Malware.dest      <- host_name
    transfer = events["file-transfer"]
    assert transfer.raw.get("FileName")        # Network members still project these
    assert transfer.host_name and transfer.user_name

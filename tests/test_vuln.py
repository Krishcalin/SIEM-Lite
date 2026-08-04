# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the vulnerability-management sources: the Qualys / Tenable /
Rapid7 parsers, their collectors, and the CIM Vulnerability model they populate.

DB-free and network-free throughout: every URL, body, header and response shaper
is a pure function called with a fixture string, and the one thin network method
is instance-patched.
"""
import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest

import app.collectors.runner as runner
import app.collectors.vuln as vuln
from app.cim import match
from app.collectors.vuln import (QualysDetectionCollector, Rapid7InsightVmCollector,
                                 TenableVulnExportCollector, basic_auth, make_cursor,
                                 parse_cursor, qualys_headers, qualys_detection_count,
                                 qualys_detection_url, qualys_next_url, qualys_time,
                                 r7_asset_vulns_url, r7_join, r7_page, r7_search_body,
                                 r7_search_url, r7_vuln_url, tenable_chunk_url,
                                 tenable_export_body, tenable_export_status,
                                 tenable_export_uuid, tenable_headers,
                                 tenable_status_url)
from app.parsers import qualys, rapid7, tenable
from app.severity import SEVERITY_ORDER

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def sample(name: str) -> str:
    """The shipped fixture, wherever it currently lives.

    The three scanner samples are STAGED under `samples/pending/` so that
    tests/test_cim.py's `corpus()` — which enumerates `samples/` and skips
    directories — stays green until the wire phase registers the parsers and
    teaches `app/detect.py` to route them. Dropping them straight into `samples/`
    would fail `corpus()`'s `fmt in PARSERS` assertion and take every other
    agent's suite down with it. Looking in both places means moving them up one
    level costs no edit here.
    """
    for path in (SAMPLES / name, SAMPLES / "pending" / name):
        if path.exists():
            return path.read_text(encoding="utf-8")
    raise AssertionError(f"sample fixture {name!r} not found under {SAMPLES}")


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
#  CVSS -> the repo's severity vocabulary                                      #
# --------------------------------------------------------------------------- #
#: (score, expected) over every NVD band boundary, including both sides of each.
_BANDS = [
    (0, "informational"), (0.0, "informational"),
    (0.1, "low"), (3.9, "low"),
    (4.0, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"),
    (9.0, "critical"), (10, "critical"), (10.0, "critical"),
]


def test_cvss_severity_maps_the_nvd_bands():
    for score, expected in _BANDS:
        assert qualys.cvss_severity(score) == expected, score
    # never invents a level outside the repo's own vocabulary
    assert {name for _, name in _BANDS} <= set(SEVERITY_ORDER)


def test_cvss_severity_rejects_what_is_not_a_score():
    """None means "no CVSS" so the caller falls back to the vendor's own rating —
    it must never be confused with 0.0, which means "no impact"."""
    for bad in (None, "", "n/a", "none", "critical", float("nan"), float("inf"),
                10.1, 11, -0.1, {}, []):
        assert qualys.cvss_severity(bad) is None, bad
    assert qualys.cvss_severity(0.0) == "informational"


def test_cvss_severity_accepts_a_score_glued_to_its_vector():
    """Qualys ships `CVSS3_BASE` as "8.8 (AV:N/AC:L/...)"."""
    assert qualys.cvss_severity("8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)") == "high"
    assert qualys.cvss_severity(" 9.8 ") == "critical"


def test_the_three_scanner_parsers_agree_on_every_cvss_score():
    """The mapping is duplicated per parser on purpose (the repo already duplicates
    `_SEVERITY` across four syslog parsers). This is the guard that keeps the three
    copies from drifting apart silently."""
    probes = [s for s, _ in _BANDS] + [None, "", "7.5 (AV:N)", 10.1, -1, "nan", 2.5, 6.99]
    for probe in probes:
        got = (qualys.cvss_severity(probe), tenable.cvss_severity(probe),
               rapid7.cvss_severity(probe))
        assert got[0] == got[1] == got[2], (probe, got)


# --------------------------------------------------------------------------- #
#  CVE flattening — jsonb lookups are byte-exact and cannot index an array      #
# --------------------------------------------------------------------------- #
def test_cve_scalars_flattens_dedupes_and_upper_cases():
    joined, one = tenable.cve_scalars(["CVE-2021-44228", "cve-2021-45046"], None,
                                      "CVE-2021-44228")
    assert joined == "CVE-2021-44228,CVE-2021-45046"   # complete list wins the CIM field
    assert one == "CVE-2021-44228"                     # clean single value for equality
    assert tenable.cve_scalars([], None, "no cve here") == (None, None)
    # containers and non-CVE text are ignored, embedded ids are recovered
    assert tenable.cve_scalars({"cve": "CVE-2000-1111"}, "msft-cve-2021-34527") == \
        ("CVE-2021-34527", "CVE-2021-34527")


# --------------------------------------------------------------------------- #
#  Qualys parser — Host List Detection XML                                     #
# --------------------------------------------------------------------------- #
_QUALYS_BARE = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST>
  <ID>84213377</ID><IP>10.20.30.41</IP>
  <DNS><![CDATA[db01.corp.example.com]]></DNS><NETBIOS><![CDATA[DB01]]></NETBIOS>
  <LAST_SCAN_DATETIME>2026-06-25T08:55:00Z</LAST_SCAN_DATETIME>
  <DETECTION_LIST><DETECTION>
    <QID>150323</QID><TYPE>Confirmed</TYPE><SEVERITY>5</SEVERITY>
    <PORT>8080</PORT><PROTOCOL>tcp</PROTOCOL><STATUS>Active</STATUS>
    <LAST_FOUND_DATETIME>2026-06-25T08:55:00Z</LAST_FOUND_DATETIME>
  </DETECTION></DETECTION_LIST>
</HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""

_QUALYS_ENRICHED = """<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST><HOST>
  <ID>84213402</ID><IP>10.20.30.52</IP>
  <DNS><![CDATA[web02.corp.example.com]]></DNS>
  <DETECTION_LIST><DETECTION>
    <QID>91785</QID><SEVERITY>3</SEVERITY><PORT>445</PORT><PROTOCOL>TCP</PROTOCOL>
    <STATUS>Re-Opened</STATUS>
    <VULN_TITLE><![CDATA[Windows Print Spooler RCE (PrintNightmare)]]></VULN_TITLE>
    <CATEGORY>Windows</CATEGORY>
    <CVSS3_BASE>8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)</CVSS3_BASE>
    <CVE_LIST><CVE><ID><![CDATA[CVE-2021-34527]]></ID>
      <URL><![CDATA[https://example.invalid/CVE-2021-34527]]></URL></CVE></CVE_LIST>
    <LAST_FOUND_DATETIME>2026-06-25T08:58:00Z</LAST_FOUND_DATETIME>
  </DETECTION></DETECTION_LIST>
</HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"""


def test_qualys_emits_one_event_per_host_detection_pair():
    events = list(qualys.parse(sample("qualys_detection.xml")))
    assert len(events) == 3                       # 2 detections on host A + 1 on host B
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("qualys", "vmdr", "vulnerability")
    assert e.host_name == "db01.corp.example.com"   # DNS name beats NetBIOS and IP
    assert e.dst_ip == "10.20.30.41"
    assert (e.dst_port, e.protocol) == (8080, "tcp")
    assert e.event_time == _utc("2026-06-25T08:55:00")
    # the host block is flattened onto every one of its detections
    assert e.raw["host_id"] == "84213377" and e.raw["qid"] == "150323"


def test_qualys_falls_back_to_the_qid_and_the_vendor_severity():
    """The bare detection API carries no CVE and no title — that is a property of
    the endpoint, so the parser must degrade to QID + Qualys' 1-5 scale rather than
    invent either."""
    e = list(qualys.parse(_QUALYS_BARE))[0]
    assert e.rule_name == "QID 150323"
    assert e.severity == "critical"               # SEVERITY 5 = urgent
    assert e.action == "open"                     # STATUS "Active"
    assert "cve" not in e.raw and "cve_id" not in e.raw


def test_qualys_lifts_cve_title_and_cvss_when_the_export_is_kb_enriched():
    e = list(qualys.parse(_QUALYS_ENRICHED))[0]
    assert e.rule_name == "Windows Print Spooler RCE (PrintNightmare)"
    assert e.raw["cve"] == "CVE-2021-34527" and e.raw["cve_id"] == "CVE-2021-34527"
    assert e.raw["category"] == "Windows"
    assert e.raw["cvss"] == 8.8                   # the NUMBER, not the vector string
    # CVSS FIRST, vendor rating second: the fixture disagrees on purpose — Qualys
    # severity 3 would be `medium`, CVSS 8.8 is `high`. The CVSS base score is the
    # only rating that means the same thing across all three scanners, which is
    # what makes a cross-vendor `severity=high` search honest.
    assert e.severity == "high"
    assert e.action == "reopened"
    assert e.protocol == "tcp"                    # lower-cased


def test_qualys_reads_cves_only_out_of_cve_named_tags():
    """A CVE quoted in a RESULTS proof blob is evidence, not the finding's own id."""
    doc = _QUALYS_BARE.replace(
        "<STATUS>Active</STATUS>",
        "<STATUS>Active</STATUS><RESULTS><![CDATA[looks like CVE-1999-0001]]></RESULTS>")
    e = list(qualys.parse(doc))[0]
    assert "cve" not in e.raw
    assert "CVE-1999-0001" in e.raw["results"]    # still searchable, just not the id


def test_qualys_rejects_a_document_that_declares_entities():
    """ElementTree expands internal entities ("billion laughs" / quadratic blowup).
    Both attacks need a DTD internal subset, so a prolog declaration is fatal."""
    hostile = _QUALYS_BARE.replace(
        '<?xml version="1.0" encoding="UTF-8" ?>',
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT [<!ENTITY boom "EXPANDED">]>'
    ).replace("<![CDATA[db01.corp.example.com]]>", "&boom;")
    assert list(qualys.parse(hostile)) == []
    assert qualys._has_declaration(hostile) is True


def test_qualys_keeps_a_doctype_inside_the_body_from_killing_the_document():
    """The guard walks the PROLOG only. Qualys RESULTS sections are CDATA and
    legitimately contain captured HTML, doctype and all — a blanket substring test
    would silently drop the whole page."""
    doc = _QUALYS_BARE.replace(
        "<STATUS>Active</STATUS>",
        "<STATUS>Active</STATUS><RESULTS><![CDATA[<!DOCTYPE html><html>hi</html>]]></RESULTS>")
    assert qualys._has_declaration(doc) is False
    events = list(qualys.parse(doc))
    assert len(events) == 1 and events[0].raw["qid"] == "150323"


def test_qualys_parses_the_concatenated_pages_of_a_truncated_response():
    """A truncated Qualys response is continued at `<WARNING><URL>`, so the
    collector hands the parser several complete documents back to back."""
    events = list(qualys.parse(_QUALYS_BARE + "\n" + _QUALYS_ENRICHED))
    assert [e.raw["qid"] for e in events] == ["150323", "91785"]


def test_qualys_never_raises_on_garbage():
    for junk in ("", "   ", "not xml at all", "<HOST><ID>1</ID>", "<?xml ?><a></a>"):
        assert list(qualys.parse(junk)) == []


# --------------------------------------------------------------------------- #
#  Tenable parser — vulns/export chunk                                         #
# --------------------------------------------------------------------------- #
def test_tenable_flattens_an_export_finding_onto_the_common_event():
    events = list(tenable.parse(sample("tenable_vulns.json")))
    assert len(events) == 3
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("tenable", "tenable_io", "vulnerability")
    assert e.severity == "critical"                          # cvss3 10.0
    assert e.action == "open"
    assert e.host_name == "db01.corp.example.com"
    assert e.dst_ip == "10.20.30.41"
    assert e.rule_name.startswith("Apache Log4j")
    assert e.event_time == _utc("2026-06-25T09:02:11")       # last_found, not indexed
    assert events[1].action == "reopened" and events[1].severity == "medium"


def test_tenable_writes_cve_and_family_back_as_top_level_scalars():
    """CIM jsonb lookups are byte-exact and descend objects only — `plugin.cve` is
    an ARRAY, so the model could never read it. This is the windows_security.py
    `event_id` precedent applied to CVE."""
    e = list(tenable.parse(sample("tenable_vulns.json")))[0]
    assert isinstance(e.raw["plugin"]["cve"], list)          # the unreachable original
    assert e.raw["cve"] == "CVE-2021-44228,CVE-2021-45046"   # the reachable scalar
    assert e.raw["cve_id"] == "CVE-2021-44228"
    assert e.raw["category"] == e.raw["plugin_family"] == "Misc."
    assert e.raw["cvss"] == 10.0 and e.raw["cvss_version"] == "3.0"


def test_tenable_port_zero_means_no_port():
    """Tenable reports port 0 for a local/agent plugin. Storing 0 would make every
    such finding look like a real service on port zero."""
    events = list(tenable.parse(sample("tenable_vulns.json")))
    assert events[0].raw["port"]["port"] == 0 and events[0].dst_port is None
    assert events[1].dst_port == 443


def test_tenable_falls_back_to_its_own_rating_without_a_score():
    body = json.dumps([{"asset": {"hostname": "host9"}, "severity": "info",
                        "state": "FIXED", "last_found": "2026-06-25T09:00:00Z",
                        "plugin": {"name": "Compliance check", "id": 1}}])
    e = list(tenable.parse(body))[0]
    assert e.severity == "informational"     # "info" is normalized into the vocabulary
    assert e.action == "fixed"
    assert e.severity in SEVERITY_ORDER


# --------------------------------------------------------------------------- #
#  Rapid7 parser — the asset x finding x catalog join                          #
# --------------------------------------------------------------------------- #
def test_rapid7_flattens_the_three_way_join_envelope():
    events = list(rapid7.parse(sample("rapid7_insightvm.json")))
    assert len(events) == 3
    e = events[0]
    assert (e.vendor, e.product, e.log_type) == ("rapid7", "insightvm", "vulnerability")
    assert e.host_name == "app01.corp.example.com" and e.dst_ip == "10.20.30.42"
    assert (e.dst_port, e.protocol) == (443, "tcp")
    assert e.rule_name.startswith("Apache HTTPD")
    assert e.action == "open"                                 # status "vulnerable"
    assert e.raw["category"] == "Apache, Web"
    assert events[1].action == "open"                         # "vulnerable-version"


def test_rapid7_prefers_the_cvss_v3_score_over_v2():
    """v2 7.5 and v3 9.8 disagree across a band boundary; taking v2 would under-rate
    the finding as `high`."""
    e = list(rapid7.parse(sample("rapid7_insightvm.json")))[0]
    assert e.raw["cvss"] == 9.8 and e.severity == "critical"
    assert list(rapid7.parse(sample("rapid7_insightvm.json")))[1].raw["cvss"] == 4.3


def test_rapid7_recovers_the_cve_from_the_id_when_the_catalog_entry_is_missing():
    """The catalog lookup is budgeted and can 404, so the finding must still carry a
    CVE — InsightVM names a large share of its checks `<product>-cve-YYYY-NNNNN`."""
    e = list(rapid7.parse(sample("rapid7_insightvm.json")))[2]
    assert e.raw["vulnerability"] == {}                # catalog miss, honestly recorded
    assert e.raw["cve"] == "CVE-2021-34527"
    assert e.rule_name == "msft-cve-2021-34527"        # the id stands in for the title
    assert e.severity is None                          # and severity is genuinely absent


def test_rapid7_falls_back_to_the_vendor_rating_when_there_is_no_cvss():
    body = json.dumps([{"asset": {"ip": "10.0.0.9"},
                        "finding": {"id": "x", "status": "potential"},
                        "vulnerability": {"id": "x", "title": "T", "severity": "Severe"}}])
    e = list(rapid7.parse(body))[0]
    assert e.severity == "high"        # InsightVM "Severe" is not the repo's "severe"
    assert e.action == "potential"


# --------------------------------------------------------------------------- #
#  The CIM Vulnerability model — empty by design until exactly these sources    #
# --------------------------------------------------------------------------- #
def _all_scanner_events():
    return (list(qualys.parse(sample("qualys_detection.xml")))
            + list(tenable.parse(sample("tenable_vulns.json")))
            + list(rapid7.parse(sample("rapid7_insightvm.json"))))


def test_every_scanner_event_lands_in_the_vulnerability_model_and_nowhere_else():
    """The model's single clause ANDs a scanner vendor with a scanner log_type.
    `== ["vulnerability"]` (not `in`) is the real assertion: a scanner finding that
    also tagged `ids` or `network` would corrupt those models."""
    events = _all_scanner_events()
    assert len(events) == 9
    for e in events:
        assert match.tags_for(e) == ["vulnerability"], (e.vendor, e.rule_name)


def test_the_vendor_and_log_type_pair_is_what_the_membership_clause_matches():
    vendors = {e.vendor for e in _all_scanner_events()}
    assert vendors == {"qualys", "tenable", "rapid7"}
    assert vendors <= {"qualys", "tenable", "rapid7", "nessus", "openvas", "nexpose"}
    assert {e.log_type for e in _all_scanner_events()} == {"vulnerability"}


def test_the_vulnerability_model_fields_project_from_what_the_parsers_emit():
    """models.yaml honesty rule 4: on a POPULATED model, a field no member can
    provide is deleted rather than shipped null-by-construction. Every field below
    is provided by at least one member; `user` is the one that is not — scanner
    findings have no acting account — and is reported for removal in the handoff.
    """
    events = _all_scanner_events()
    assert any(e.rule_name for e in events)                       # signature
    assert any(e.raw.get("cve") or e.raw.get("cve_id") for e in events)   # cve
    assert any(e.severity for e in events)                        # severity
    assert all(e.severity in SEVERITY_ORDER for e in events if e.severity)
    assert any(e.host_name for e in events)                       # dest / dvc
    assert any(e.raw.get("category") or e.raw.get("plugin_family") for e in events)
    assert all(e.vendor and e.product for e in events)            # vendor_product
    # the null-by-construction one, asserted so it cannot quietly start passing
    assert not any(e.user_name for e in events)                   # user


def test_the_cve_field_reads_a_scalar_not_a_container():
    """`match._text` returns None for any dict/list, so a CVE left inside its array
    is unreachable no matter how the field is declared."""
    for e in _all_scanner_events():
        for key in ("cve", "cve_id", "category", "plugin_family"):
            assert not isinstance(e.raw.get(key), (dict, list, tuple))


# --------------------------------------------------------------------------- #
#  Qualys collector — pure functions                                           #
# --------------------------------------------------------------------------- #
def test_basic_auth_matches_the_rfc_encoding():
    assert basic_auth("scanuser", "s3cr3t") == "Basic c2NhbnVzZXI6czNjcjN0"


def test_qualys_headers_carry_basic_auth_and_the_csrf_guard():
    h = qualys_headers("u", "p")
    assert h["Authorization"].startswith("Basic ")
    assert h["X-Requested-With"] == "LogOcean"      # Qualys 403s without it


def test_qualys_time_normalizes_both_cursor_shapes():
    """Cursors are MIXED-FORMAT in one column: `iso_lookback` emits a fractional
    `Z` form, `max_time_iso` emits a `+00:00` offset. Qualys accepts neither."""
    assert qualys_time("2026-06-25T11:30:00.000Z") == "2026-06-25T11:30:00Z"
    assert qualys_time("2026-06-25T11:30:00+00:00") == "2026-06-25T11:30:00Z"
    assert qualys_time("2026-06-25T17:00:00+05:30") == "2026-06-25T11:30:00Z"


def test_qualys_detection_url_escapes_the_watermark_in_the_query_string():
    for cursor in ("2026-06-25T11:30:00.000Z", "2026-06-25T11:30:00+00:00"):
        url = qualys_detection_url("https://qualysapi.example.com/", cursor)
        assert url.startswith(
            "https://qualysapi.example.com/api/2.0/fo/asset/host/vm/detection/?")
        assert "detection_updated_since=2026-06-25T11%3A30%3A00Z" in url
        assert "+" not in url          # an unescaped `+` decodes as a space
        assert "truncation_limit=1000" in url and "action=list" in url


def test_qualys_next_url_reads_the_truncation_warning():
    body = ('<RESPONSE><WARNING><CODE>1980</CODE><TEXT>truncated</TEXT>'
            '<URL><![CDATA[https://q.example.com/api?a=1&amp;b=2]]></URL>'
            '</WARNING></RESPONSE>')
    assert qualys_next_url(body) == "https://q.example.com/api?a=1&b=2"
    assert qualys_next_url("<RESPONSE><HOST_LIST/></RESPONSE>") is None
    assert qualys_next_url("") is None


def test_qualys_detection_count_reads_the_page_without_parsing_it():
    assert qualys_detection_count(_QUALYS_BARE) == 1
    assert qualys_detection_count(_QUALYS_BARE + _QUALYS_ENRICHED) == 2
    assert qualys_detection_count("<HOST_LIST/>") == 0


def _freeze(monkeypatch, when: datetime):
    monkeypatch.setattr(vuln, "_now", lambda: when)


def test_qualys_fetch_walks_the_continuation_pages(monkeypatch):
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24)
    # Qualys carries the continuation link INSIDE <RESPONSE>, after </HOST_LIST>
    page1 = _QUALYS_BARE.replace(
        "</HOST_LIST></RESPONSE>",
        "</HOST_LIST><WARNING><CODE>1980</CODE>"
        "<URL>https://q.example.com/next</URL></WARNING></RESPONSE>")
    # exhaustible: an over-fetch raises StopIteration rather than looping silently
    pages = iter([page1, _QUALYS_ENRICHED])
    seen = []

    def _get(url, headers):
        seen.append(url)
        return next(pages)

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch(None)
    assert seen[1] == "https://q.example.com/next"        # followed the WARNING link
    assert res.count == 2
    assert [e.raw["qid"] for e in qualys.parse(res.content)] == ["150323", "91785"]
    assert parse_cursor(res.cursor) == {"since": "2026-06-25T12:00:00Z"}  # window END


def test_qualys_fetch_returns_empty_content_when_nothing_changed(monkeypatch):
    """`run_collector` gates ingest on `content.strip()`. Returning the empty
    envelope instead of "" would re-ingest identical bytes every poll and pile up
    zero-row `already_ingested` batches."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24)
    empty = ('<?xml version="1.0" ?><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE>'
             '<HOST_LIST/></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>')
    monkeypatch.setattr(c, "_http_get", lambda url, headers: empty)
    res = c.fetch("2026-06-25T09:00:00Z")
    assert res.content == "" and res.count == 0
    assert parse_cursor(res.cursor) == {"since": "2026-06-25T12:00:00Z"}  # window moves


def test_qualys_parks_the_continuation_link_when_the_page_budget_runs_out(monkeypatch):
    """A first backfill can exceed `_MAX_PAGES` of 1000 detections. Capping the walk
    and advancing the watermark anyway would drop the remainder SILENTLY and
    forever, while still reporting last_status='ok'."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    monkeypatch.setattr(vuln, "_MAX_PAGES", 2)
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24)
    truncated = _QUALYS_BARE.replace(
        "</HOST_LIST></RESPONSE>",
        "</HOST_LIST><WARNING><URL>https://q.example.com/p{n}</URL></WARNING></RESPONSE>")
    seen = []

    def _get(url, headers):
        seen.append(url)
        return truncated.replace("{n}", str(len(seen)))

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch("2026-06-25T09:00:00Z")
    assert len(seen) == 2 and res.count == 2          # stopped at the budget
    parked = parse_cursor(res.cursor)
    assert parked["next"] == "https://q.example.com/p2"    # resume pointer kept
    assert parked["since"] == "2026-06-25T09:00:00Z"       # watermark HELD BACK
    assert parked["until"] == "2026-06-25T12:00:00Z"       # window end pinned


def test_qualys_resumes_a_parked_walk_ignoring_the_cadence_floor(monkeypatch):
    """A resuming tick must not re-request the window from the start, must not wait
    out `min_interval_seconds` (a backfill would never finish), and must adopt the
    window end that was pinned when the walk began — re-reading the clock would step
    the watermark past detections updated while we were still paging."""
    now = _utc("2026-06-25T12:05:00")
    _freeze(monkeypatch, now)
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24,
                                 min_interval_seconds=86400)
    c._last_pull = _utc("2026-06-25T12:00:00")            # nowhere near due
    seen = []

    def _get(url, headers):
        seen.append(url)
        return _QUALYS_ENRICHED                            # no WARNING -> last page

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch(make_cursor(since="2026-06-25T09:00:00Z", until="2026-06-25T12:00:00Z",
                              next="https://q.example.com/p2"))
    assert seen == ["https://q.example.com/p2"]           # resumed, not restarted
    assert res.count == 1
    # walk complete -> the watermark finally moves, to the PINNED end not to `now`
    assert parse_cursor(res.cursor) == {"since": "2026-06-25T12:00:00Z"}


# --------------------------------------------------------------------------- #
#  Tenable collector — the asynchronous export, resumed across scheduler ticks  #
# --------------------------------------------------------------------------- #
def test_tenable_headers_and_urls():
    assert tenable_headers("AK", "SK")["X-ApiKeys"] == "accessKey=AK;secretKey=SK"
    assert tenable_status_url("https://cloud.tenable.com", "U") == \
        "https://cloud.tenable.com/vulns/export/U/status"
    assert tenable_chunk_url("https://cloud.tenable.com/", "U", 3) == \
        "https://cloud.tenable.com/vulns/export/U/chunks/3"


def test_tenable_export_body_uses_epoch_seconds():
    """`filters.since` is epoch seconds; sending the ISO cursor would be rejected."""
    body = json.loads(tenable_export_body(1782000000, num_assets=250))
    assert body["filters"]["since"] == 1782000000
    assert body["num_assets"] == 250
    assert body["filters"]["state"] == ["OPEN", "REOPENED", "FIXED"]


def test_tenable_export_uuid_and_status_unwrap():
    assert tenable_export_uuid('{"export_uuid":"abc"}') == "abc"
    assert tenable_export_uuid('{"error":"nope"}') is None
    assert tenable_export_uuid("not json") is None
    assert tenable_export_status('{"status":"finished","chunks_available":[2,"1"]}') == \
        ("FINISHED", [1, 2])
    assert tenable_export_status('{"status":"PROCESSING"}') == ("PROCESSING", [])
    assert tenable_export_status("garbage") == ("", [])


def test_the_cursor_codec_round_trips_and_accepts_a_bare_iso():
    """One opaque text column carries the watermark AND the resume state, so a
    walk that spans several scheduler ticks knows where it stopped."""
    text = make_cursor(since="2026-06-25T09:00:00Z", export="UUID",
                       requested="2026-06-25T12:00:00Z", done=[1, 2])
    assert parse_cursor(text) == {"since": "2026-06-25T09:00:00Z", "export": "UUID",
                                  "requested": "2026-06-25T12:00:00Z", "done": [1, 2]}
    # empty members are dropped so an idle cursor stays short
    assert make_cursor(since="X", export=None, done=[]) == '{"since": "X"}'
    # a watermark written before this codec existed still decodes
    assert parse_cursor("2026-06-25T09:00:00Z") == {"since": "2026-06-25T09:00:00Z"}
    # unparseable decodes to "start over" rather than raising inside the scheduler
    assert parse_cursor(None) == {} and parse_cursor("{bad json") == {}
    # NEVER None: run_collector writes `cursor=result.cursor` unconditionally, so a
    # None here would write SQL NULL and replay the whole lookback window.
    assert isinstance(make_cursor(), str)


def _tenable(monkeypatch, now, **kw):
    _freeze(monkeypatch, now)
    return TenableVulnExportCollector("AK", "SK", 24, **kw)


_CHUNK = json.dumps([{"asset": {"hostname": "h1", "ipv4": "10.0.0.1"},
                      "plugin": {"id": 1, "name": "P1", "cve": ["CVE-2021-1234"],
                                 "cvss3_base_score": 9.5, "family": "Windows"},
                      "port": {"port": 445, "protocol": "TCP"},
                      "severity": "critical", "state": "OPEN",
                      "last_found": "2026-06-25T10:00:00Z"}])


def test_tenable_first_tick_only_queues_the_export(monkeypatch):
    """POST /vulns/export QUEUES a job; blocking here would hold the shared,
    serial scheduler thread for minutes. The uuid is parked in the cursor instead."""
    now = _utc("2026-06-25T12:00:00")
    c = _tenable(monkeypatch, now)
    posted = {}

    def _post(url, headers, data):
        posted["url"], posted["body"] = url, json.loads(data.decode())
        return '{"export_uuid":"EXP-1"}'

    monkeypatch.setattr(c, "_http_post", _post)
    monkeypatch.setattr(c, "_http_get", lambda url, headers: pytest.fail("polled too early"))
    res = c.fetch("2026-06-25T09:00:00Z")
    assert posted["url"].endswith("/vulns/export")
    assert posted["body"]["filters"]["since"] == int(_utc("2026-06-25T09:00:00").timestamp())
    assert res.content == "" and res.count == 0
    state = parse_cursor(res.cursor)
    assert state.get("export") == "EXP-1" and state.get("done", []) == []
    assert state.get("since") == "2026-06-25T09:00:00Z"       # watermark NOT advanced yet


def test_tenable_a_later_tick_downloads_the_chunks_and_advances_to_the_request_time(monkeypatch):
    now = _utc("2026-06-25T12:05:00")
    c = _tenable(monkeypatch, now)
    cursor = make_cursor(since="2026-06-25T09:00:00Z", export="EXP-1", requested="2026-06-25T12:00:00Z")

    def _get(url, headers):
        if url.endswith("/status"):
            return '{"status":"FINISHED","chunks_available":[1]}'
        assert url.endswith("/chunks/1")
        return _CHUNK

    monkeypatch.setattr(c, "_http_get", _get)
    monkeypatch.setattr(c, "_http_post", lambda *a: pytest.fail("re-queued a live export"))
    res = c.fetch(cursor)
    assert res.count == 1
    assert list(tenable.parse(res.content))[0].rule_name == "P1"
    state = parse_cursor(res.cursor)
    # the export covered everything up to when it was REQUESTED — that is the mark
    assert state.get("since") == "2026-06-25T12:00:00Z" and state.get("export") is None


def test_tenable_keeps_the_export_in_flight_when_only_some_chunks_fit(monkeypatch):
    """Chunk-level resumability: the watermark may not move until every chunk that
    export produced has been ingested, or the unread ones are lost forever."""
    now = _utc("2026-06-25T12:05:00")
    c = _tenable(monkeypatch, now, max_chunks=1)
    cursor = make_cursor(since="2026-06-25T09:00:00Z", export="EXP-1", requested="2026-06-25T12:00:00Z")
    monkeypatch.setattr(c, "_http_get", lambda url, headers: (
        '{"status":"FINISHED","chunks_available":[1,2]}' if url.endswith("/status") else _CHUNK))
    res = c.fetch(cursor)
    state = parse_cursor(res.cursor)
    assert res.count == 1
    assert state.get("export") == "EXP-1" and state.get("done", []) == [1]
    assert state.get("since") == "2026-06-25T09:00:00Z"       # still not advanced


def test_tenable_a_still_processing_export_costs_nothing(monkeypatch):
    now = _utc("2026-06-25T12:01:00")
    c = _tenable(monkeypatch, now)
    cursor = make_cursor(since="2026-06-25T09:00:00Z", export="EXP-1", requested="2026-06-25T12:00:00Z")
    monkeypatch.setattr(c, "_http_get", lambda url, headers:
                        '{"status":"PROCESSING","chunks_available":[]}')
    res = c.fetch(cursor)
    assert res.content == "" and res.count == 0
    assert parse_cursor(res.cursor) == parse_cursor(cursor)


def test_tenable_a_failed_export_is_dropped_without_advancing_the_watermark(monkeypatch):
    now = _utc("2026-06-25T12:05:00")
    c = _tenable(monkeypatch, now)
    cursor = make_cursor(since="2026-06-25T09:00:00Z", export="EXP-1", requested="2026-06-25T12:00:00Z")
    monkeypatch.setattr(c, "_http_get", lambda url, headers: '{"status":"ERROR"}')
    res = c.fetch(cursor)
    state = parse_cursor(res.cursor)
    assert state.get("export") is None                        # dead job released
    assert state.get("since") == "2026-06-25T09:00:00Z"       # identical window retried


def test_tenable_abandons_an_export_that_never_finished(monkeypatch):
    """A job Tenable silently dropped would otherwise wedge the collector at one
    window forever, reporting last_status='ok' on every poll."""
    now = _utc("2026-06-26T12:00:00")                     # 24h after the request
    c = _tenable(monkeypatch, now)
    cursor = make_cursor(since="2026-06-25T09:00:00Z", export="STALE", requested="2026-06-25T12:00:00Z", done=[1])
    monkeypatch.setattr(c, "_http_post", lambda url, headers, data: '{"export_uuid":"EXP-2"}')
    monkeypatch.setattr(c, "_http_get", lambda url, headers: pytest.fail("polled a stale export"))
    state = parse_cursor(c.fetch(cursor).cursor)
    assert state.get("export") == "EXP-2" and state.get("done", []) == []
    assert state.get("since") == "2026-06-25T09:00:00Z"


# --------------------------------------------------------------------------- #
#  Rapid7 collector — the three-way join                                       #
# --------------------------------------------------------------------------- #
def test_r7_search_body_floors_the_watermark_to_a_date():
    """InsightVM's `last-scan-date` filter takes a DATE, so the window is
    deliberately wider than the cursor; dedup absorbs the overlap."""
    body = json.loads(r7_search_body("2026-06-25T11:30:00+00:00"))
    assert body["filters"][0] == {"field": "last-scan-date",
                                  "operator": "is-on-or-after", "value": "2026-06-25"}
    assert json.loads(r7_search_body("2026-06-25T00:00:00.000Z"))["filters"][0]["value"] \
        == "2026-06-25"


def test_r7_urls():
    # the sort is load-bearing, not cosmetic: the walk parks a PAGE NUMBER between
    # ticks, and a page number only means anything over a stable ordering
    assert r7_search_url("https://c:3780/", 2, 500) == \
        "https://c:3780/api/3/assets/search?page=2&size=500&sort=id%2Casc"
    assert r7_asset_vulns_url("https://c:3780", 282, 0, 500) == \
        "https://c:3780/api/3/assets/282/vulnerabilities?page=0&size=500"
    assert r7_vuln_url("https://c:3780", "msft-cve-2021-34527") == \
        "https://c:3780/api/3/vulnerabilities/msft-cve-2021-34527"


def test_r7_page_unwraps_resources_and_total_pages():
    assert r7_page('{"resources":[{"id":1},"junk"],"page":{"totalPages":3}}') == \
        ([{"id": 1}], 3)
    assert r7_page('{"resources":[]}') == ([], 1)          # absent totalPages -> one page
    assert r7_page("nope") == ([], 1)


def test_r7_join_is_the_envelope_the_parser_reads():
    env = r7_join({"id": 1}, {"id": "v"}, {"title": "T"})
    assert set(env) == {"asset", "finding", "vulnerability"}


def _r7_router(pages, findings, catalog, calls):
    def _get(url, headers):
        calls.append(url)
        if "/vulnerabilities/" in url and "/assets/" not in url:
            return json.dumps(catalog[url.rsplit("/", 1)[1]])
        return json.dumps({"resources": findings[url.split("/assets/")[1].split("/")[0]],
                           "page": {"totalPages": 1}})

    def _post(url, headers, data):
        calls.append(url)
        return pages.pop(0)

    return _get, _post


def test_rapid7_fetch_joins_asset_finding_and_catalog(monkeypatch):
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24)
    calls = []
    pages = [json.dumps({"resources": [{"id": 282, "ip": "10.0.0.1",
                                        "hostName": "app01"}],
                         "page": {"totalPages": 1}})]
    findings = {"282": [{"id": "apache-cve-2021-41773", "status": "vulnerable",
                         "since": "2026-06-20T00:00:00Z",
                         "results": [{"port": 443, "protocol": "tcp"}]}]}
    catalog = {"apache-cve-2021-41773": {"id": "apache-cve-2021-41773", "title": "Apache RCE",
                                         "severity": "Critical",
                                         "cvss": {"v3": {"score": 9.8}},
                                         "categories": ["Apache"],
                                         "cves": ["CVE-2021-41773"]}}
    get, post = _r7_router(pages, findings, catalog, calls)
    monkeypatch.setattr(c, "_http_get", get)
    monkeypatch.setattr(c, "_http_post", post)

    res = c.fetch(None)
    assert res.count == 1
    e = list(rapid7.parse(res.content))[0]
    assert e.host_name == "app01" and e.severity == "critical"
    assert e.raw["cve"] == "CVE-2021-41773" and e.rule_name == "Apache RCE"
    assert parse_cursor(res.cursor) == {"since": now.isoformat()}


def test_rapid7_caches_catalog_entries_across_polls(monkeypatch):
    """Collectors are built once at startup, so the id -> catalog join warms up and
    steady state costs roughly one request per asset instead of one per finding."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24, min_interval_seconds=0)
    calls = []
    asset_page = json.dumps({"resources": [{"id": 1, "ip": "10.0.0.1"}],
                             "page": {"totalPages": 1}})
    findings = {"1": [{"id": "v1", "status": "vulnerable"},
                      {"id": "v1", "status": "vulnerable"}]}
    catalog = {"v1": {"id": "v1", "title": "T", "severity": "Severe"}}
    get, post = _r7_router([asset_page, asset_page], findings, catalog, calls)
    monkeypatch.setattr(c, "_http_get", get)
    monkeypatch.setattr(c, "_http_post", post)

    assert c.fetch(None).count == 2
    lookups = [u for u in calls if u.endswith("/vulnerabilities/v1")]
    assert len(lookups) == 1                      # deduped within the run
    c.fetch(None)
    assert len([u for u in calls if u.endswith("/vulnerabilities/v1")]) == 1  # and across


def test_rapid7_a_404_catalog_entry_does_not_wedge_the_collector(monkeypatch):
    """A 404 means the console reported a check its catalog no longer has. Any OTHER
    status must propagate — the cursor may not advance past a window we could not read."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24)
    asset_page = json.dumps({"resources": [{"id": 1, "ip": "10.0.0.1"}],
                             "page": {"totalPages": 1}})

    def _get(url, headers, code=404):
        if url.endswith("/vulnerabilities/msft-cve-2021-34527"):
            raise HTTPError(url, code, "gone", {}, None)
        return json.dumps({"resources": [{"id": "msft-cve-2021-34527",
                                          "status": "vulnerable"}],
                           "page": {"totalPages": 1}})

    monkeypatch.setattr(c, "_http_get", _get)
    monkeypatch.setattr(c, "_http_post", lambda url, headers, data: asset_page)
    res = c.fetch(None)
    assert res.count == 1
    assert list(rapid7.parse(res.content))[0].raw["cve"] == "CVE-2021-34527"

    c2 = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24)
    monkeypatch.setattr(c2, "_http_get", lambda url, h: _get(url, h, code=500))
    monkeypatch.setattr(c2, "_http_post", lambda url, headers, data: asset_page)
    with pytest.raises(HTTPError):
        c2.fetch(None)


def test_rapid7_returns_empty_content_when_no_asset_was_scanned(monkeypatch):
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24)
    monkeypatch.setattr(c, "_http_post", lambda url, headers, data:
                        '{"resources":[],"page":{"totalPages":1}}')
    monkeypatch.setattr(c, "_http_get", lambda url, headers: pytest.fail("walked no assets"))
    res = c.fetch(None)
    assert res.content == "" and res.count == 0
    assert parse_cursor(res.cursor) == {"since": now.isoformat()}


def test_rapid7_parks_the_asset_page_when_the_estate_spans_several_ticks(monkeypatch):
    """One asset page per poll bounds the request cost on a serial scheduler. The
    page number is parked so the assets past it are not silently skipped, and the
    watermark is held until the last page is walked."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = Rapid7InsightVmCollector("https://c:3780", "u", "p", 24)
    posted = []

    def _post(url, headers, data):
        posted.append(url)
        return json.dumps({"resources": [{"id": 1, "ip": "10.0.0.1"}],
                           "page": {"totalPages": 3}})

    monkeypatch.setattr(c, "_http_post", _post)
    monkeypatch.setattr(c, "_http_get", lambda url, headers:
                        '{"resources":[],"page":{"totalPages":1}}')
    parked = parse_cursor(c.fetch(None).cursor)
    assert "page=0" in posted[0]
    assert parked["page"] == 1                            # next page parked
    assert parked["until"] == now.isoformat()             # window end pinned
    assert "since" in parked and parked["since"] != now.isoformat()   # watermark held

    # the resuming tick asks for the parked page and keeps the pinned window end
    _freeze(monkeypatch, now + timedelta(minutes=5))
    resumed = parse_cursor(c.fetch(make_cursor(since=parked["since"],
                                               until=parked["until"], page=2)).cursor)
    assert "page=2" in posted[1]
    assert resumed == {"since": now.isoformat()}          # last page -> watermark moves


# --------------------------------------------------------------------------- #
#  Poll cadence + registration contract                                        #
# --------------------------------------------------------------------------- #
def test_a_scanner_collector_no_ops_between_pulls_without_destroying_the_cursor(monkeypatch):
    """`run_collector` writes `cursor=result.cursor` UNCONDITIONALLY, so a skipped
    tick must thread the incoming cursor back through. Returning None would write
    SQL NULL and replay the whole lookback window on the next poll."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24,
                                 min_interval_seconds=3600)
    monkeypatch.setattr(c, "_http_get", lambda url, headers: _QUALYS_BARE)
    first = c.fetch("2026-06-25T09:00:00Z")
    assert first.count == 1

    _freeze(monkeypatch, now + timedelta(minutes=5))       # the next scheduler tick
    monkeypatch.setattr(c, "_http_get", lambda url, headers: pytest.fail("polled too soon"))
    skipped = c.fetch("2026-06-25T12:00:00Z")
    assert skipped.content == "" and skipped.count == 0
    # threaded back through, not None — None would write SQL NULL
    assert parse_cursor(skipped.cursor) == {"since": "2026-06-25T12:00:00Z"}

    _freeze(monkeypatch, now + timedelta(hours=2))         # past the floor
    monkeypatch.setattr(c, "_http_get", lambda url, headers: _QUALYS_BARE)
    assert c.fetch("2026-06-25T12:00:00Z").count == 1


def test_due_is_a_pure_decision_over_instance_state():
    c = QualysDetectionCollector("b", "u", "p", 24, min_interval_seconds=600)
    now = _utc("2026-06-25T12:00:00")
    assert c.due(now) is True                              # never pulled
    c._last_pull = now
    assert c.due(now + timedelta(seconds=599)) is False
    assert c.due(now + timedelta(seconds=600)) is True


def test_configured_requires_every_mandatory_credential():
    assert QualysDetectionCollector("https://q", "u", "p", 24).configured()
    assert not QualysDetectionCollector("", "u", "p", 24).configured()
    assert not QualysDetectionCollector("https://q", "", "p", 24).configured()
    assert not QualysDetectionCollector("https://q", "u", "", 24).configured()
    assert TenableVulnExportCollector("AK", "SK", 24).configured()
    assert not TenableVulnExportCollector("", "SK", 24).configured()
    assert not TenableVulnExportCollector("AK", "", 24).configured()
    assert Rapid7InsightVmCollector("https://c", "u", "p", 24).configured()
    assert not Rapid7InsightVmCollector("https://c", "u", "", 24).configured()


def test_each_collector_declares_its_name_and_parser_format():
    """`name` is the collectors-table primary key and the `source_addr` stamped on
    every batch; `fmt` must be a key of `app/parsers/__init__.py:PARSERS` or ingest
    raises `unknown format` on every poll. Both are pinned here so the wire phase
    has one unambiguous list to register."""
    declared = {(c.name, c.fmt) for c in (
        QualysDetectionCollector("b", "u", "p", 24),
        TenableVulnExportCollector("AK", "SK", 24),
        Rapid7InsightVmCollector("b", "u", "p", 24))}
    assert declared == {("qualys", "qualys"), ("tenable", "tenable"),
                        ("rapid7", "rapid7")}


def test_run_collector_ingests_a_scanner_pull_under_its_own_source_addr(monkeypatch):
    """The runner glue, with `runner.db` / `runner.ingest` patched: a pulled batch
    takes the identical parse -> CIM-stamp -> detect path as an upload."""
    now = _utc("2026-06-25T12:00:00")
    _freeze(monkeypatch, now)
    calls = {}
    monkeypatch.setattr(runner.db, "get_collector", lambda name: {"cursor": "2026-06-25T09:00:00Z"})
    monkeypatch.setattr(runner.db, "update_collector",
                        lambda name, **f: calls.setdefault("update", (name, f)))
    monkeypatch.setattr(runner.ingest, "ingest",
                        lambda content, fmt, **kw: calls.setdefault("ingest", (content, fmt, kw)))
    c = QualysDetectionCollector("https://q.example.com", "u", "p", 24)
    monkeypatch.setattr(c, "_http_get", lambda url, headers: _QUALYS_BARE)

    assert runner.run_collector(c) == 1
    content, fmt, kw = calls["ingest"]
    assert fmt == "qualys"
    assert kw["source_type"] == "collector" and kw["source_addr"] == "qualys"
    assert list(qualys.parse(content))[0].vendor == "qualys"
    name, fields = calls["update"]
    assert name == "qualys"
    assert parse_cursor(fields["cursor"]) == {"since": "2026-06-25T12:00:00Z"}
    assert fields["last_status"] == "ok" and fields["last_count"] == 1


def test_a_fetch_failure_leaves_the_checkpoint_untouched(monkeypatch):
    """At-least-once delivery depends on the exception PROPAGATING out of `fetch`:
    runner.run_collector returns 0 without passing `cursor=`."""
    calls = {}
    monkeypatch.setattr(runner.db, "get_collector", lambda name: {"cursor": "C0"})
    monkeypatch.setattr(runner.db, "update_collector",
                        lambda name, **f: calls.setdefault("update", f))
    monkeypatch.setattr(runner.ingest, "ingest",
                        lambda *a, **k: pytest.fail("ingested a failed fetch"))

    class _Boom(QualysDetectionCollector):
        def fetch(self, cursor):
            raise RuntimeError("HTTP 503")

    assert runner.run_collector(_Boom("b", "u", "p", 24)) == 0
    assert "cursor" not in calls["update"]
    assert calls["update"]["last_status"] == "error"


def test_every_scanner_fetch_stays_synchronous():
    """`CollectorScheduler` runs `fetch` through `run_in_threadpool`, which requires
    a blocking callable. An `async def fetch` would hand `run_collector` a coroutine
    that it would then dereference as a FetchResult."""
    for cls, args in ((QualysDetectionCollector, ("b", "u", "p", 24)),
                      (TenableVulnExportCollector, ("AK", "SK", 24)),
                      (Rapid7InsightVmCollector, ("b", "u", "p", 24))):
        c = cls(*args)
        assert not inspect.iscoroutinefunction(c.fetch), cls.__name__

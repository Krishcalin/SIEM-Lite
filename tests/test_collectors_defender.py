# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Unit tests for the Microsoft Defender XDR collector + parser.

DB-free and network-free: every URL builder, page unwrapper and evidence
extractor is a pure function called with a fixture string, and the two `fetch`
bodies are exercised end-to-end by patching the one thin `_http_get` on the
instance. The CIM assertions are measured — they parse the fixtures with the real
parser and evaluate the real registry (plus, for the clauses this build ASKS the
wire phase to add, an overlay registry built from the shipped models.yaml).
"""
import json
from pathlib import Path

import yaml

from app import cim as cim_pkg
from app.cim import match as cim_match
from app.cim import registry as cim_registry
from app.collectors.base import parse_cursor
from app.collectors.defender import (CURSOR_FIELD, DefenderAlertCollector,
                                     DefenderIncidentCollector, alerts_url,
                                     graph_filter_time, graph_page, incidents_url,
                                     updated_since_filter)
from app.parsers import defender_xdr
from app.parsers.defender_xdr import (account_label, alert_action, evidence_kind,
                                      evidence_of, first_evidence, full_path,
                                      indicators, is_incident, normalize_severity,
                                      registry_target, service_log_type)

# --------------------------------------------------------------------------- #
#  Fixtures — trimmed but structurally faithful Graph responses                #
# --------------------------------------------------------------------------- #
ENDPOINT_ALERT = r"""
{"value":[
 {"id":"da637551227677560813_-961444813","providerAlertId":"pa-1","incidentId":"28282",
  "status":"resolved","severity":"high","classification":"truePositive",
  "determination":"malware","serviceSource":"microsoftDefenderForEndpoint",
  "detectionSource":"antivirus","title":"Suspicious execution of hidden file",
  "description":"A hidden file was launched","category":"DefenseEvasion",
  "mitreTechniques":["T1564.001","T1059"],"threatFamilyName":"Emotet",
  "alertWebUrl":"https://security.microsoft.com/alerts/x",
  "createdDateTime":"2026-06-25T10:00:00Z","lastUpdateDateTime":"2026-06-25T12:00:00Z",
  "firstActivityDateTime":"2026-06-25T09:55:00Z",
  "evidence":[
   {"@odata.type":"#microsoft.graph.security.deviceEvidence","verdict":"malicious",
    "deviceDnsName":"WIN-FIN-01","mdeDeviceId":"dev-1","osPlatform":"Windows11",
    "ipInterfaces":["10.1.2.3"],"remediationStatus":"none"},
   {"@odata.type":"#microsoft.graph.security.fileEvidence","detectionStatus":"blocked",
    "fileDetails":{"fileName":"evil.exe","filePath":"C:\\Users\\bob\\Downloads",
                   "sha256":"AAA256","sha1":"AAA1","fileSize":1024}},
   {"@odata.type":"#microsoft.graph.security.processEvidence","detectionStatus":"detected",
    "processId":4780,"parentProcessId":668,"processCommandLine":"\"evil.exe\" -enc x",
    "imageFile":{"fileName":"evil.exe","filePath":"C:\\Users\\bob\\Downloads",
                 "sha256":"BBB256"},
    "parentProcessImageFile":{"fileName":"explorer.exe","filePath":"C:\\Windows"},
    "userAccount":{"accountName":"bob","domainName":"CONTOSO","userSid":"S-1-5-21"}},
   {"@odata.type":"#microsoft.graph.security.ipEvidence","ipAddress":"203.0.113.9"},
   {"@odata.type":"#microsoft.graph.security.registryValueEvidence",
    "registryHive":"HKEY_LOCAL_MACHINE","registryKey":"SOFTWARE\\Microsoft\\Run",
    "registryValueName":"Updater","registryValue":"C:\\evil.exe"}
  ]}
]}
"""

OFFICE_ALERT = r"""
{"value":[{"id":"a2","status":"new","severity":"medium",
 "serviceSource":"microsoftDefenderForOffice365","title":"Malicious URL removed",
 "category":"InitialAccess","createdDateTime":"2026-06-25T08:00:00Z",
 "lastUpdateDateTime":"2026-06-25T08:05:00Z",
 "evidence":[
  {"@odata.type":"#microsoft.graph.security.analyzedMessageEvidence",
   "subject":"Invoice due","p1Sender":"env@bad.example","p2Sender":"ceo@bad.example",
   "recipientEmailAddress":"alice@contoso.com","senderIp":"198.51.100.7",
   "networkMessageId":"nm-1","remediationStatus":"remediated"},
  {"@odata.type":"#microsoft.graph.security.mailboxEvidence",
   "primaryAddress":"alice@contoso.com","upn":"alice@contoso.com"}]}]}
"""

IDENTITY_ALERT = r"""
{"value":[{"id":"a3","status":"new","severity":"high",
 "serviceSource":"microsoftDefenderForIdentity","title":"Suspected Golden Ticket usage",
 "createdDateTime":"2026-06-25T07:00:00Z","lastUpdateDateTime":"2026-06-25T07:01:00Z",
 "evidence":[{"@odata.type":"#microsoft.graph.security.userEvidence",
   "userAccount":{"accountName":"svc_sql","domainName":"CONTOSO",
                  "userPrincipalName":"svc_sql@contoso.com"}}]}]}
"""

INCIDENT_WITH_ALERTS = r"""
{"value":[{"id":"2972395","incidentWebUrl":"https://security.microsoft.com/incidents/2972395",
 "displayName":"Multi-stage incident on WIN-FIN-01","createdDateTime":"2026-06-25T11:00:00Z",
 "lastUpdateDateTime":"2026-06-25T13:00:00Z","assignedTo":"kai@contoso.com",
 "classification":"truePositive","determination":"multiStagedAttack","status":"active",
 "severity":"medium","customTags":["Demo"],
 "alerts":[{"id":"a9","serviceSource":"microsoftDefenderForEndpoint","severity":"high",
   "status":"new","title":"Ransomware behaviour detected","category":"Impact",
   "createdDateTime":"2026-06-25T11:05:00Z","lastUpdateDateTime":"2026-06-25T11:06:00Z",
   "evidence":[{"@odata.type":"#microsoft.graph.security.deviceEvidence",
                "deviceDnsName":"WIN-FIN-01"},
               {"@odata.type":"#microsoft.graph.security.fileEvidence",
                "detectionStatus":"prevented",
                "fileDetails":{"fileName":"locker.exe","filePath":"C:\\Temp",
                               "sha256":"CCC256"}}]}]}]}
"""


def _one(text):
    events = list(defender_xdr.parse(text))
    assert events, "fixture parsed to nothing"
    return events[0]


# --------------------------------------------------------------------------- #
#  Provider -> log_type (the CIM membership handle)                            #
# --------------------------------------------------------------------------- #
def test_service_log_type_maps_every_shipped_defender_provider():
    assert service_log_type("microsoftDefenderForEndpoint") == "endpoint"
    assert service_log_type("microsoftDefenderForIdentity") == "identity"
    assert service_log_type("microsoftDefenderForOffice365") == "email"
    assert service_log_type("microsoftDefenderForCloudApps") == "cloud-apps"
    assert service_log_type("microsoftDefenderForCloud") == "cloud"
    assert service_log_type("azureAdIdentityProtection") == "identity"
    assert service_log_type("microsoft365Defender") == "xdr"
    # case / spacing / underscores are normalized away
    assert service_log_type("Microsoft Defender for Endpoint") == "endpoint"
    assert service_log_type("microsoft_defender_for_identity") == "identity"


def test_service_log_type_hint_order_keeps_cloud_apps_out_of_cloud():
    # A provider not in the exact table still has to route correctly. "cloudapp"
    # MUST be tested before "cloud" or every Cloud Apps alert is tagged `cloud`.
    assert service_log_type("microsoftDefenderForCloudAppsPreview") == "cloud-apps"
    assert service_log_type("microsoftDefenderForCloudPreview") == "cloud"
    assert service_log_type("someNewOffice365Service") == "email"


def test_service_log_type_is_total_for_missing_or_unknown_providers():
    # `(vendor, log_type)` is the source-health identity, so it is never half-empty.
    assert service_log_type(None) == "alert"
    assert service_log_type("") == "alert"
    assert service_log_type("brandNewProvider") == "alert"


# --------------------------------------------------------------------------- #
#  Severity + disposition                                                      #
# --------------------------------------------------------------------------- #
def test_normalize_severity_drops_the_placeholder_enums():
    assert normalize_severity("High") == "high"
    assert normalize_severity("informational") == "informational"
    assert normalize_severity("unknownFutureValue") is None
    assert normalize_severity("unknown") is None
    assert normalize_severity(None) is None


def test_alert_action_ranks_the_strongest_disposition_across_all_evidence():
    rec = json.loads(ENDPOINT_ALERT)["value"][0]
    # device says remediationStatus=none, file says blocked, process says detected —
    # ranked, not first-wins, so `blocked` is the answer.
    assert alert_action(rec) == "blocked"
    assert alert_action({"evidence": [{"detectionStatus": "detected"},
                                      {"remediationStatus": "prevented"}]}) == "prevented"


def test_alert_action_falls_back_to_the_triage_status_without_evidence():
    assert alert_action({"status": "Resolved"}) == "resolved"
    assert alert_action({"evidence": [{"detectionStatus": "none"}],
                         "status": "active"}) == "active"
    assert alert_action({}) is None


# --------------------------------------------------------------------------- #
#  Evidence walking                                                            #
# --------------------------------------------------------------------------- #
def test_evidence_kind_strips_the_odata_type_prefix():
    assert evidence_kind({"@odata.type": "#microsoft.graph.security.deviceEvidence"}) \
        == "deviceevidence"
    assert evidence_kind({"@odata.type": "microsoft.graph.security.fileEvidence"}) \
        == "fileevidence"
    assert evidence_kind({"no": "type"}) == ""
    assert evidence_kind("not a dict") == ""


def test_evidence_of_selects_only_the_requested_kind():
    rec = json.loads(ENDPOINT_ALERT)["value"][0]
    assert len(evidence_of(rec, "fileevidence")) == 1
    assert evidence_of(rec, "urlevidence") == []
    assert first_evidence(rec, "urlevidence") == {}
    assert first_evidence(rec, "deviceevidence")["deviceDnsName"] == "WIN-FIN-01"


def test_full_path_rejoins_defenders_split_directory_and_leaf():
    # Defender's `filePath` is the DIRECTORY; Sysmon's `Image` is the whole path,
    # and the Endpoint model reads the Sysmon spelling.
    assert full_path({"filePath": "C:\\Windows", "fileName": "cmd.exe"}) == \
        "C:\\Windows\\cmd.exe"
    assert full_path({"filePath": "C:\\Windows\\", "fileName": "cmd.exe"}) == \
        "C:\\Windows\\cmd.exe"
    assert full_path({"fileName": "cmd.exe"}) == "cmd.exe"
    assert full_path({"filePath": "C:\\Windows"}) == "C:\\Windows"
    assert full_path(None) is None
    assert full_path({}) is None


def test_account_label_prefers_upn_then_domain_qualified_name():
    assert account_label({"userPrincipalName": "bob@contoso.com",
                          "accountName": "bob", "domainName": "CONTOSO"}) == \
        "bob@contoso.com"
    assert account_label({"accountName": "bob", "domainName": "CONTOSO"}) == "CONTOSO\\bob"
    assert account_label({"accountName": "bob"}) == "bob"
    assert account_label({}) is None
    assert account_label("nope") is None


def test_registry_target_renders_one_sysmon_style_target_object():
    assert registry_target({"registryHive": "HKEY_LOCAL_MACHINE",
                            "registryKey": "SOFTWARE\\Microsoft\\Run",
                            "registryValueName": "Updater"}) == \
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Run\\Updater"
    assert registry_target({"registryKey": "SOFTWARE\\X"}) == "SOFTWARE\\X"
    assert registry_target({}) is None


# --------------------------------------------------------------------------- #
#  The evidence lift — the whole point of this parser                          #
# --------------------------------------------------------------------------- #
def test_indicators_lift_every_cim_read_key_to_the_top_level():
    # `app/cim/match.py` matches a jsonb key byte-exactly, never indexes an array
    # and returns nothing for a container — so each of these MUST be a scalar at
    # the top level or the Endpoint/Malware fields read NULL.
    got = indicators(json.loads(ENDPOINT_ALERT)["value"][0])
    assert got["Image"] == "C:\\Users\\bob\\Downloads\\evil.exe"      # process_name
    assert got["CommandLine"] == '"evil.exe" -enc x'                  # process
    assert got["ParentImage"] == "C:\\Windows\\explorer.exe"          # parent_process
    assert got["FileName"] == "evil.exe"                              # file_name
    assert got["SHA256"] == "AAA256"                                  # process_hash
    assert got["TargetObject"] == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Run\\Updater"
    assert got["DeviceName"] == "WIN-FIN-01"
    assert got["AccountName"] == "CONTOSO\\bob"
    assert got["IpAddress"] == "203.0.113.9"
    assert got["ProcessId"] == "4780" and got["ParentProcessId"] == "668"
    assert got["DeviceIp"] == "10.1.2.3"                              # ipInterfaces[0]
    assert all(not isinstance(v, (dict, list)) for v in got.values())


def test_indicators_prefer_file_evidence_over_the_process_image():
    # File evidence is lifted first and `_merge` never overwrites, so the hash on a
    # malware alert describes the malicious FILE (AAA256), not the image (BBB256).
    got = indicators(json.loads(ENDPOINT_ALERT)["value"][0])
    assert got["SHA256"] == "AAA256" and got["SHA1"] == "AAA1"


def test_indicators_fall_through_to_the_image_file_when_there_is_no_file_evidence():
    rec = {"evidence": [{"@odata.type": "#microsoft.graph.security.processEvidence",
                         "processCommandLine": "powershell.exe -enc AAA",
                         "imageFile": {"fileName": "powershell.exe",
                                       "filePath": "C:\\Windows\\System32",
                                       "sha256": "BBB256"}}]}
    got = indicators(rec)
    assert got["FileName"] == "powershell.exe" and got["SHA256"] == "BBB256"
    assert got["Image"] == "C:\\Windows\\System32\\powershell.exe"


def test_indicators_join_mitre_techniques_into_a_scalar():
    # A list value is unreadable to CIM (`match._text` returns None for containers).
    got = indicators(json.loads(ENDPOINT_ALERT)["value"][0])
    assert got["mitre_techniques"] == "T1564.001,T1059"
    assert got["threat"] == "Emotet"


def test_indicators_lift_the_email_model_keys_verbatim():
    # Email reads `subject` / `sender` / `recipient` — lower-case, exactly these.
    got = indicators(json.loads(OFFICE_ALERT)["value"][0])
    assert got["subject"] == "Invoice due"
    assert got["sender"] == "ceo@bad.example"          # p2Sender (From) beats p1Sender
    assert got["recipient"] == "alice@contoso.com"
    assert got["SenderIp"] == "198.51.100.7"


def test_indicators_survive_malformed_evidence():
    assert indicators({}) == {}
    assert indicators({"evidence": "not a list"}) == {}
    assert indicators({"evidence": ["scalar", None, {"@odata.type": "x.fileEvidence"}]}) == {}


# --------------------------------------------------------------------------- #
#  parse() — record routing and normalized columns                             #
# --------------------------------------------------------------------------- #
def test_parse_maps_an_endpoint_alert_onto_the_normalized_columns():
    e = _one(ENDPOINT_ALERT)
    assert (e.vendor, e.product, e.log_type) == ("microsoft", "defender", "endpoint")
    assert e.severity == "high" and e.action == "blocked"
    assert e.user_name == "CONTOSO\\bob" and e.host_name == "WIN-FIN-01"
    assert e.src_ip == "203.0.113.9"
    assert e.rule_name == "Suspicious execution of hidden file"       # CIM `signature`
    assert e.message.startswith("Suspicious execution of hidden file") and "Emotet" in e.message
    # firstActivityDateTime wins over createdDateTime — when it HAPPENED, not when
    # the alert was raised.
    assert e.event_time.isoformat().startswith("2026-06-25T09:55:00")


def test_parse_keeps_the_vendor_record_intact_and_only_adds_lifted_keys():
    e = _one(ENDPOINT_ALERT)
    original = json.loads(ENDPOINT_ALERT)["value"][0]
    for key, value in original.items():
        assert e.raw[key] == value                     # nothing rewritten or dropped
    assert e.raw["Image"] == "C:\\Users\\bob\\Downloads\\evil.exe"
    assert e.raw["SHA256"] == "AAA256"


def test_parse_routes_the_identity_provider_to_its_own_log_type():
    e = _one(IDENTITY_ALERT)
    assert e.log_type == "identity"
    assert e.user_name == "svc_sql@contoso.com"
    assert e.action == "new"                           # no disposition -> triage status


def test_parse_yields_the_incident_then_each_expanded_alert():
    events = list(defender_xdr.parse(INCIDENT_WITH_ALERTS))
    assert [e.log_type for e in events] == ["incident", "endpoint"]
    inc, alert = events
    assert inc.rule_name == "Multi-stage incident on WIN-FIN-01"
    assert inc.action == "active" and inc.severity == "medium"
    assert "truepositive" in inc.message
    # The incident inherits its alerts' evidence, so the Endpoint fields are not
    # null-by-construction when $expand=alerts is on.
    assert inc.host_name == "WIN-FIN-01" and inc.raw["SHA256"] == "CCC256"
    assert alert.action == "prevented" and alert.raw["FileName"] == "locker.exe"


def test_is_incident_uses_the_keys_only_one_shape_carries():
    assert is_incident({"incidentWebUrl": "u", "displayName": "n"})
    assert is_incident({"displayName": "n", "alerts": []})
    assert not is_incident({"serviceSource": "microsoftDefenderForEndpoint"})
    assert not is_incident({"evidence": [], "displayName": "n"})   # alert-only key wins
    assert not is_incident({"alertWebUrl": "u"})
    assert not is_incident({"id": "x"})


def test_parse_accepts_a_bare_array_a_single_object_and_ndjson():
    recs = json.loads(ENDPOINT_ALERT)["value"]
    assert len(list(defender_xdr.parse(json.dumps(recs)))) == 1
    assert len(list(defender_xdr.parse(json.dumps(recs[0])))) == 1
    ndjson = "\n".join(json.dumps(r) for r in recs * 3)
    assert len(list(defender_xdr.parse(ndjson))) == 3


def test_parse_never_raises_on_garbage():
    for junk in ("", "   ", "not json", "[]", '{"value":"nope"}', "null",
                 '{"value":[null,"x",{"id":"a"}]}'):
        list(defender_xdr.parse(junk))
    e = _one('{"value":[{"id":"a","severity":null,"evidence":null,'
             '"serviceSource":null,"lastUpdateDateTime":"2026-06-25T00:00:00Z"}]}')
    assert e.log_type == "alert" and e.severity is None and e.vendor == "microsoft"


# --------------------------------------------------------------------------- #
#  CIM — what lands for free, and what the wire phase must add                 #
# --------------------------------------------------------------------------- #
def test_office365_alerts_land_in_the_email_model_with_no_registry_edit():
    # Measured against the SHIPPED registry: `log_type: email` is already a member
    # value of the Email model's forward-looking clause, which is exactly why the
    # parser maps microsoftDefenderForOffice365 to it.
    e = _one(OFFICE_ALERT)
    assert e.log_type == "email"
    assert "email" in cim_match.tags_for(e)


def test_the_shipped_membership_clauses_tag_endpoint_identity_and_malware():
    """Asserted against the SHIPPED registry — the whole point.

    These two tests used to build a temporary models.yaml with the three Defender
    clauses spliced in, which was right while the clauses were still a proposal: they
    proved the requested edit rather than a paraphrase of it. But the clauses have
    since been merged verbatim into app/cim/models.yaml, so the overlay was re-adding
    a duplicate of what was already there and the assertion could no longer observe
    the shipped clause at all. Deleting any of the three from models.yaml — i.e.
    breaking Defender CIM membership in production — left all 40 tests in this file
    passing, including the two named as if they proved otherwise.

    (The golden corpus in test_cim.py did catch those deletions, so this was never a
    coverage hole. It was a test that claimed something it did not check, which is the
    more dangerous kind: a reader looking for Defender CIM coverage finds it here.)
    """
    endpoint_evt, identity_evt = _one(ENDPOINT_ALERT), _one(IDENTITY_ALERT)
    assert "endpoint" in cim_match.tags_for(endpoint_evt)
    assert "authentication" in cim_match.tags_for(identity_evt)
    # The malware clause keys on the alert's own `category`, so a DefenseEvasion
    # alert must NOT be pulled into Malware.
    assert "malware" not in cim_match.tags_for(endpoint_evt)
    malware_evt = _one(ENDPOINT_ALERT.replace('"DefenseEvasion"', '"Malware"'))
    assert "malware" in cim_match.tags_for(malware_evt)


def test_the_endpoint_model_projects_real_values_for_a_defender_alert():
    # Honesty rule 4: a model must not gain a member whose fields are all null.
    # These are the raw keys the shipped Endpoint field mappings read.
    raw = _one(ENDPOINT_ALERT).raw
    assert raw["CommandLine"] and raw["Image"] and raw["ParentImage"]
    assert raw["FileName"] and raw["SHA256"] and raw["TargetObject"]
    assert "endpoint" in cim_match.tags_for(_one(ENDPOINT_ALERT))


def test_the_fixtures_carry_the_keys_detect_format_must_route_on():
    # The wire phase inserts a `defender_xdr` key test into `detect._detect_json`
    # ABOVE the crowdstrike/generic_json lines. These are the discriminators it
    # keys on — if a fixture ever loses them, the routing proposal is stale.
    alert_keys = {k.lower() for k in json.loads(ENDPOINT_ALERT)["value"][0]}
    incident_keys = {k.lower() for k in json.loads(INCIDENT_WITH_ALERTS)["value"][0]}
    assert {"servicesource", "alertweburl", "provideralertid"} <= alert_keys
    assert "incidentweburl" in incident_keys
    assert {"determination", "lastupdatedatetime"} <= alert_keys
    assert {"determination", "lastupdatedatetime"} <= incident_keys
    # ...and none of them trip an earlier detector in the chain.
    for keys in (alert_keys, incident_keys):
        assert "event_type" not in keys and "providername" not in keys
        assert "eventsource" not in keys and "workload" not in keys
        assert "eventtype" not in keys and "protopayload" not in keys
        assert not ({"aid", "cid", "sensorid", "detectname"} & keys)
        assert not ({"metadata", "event"} <= keys)


# --------------------------------------------------------------------------- #
#  Collector — URL builders                                                    #
# --------------------------------------------------------------------------- #
def test_graph_filter_time_normalizes_both_cursor_shapes_to_one_literal():
    # The cursor column is mixed-format: iso_lookback writes `...000Z`, max_time_iso
    # writes `datetime.isoformat()` (`+00:00`). Both must reach Graph identically.
    assert graph_filter_time("2026-06-25T00:00:00.000Z") == "2026-06-25T00:00:00.000Z"
    assert graph_filter_time("2026-06-25T11:30:00+00:00") == "2026-06-25T11:30:00.000Z"
    assert graph_filter_time("2026-06-25T11:30:00Z") == \
        graph_filter_time("2026-06-25T11:30:00+00:00")
    # a non-UTC offset is converted, not truncated
    assert graph_filter_time("2026-06-25T11:30:00+05:30") == "2026-06-25T06:00:00.000Z"
    assert graph_filter_time("garbage") == "garbage"       # passed through, not guessed
    assert graph_filter_time(None) == ""


def test_updated_since_filter_windows_on_the_mutable_update_stamp():
    assert CURSOR_FIELD == "lastUpdateDateTime"
    assert updated_since_filter("2026-06-25T00:00:00.000Z") == \
        "lastUpdateDateTime gt 2026-06-25T00:00:00.000Z"


def test_alerts_url_encodes_the_filter_and_never_emits_a_bare_plus():
    u = alerts_url("2026-06-25T11:30:00+00:00", top=200)
    assert u.startswith("https://graph.microsoft.com/v1.0/security/alerts_v2?$top=200")
    assert "lastUpdateDateTime%20gt%202026-06-25T11%3A30%3A00.000Z" in u
    # A raw '+' in a query string decodes as a space and shifts the window.
    assert "+" not in u
    assert "$orderby" not in u


def test_incidents_url_expands_alerts_only_when_asked():
    plain = incidents_url("2026-06-25T00:00:00.000Z", top=50)
    assert plain.startswith("https://graph.microsoft.com/v1.0/security/incidents?$top=50")
    assert "$expand" not in plain
    assert "$expand=alerts" in incidents_url("2026-06-25T00:00:00.000Z", 50, True)


def test_graph_page_unwraps_value_and_the_next_link():
    body = '{"value":[{"id":"1"},{"id":"2"}],"@odata.nextLink":"https://graph/next"}'
    recs, nxt = graph_page(body)
    assert [r["id"] for r in recs] == ["1", "2"] and nxt == "https://graph/next"
    assert graph_page('{"value":[]}') == ([], None)
    # An empty / null nextLink is the LAST page, not another hop — following it
    # would re-request the same URL until the page cap on every idle poll.
    assert graph_page('{"value":[],"@odata.nextLink":""}') == ([], None)
    assert graph_page('{"value":[],"@odata.nextLink":null}') == ([], None)
    assert graph_page('{"value":"nope"}') == ([], None)
    assert graph_page("not json") == ([], None)
    assert graph_page("[1,2]") == ([], None)


# --------------------------------------------------------------------------- #
#  Collector — fetch (network patched on the instance)                         #
# --------------------------------------------------------------------------- #
def test_defender_collectors_are_configured_by_the_one_app_registration():
    assert DefenderAlertCollector("tid", "cid", "sec", 24).configured()
    assert not DefenderAlertCollector("", "cid", "sec", 24).configured()
    assert not DefenderAlertCollector("tid", "", "sec", 24).configured()
    assert not DefenderAlertCollector("tid", "cid", "", 24).configured()
    assert DefenderIncidentCollector("tid", "cid", "sec", 24).configured()
    assert not DefenderIncidentCollector("tid", "cid", "", 24).configured()


def test_defender_collectors_bind_to_the_defender_xdr_parser():
    # `fmt` must be a key of PARSERS or pipeline.parse_events raises before any DB
    # work and run_collector swallows it into last_status='error' forever.
    assert DefenderAlertCollector.fmt == "defender_xdr"
    assert DefenderIncidentCollector.fmt == "defender_xdr"
    assert DefenderAlertCollector.name == "defender_alerts"
    assert DefenderIncidentCollector.name == "defender_incidents"


def test_alert_fetch_follows_next_link_and_advances_the_cursor(monkeypatch):
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    seen = []
    pages = iter([
        '{"value":[{"id":"1","lastUpdateDateTime":"2026-06-25T10:00:00Z"}],'
        '"@odata.nextLink":"https://graph/page2"}',
        '{"value":[{"id":"2","lastUpdateDateTime":"2026-06-25T12:00:00Z"}]}',
    ])

    def _get(url, headers):
        seen.append(url)
        assert headers["Authorization"] == "Bearer AT"
        return next(pages)          # over-fetching raises StopIteration

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch("2026-06-25T00:00:00.000Z")

    assert res.count == 2
    assert json.loads(res.content)["value"][1]["id"] == "2"
    # The walk COMPLETED (page 2 carried no nextLink), so the watermark advances to the
    # newest record and no resume pointer is parked.
    state = parse_cursor(res.cursor)
    assert state["since"].startswith("2026-06-25T12:00:00")       # newest, not oldest
    assert "next" not in state
    assert seen[0].startswith("https://graph.microsoft.com/v1.0/security/alerts_v2")
    assert "2026-06-25T00%3A00%3A00.000Z" in seen[0]             # stored cursor used
    assert seen[1] == "https://graph/page2"                      # nextLink followed verbatim


def test_incident_fetch_requests_the_expansion_it_was_built_with(monkeypatch):
    seen = []

    def _run(expand):
        c = DefenderIncidentCollector("tid", "cid", "sec", 24, expand_alerts=expand)
        monkeypatch.setattr(c, "_token", lambda: "AT")
        monkeypatch.setattr(c, "_http_get",
                            lambda url, headers: seen.append(url) or '{"value":[]}')
        return c.fetch("2026-06-25T00:00:00.000Z")

    _run(False)
    _run(True)
    assert "$expand" not in seen[0] and "$expand=alerts" in seen[1]
    assert all("/security/incidents?" in u for u in seen)


def test_idle_poll_returns_empty_content_and_keeps_the_cursor(monkeypatch):
    # '' skips ingest entirely; '{"value": []}' would round-trip a zero-row batch
    # on every single poll, forever.
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    monkeypatch.setattr(c, "_http_get", lambda url, headers: '{"value":[]}')
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert res.content == "" and res.count == 0
    # never None, and the watermark is held exactly where it was
    assert parse_cursor(res.cursor) == {"since": "2026-06-25T00:00:00.000Z"}


def test_first_run_without_a_cursor_windows_on_the_lookback(monkeypatch):
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    seen = []
    monkeypatch.setattr(c, "_http_get",
                        lambda url, headers: seen.append(url) or '{"value":[]}')
    res = c.fetch(None)
    assert "lastUpdateDateTime%20gt%20" in seen[0]
    assert parse_cursor(res.cursor)["since"].endswith("Z")       # the lookback, kept


def test_fetch_stops_at_the_page_cap(monkeypatch):
    # A never-ending nextLink must not hold the serial scheduler thread forever.
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    calls = []
    monkeypatch.setattr(
        c, "_http_get",
        lambda url, headers: calls.append(url) or
        '{"value":[{"id":"x","lastUpdateDateTime":"2026-06-25T10:00:00Z"}],'
        '"@odata.nextLink":"https://graph/again"}')
    res = c.fetch("2026-06-25T00:00:00.000Z")
    assert len(calls) == 20 and res.count == 20


def test_a_truncated_walk_parks_the_next_link_and_does_not_advance_the_watermark(
        monkeypatch):
    """The page cap must not become a delete.

    `alerts_url` sends no `$orderby` and Graph documents no default order for
    alerts_v2, newest-first being the common behaviour. So when the walk stops at
    _MAX_PAGES, the maximum over the pages that WERE read is not a valid watermark:
    the next poll's `$filter lastUpdateDateTime gt <cursor>` would exclude every
    record on an unread page stamped older than it, permanently.

    Newest-first is exactly what this stub returns — page 0 is the newest — so a
    collector that advanced the watermark here would strand pages 20-22.
    """
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    day = iter(range(20, -3, -1))            # 2026-08-20 down to 2026-07-29

    def _get(url, headers):
        d = next(day)
        stamp = (f"2026-08-{d:02d}T00:00:00Z" if d > 0
                 else f"2026-07-{31 + d:02d}T00:00:00Z")
        return json.dumps({"value": [{"id": f"a{d}", CURSOR_FIELD: stamp}],
                           "@odata.nextLink": "https://graph/next"})

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch("2026-06-25T00:00:00.000Z")

    state = parse_cursor(res.cursor)
    assert state["next"] == "https://graph/next"          # resume pointer parked
    assert state["since"] == "2026-06-25T00:00:00.000Z"   # watermark HELD, not advanced
    assert "2026-08-20" not in state["since"]             # the newest read record


def test_a_parked_next_link_is_resumed_verbatim_on_the_following_poll(monkeypatch):
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    seen = []
    monkeypatch.setattr(
        c, "_http_get",
        lambda url, headers: seen.append(url) or
        '{"value":[{"id":"z","lastUpdateDateTime":"2026-08-21T00:00:00Z"}]}')

    res = c.fetch('{"since": "2026-06-25T00:00:00.000Z", "next": "https://graph/p21"}')

    assert seen == ["https://graph/p21"]        # resumed, NOT re-derived from `since`
    state = parse_cursor(res.cursor)
    # The walk finished this time, so the pointer is dropped and the watermark moves.
    assert "next" not in state
    assert state["since"].startswith("2026-08-21T00:00:00")


def test_an_expired_skiptoken_restarts_the_walk_rather_than_failing(monkeypatch):
    """A parked @odata.nextLink can age out. `since` was never advanced past the
    truncation point, so restarting from it re-reads and loses nothing — but only the
    FIRST hop may be retried that way; a failure mid-walk is a real error."""
    c = DefenderAlertCollector("tid", "cid", "sec", 24)
    monkeypatch.setattr(c, "_token", lambda: "AT")
    seen = []

    def _get(url, headers):
        seen.append(url)
        if url == "https://graph/stale":
            raise RuntimeError("400 skiptoken expired")
        return '{"value":[{"id":"1","lastUpdateDateTime":"2026-06-25T09:00:00Z"}]}'

    monkeypatch.setattr(c, "_http_get", _get)
    res = c.fetch('{"since": "2026-06-25T00:00:00.000Z", "next": "https://graph/stale"}')

    assert seen[0] == "https://graph/stale"
    assert seen[1].startswith("https://graph.microsoft.com/v1.0/security/alerts_v2")
    assert "2026-06-25T00%3A00%3A00.000Z" in seen[1]     # restarted from the held `since`
    assert res.count == 1

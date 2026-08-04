# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Microsoft Defender XDR parser — Graph Security alerts (``alerts_v2``) and
Microsoft 365 Defender incidents.

Both endpoints answer with the same Graph collection envelope
(``{"value": [...]}``) and both records carry ``severity`` / ``status`` /
``createdDateTime`` / ``lastUpdateDateTime``. An ALERT additionally carries
``serviceSource`` plus a typed ``evidence`` array; an INCIDENT is the correlation
object over a set of alerts and carries ``displayName`` / ``incidentWebUrl``
(and, when the collector asks for ``$expand=alerts``, the alerts themselves).

Two decisions here are load-bearing rather than stylistic:

  * ``log_type`` is derived from ``serviceSource`` — endpoint / identity / email /
    cloud-apps / cloud / xdr. A CIM membership term can only test nine normalized
    columns (``app/cim/sql.py:_TERM_COLUMNS``), so the provider has to BE one of
    them or the CIM layer cannot tell an MDE process detection from a Defender for
    Office 365 phish alert. ``email`` is chosen deliberately: it is already a
    member value of the Email model's forward-looking clause, so Defender for
    Office 365 alerts land in Email with no registry edit at all.
  * the typed ``evidence`` array is FLATTENED onto scalar TOP-LEVEL ``raw`` keys,
    using the spellings the CIM registry already reads (``Image``,
    ``CommandLine``, ``ParentImage``, ``FileName``, ``SHA256``, ``TargetObject``,
    ``subject``, ``sender``, ``recipient``). ``app/cim/match.py`` matches a jsonb
    key BYTE-EXACTLY, never descends an array index, and yields nothing at all for
    a container value — so a hash sitting at ``evidence[2].imageFile.sha256`` is
    invisible to every CIM field until it is lifted. This is the same move
    ``windows_security.py`` makes for ``event_id``, for the same reason.

The vendor record is kept intact in ``raw`` and the lifted keys are only ever
ADDED, never overwritten, so nothing Microsoft sent is lost or rewritten.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts

# ── provider -> log_type ─────────────────────────────────────────────────────
#: `serviceSource` (lower-cased, spaces stripped) -> the log_type that carries the
#: provider into CIM membership. Exact table first; `_SERVICE_HINTS` is the safety
#: net for a provider Microsoft renames or adds after this file was written.
_SERVICE_LOG_TYPES = {
    "microsoftdefenderforendpoint": "endpoint",
    "microsoftdefenderforidentity": "identity",
    "microsoftdefenderforoffice365": "email",
    "microsoftdefenderforcloudapps": "cloud-apps",
    "microsoftdefenderforcloud": "cloud",
    "microsoftdefenderthreatintelligence": "xdr",
    "microsoft365defender": "xdr",
    "microsoftdefenderxdr": "xdr",
    "microsoftsentinel": "xdr",
    "azureadidentityprotection": "identity",
    "aadidentityprotection": "identity",
    "microsoftappgovernance": "cloud-apps",
    "datalossprevention": "dlp",
    "microsoftdatalossprevention": "dlp",
}

#: ORDERED substring fallbacks. Order is load-bearing: "microsoftDefenderForCloudApps"
#: contains both "cloudapp" and "cloud", so the more specific needle must be tested
#: first or every Cloud Apps alert would be tagged as a Defender for Cloud alert.
_SERVICE_HINTS: tuple[tuple[str, str], ...] = (
    ("office", "email"),
    ("exchange", "email"),
    ("email", "email"),
    ("identity", "identity"),
    ("cloudapp", "cloud-apps"),
    ("appgovernance", "cloud-apps"),
    ("dataloss", "dlp"),
    ("endpoint", "endpoint"),
    ("cloud", "cloud"),
    ("sentinel", "xdr"),
    ("xdr", "xdr"),
)

#: log_type for a record that is an incident rather than an alert.
INCIDENT_LOG_TYPE = "incident"
#: log_type for an alert whose provider is missing or unrecognised.
DEFAULT_LOG_TYPE = "alert"

#: Enum values Graph uses for "we are not telling you" — never worth storing.
_HIDDEN = {"", "unknown", "unknownfuturevalue", "none", "notavailable"}

#: What Defender DID, most decisive first. Scanned across every evidence item so a
#: single blocked artefact wins over a merely observed one.
_DISPOSITION_RANK = ("blocked", "prevented", "remediated", "quarantined",
                     "cleaned", "detected", "allowed")


def _g(rec: dict, *names: str) -> Optional[Any]:
    """First non-empty value among `names`, resolved case-insensitively."""
    low = {str(k).strip().lower(): v for k, v in rec.items()}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, ""):
            return v
    return None


def _txt(value: Any) -> Optional[str]:
    """A scalar rendered as text — None for empty values and for containers, which
    CIM cannot read anyway (``app/cim/match.py:_text`` returns None for those)."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    s = str(value).strip()
    return s or None


def _addr(value: Any) -> Optional[str]:
    """A mail address from either spelling Microsoft uses for one.

    ``analyzedMessageEvidence.p1Sender`` / ``p2Sender`` are ``emailSender``
    OBJECTS in the Graph security API — ``{"emailAddress": …, "displayName": …}`` —
    while the Advanced Hunting ``EmailEvents`` columns of the same names are bare
    strings. ``_txt`` alone returns None for the object, so reading the object form
    is what makes the Email model's ``src_user`` resolve against real Graph output
    rather than only against a hand-flattened fixture.
    """
    if isinstance(value, dict):
        return _txt(_g(value, "emailAddress", "address", "upn",
                       "userPrincipalName", "displayName"))
    return _txt(value)


# ── provider / severity / disposition ────────────────────────────────────────
def service_log_type(service_source: Any) -> str:
    """The ``log_type`` for a Defender ``serviceSource``.

    Pure and total: an unknown or missing provider degrades to
    ``DEFAULT_LOG_TYPE`` rather than to None, so `(vendor, log_type)` — which is
    also the source-health identity — is never half-empty.
    """
    s = str(service_source or "").strip().lower().replace(" ", "").replace("_", "")
    if not s:
        return DEFAULT_LOG_TYPE
    exact = _SERVICE_LOG_TYPES.get(s)
    if exact:
        return exact
    for needle, tag in _SERVICE_HINTS:
        if needle in s:
            return tag
    return DEFAULT_LOG_TYPE


def normalize_severity(value: Any) -> Optional[str]:
    """Graph severity (informational | low | medium | high) lower-cased, with the
    placeholder enum values dropped to None."""
    s = str(value or "").strip().lower()
    return None if s in _HIDDEN else s


def alert_action(rec: dict) -> Optional[str]:
    """What Defender did about it.

    Prefers a real disposition off the evidence (``remediationStatus`` /
    ``detectionStatus``) over the alert's triage ``status``, ranked so the most
    decisive outcome across all evidence wins.
    """
    found: set[str] = set()
    for item in evidence(rec):
        for key in ("remediationStatus", "detectionStatus"):
            v = str(_g(item, key) or "").strip().lower()
            if v and v not in _HIDDEN:
                found.add(v)
    for tag in _DISPOSITION_RANK:
        if tag in found:
            return tag
    if found:
        return sorted(found)[0]
    # Lower-cased like the dispositions above so `action` has ONE casing whatever
    # branch produced it — LOQL and saved searches compare it literally.
    status = _txt(_g(rec, "status"))
    return status.lower() if status else None


# ── evidence walking ─────────────────────────────────────────────────────────
def evidence(rec: dict) -> list:
    """The record's evidence items ([] when absent or malformed)."""
    ev = _g(rec, "evidence")
    return [i for i in ev if isinstance(i, dict)] if isinstance(ev, list) else []


def evidence_kind(item: Any) -> str:
    """The short ``@odata.type`` of one evidence item.

    ``"#microsoft.graph.security.deviceEvidence"`` -> ``"deviceevidence"``;
    ``""`` when the item carries no type at all.
    """
    if not isinstance(item, dict):
        return ""
    for key in ("@odata.type", "odata.type"):
        v = _g(item, key)
        if isinstance(v, str) and v.strip():
            return v.strip().lstrip("#").rsplit(".", 1)[-1].strip().lower()
    return ""


def evidence_of(rec: dict, kind: str) -> list:
    """Every evidence item of one kind, in vendor order."""
    want = kind.strip().lower()
    return [i for i in evidence(rec) if evidence_kind(i) == want]


def first_evidence(rec: dict, kind: str) -> dict:
    """The first evidence item of one kind ({} when there is none)."""
    items = evidence_of(rec, kind)
    return items[0] if items else {}


def file_details(item: dict) -> dict:
    """The ``fileDetails`` (file evidence) or ``imageFile`` (process evidence)
    sub-object holding the name / path / hashes."""
    for key in ("fileDetails", "imageFile"):
        sub = _g(item, key)
        if isinstance(sub, dict):
            return sub
    return {}


def full_path(details: Any) -> Optional[str]:
    """``filePath`` joined to ``fileName``.

    Defender splits a path the way Sysmon does not: ``filePath`` is the DIRECTORY
    and ``fileName`` the leaf. Rejoining them is what makes the lifted ``Image``
    key comparable to Sysmon's, which is what the Endpoint model reads.
    """
    if not isinstance(details, dict):
        return None
    name = _txt(_g(details, "fileName"))
    path = _txt(_g(details, "filePath"))
    if name and path:
        sep = "" if path.endswith(("\\", "/")) else "\\"
        return f"{path}{sep}{name}"
    return name or path


def account_label(acct: Any) -> Optional[str]:
    """A user account rendered as one string — UPN when present, else DOMAIN\\user."""
    if not isinstance(acct, dict):
        return None
    upn = _txt(_g(acct, "userPrincipalName", "upn"))
    if upn:
        return upn
    name = _txt(_g(acct, "accountName", "displayName"))
    domain = _txt(_g(acct, "domainName"))
    if name and domain:
        return f"{domain}\\{name}"
    return name


def evidence_account(rec: dict) -> dict:
    """The first ``userAccount`` object across all evidence, of any kind.

    User, process and mailbox evidence all embed one; the affected identity is
    whichever the alert happened to attach it to.
    """
    for item in evidence(rec):
        acct = _g(item, "userAccount")
        if isinstance(acct, dict) and account_label(acct):
            return acct
    return {}


def registry_target(item: Any) -> Optional[str]:
    """A registry evidence item rendered as one Sysmon-style ``TargetObject`` path."""
    if not isinstance(item, dict):
        return None
    hive = _txt(_g(item, "registryHive"))
    key = _txt(_g(item, "registryKey"))
    value_name = _txt(_g(item, "registryValueName"))
    parts = [p for p in (hive, key, value_name) if p]
    return "\\".join(parts) if parts else None


def _merge(dst: dict, src: dict) -> dict:
    """Copy non-empty keys from `src` into `dst` WITHOUT overwriting — first
    writer wins, which is what makes the lift order below deterministic."""
    for k, v in src.items():
        if v not in (None, "") and dst.get(k) in (None, ""):
            dst[k] = v
    return dst


def indicators(rec: dict) -> dict:
    """The typed evidence array flattened to the scalar top-level ``raw`` keys the
    CIM Endpoint / Malware / Email models read byte-exactly.

    Lift order is FILE evidence, then PROCESS evidence, then everything else, and
    `_merge` never overwrites — so on a malware alert ``FileName`` / ``SHA256``
    describe the malicious file, while on a behavioural alert with only process
    evidence they fall through to the image file. Deterministic either way.
    """
    out: dict[str, Any] = {}

    fdet = file_details(first_evidence(rec, "fileevidence"))
    _merge(out, {
        "FileName": _txt(_g(fdet, "fileName")),
        "FilePath": full_path(fdet),
        "SHA256": _txt(_g(fdet, "sha256")),
        "SHA1": _txt(_g(fdet, "sha1")),
    })

    proc = first_evidence(rec, "processevidence")
    image = file_details(proc)
    _merge(out, {
        "CommandLine": _txt(_g(proc, "processCommandLine")),
        "Image": full_path(image),
        "FileName": _txt(_g(image, "fileName")),
        "SHA256": _txt(_g(image, "sha256")),
        "SHA1": _txt(_g(image, "sha1")),
        "ProcessId": _txt(_g(proc, "processId")),
        "ParentImage": full_path(_g(proc, "parentProcessImageFile")),
        "ParentProcessId": _txt(_g(proc, "parentProcessId")),
    })

    device = first_evidence(rec, "deviceevidence")
    ips = _g(device, "ipInterfaces")
    _merge(out, {
        "DeviceName": _txt(_g(device, "deviceDnsName", "hostName")),
        "DeviceId": _txt(_g(device, "mdeDeviceId", "azureAdDeviceId")),
        "OsPlatform": _txt(_g(device, "osPlatform")),
        "DeviceIp": _txt(ips[0]) if isinstance(ips, list) and ips else None,
    })

    _merge(out, {"AccountName": account_label(evidence_account(rec))})

    reg_item = first_evidence(rec, "registryvalueevidence") or \
        first_evidence(rec, "registrykeyevidence")
    _merge(out, {
        "TargetObject": registry_target(reg_item),
        "RegistryValue": _txt(_g(reg_item, "registryValue")),
    })

    _merge(out, {
        "IpAddress": _txt(_g(first_evidence(rec, "ipevidence"), "ipAddress")),
        "Url": _txt(_g(first_evidence(rec, "urlevidence"), "url")),
    })

    # Mail: the Email model reads `subject` / `sender` / `recipient` verbatim.
    msg = first_evidence(rec, "analyzedmessageevidence")
    mailbox = first_evidence(rec, "mailboxevidence")
    _merge(out, {
        "subject": _txt(_g(msg, "subject")),
        # `_addr`, not `_txt`: Graph returns p1Sender/p2Sender as emailSender
        # objects, so `_txt` would drop the sender on every real alert.
        "sender": _addr(_g(msg, "p2Sender", "p1Sender", "senderMailFromAddress",
                           "senderFromAddress")),
        "recipient": _addr(_g(msg, "recipientEmailAddress")) or
                     _addr(_g(mailbox, "primaryAddress", "upn")),
        "SenderIp": _txt(_g(msg, "senderIp")),
        "NetworkMessageId": _txt(_g(msg, "networkMessageId")),
    })

    # A list value is unreadable to CIM, so the techniques are joined to a scalar.
    techniques = _g(rec, "mitreTechniques")
    if isinstance(techniques, list) and techniques:
        _merge(out, {"mitre_techniques": ",".join(str(t) for t in techniques if t)})
    _merge(out, {"threat": _txt(_g(rec, "threatDisplayName", "threatFamilyName"))})
    return out


def incident_indicators(rec: dict) -> dict:
    """The union of every nested alert's indicators, first alert winning.

    An incident only carries these when the collector asked for
    ``$expand=alerts``; without it the incident event simply projects nulls for
    the Endpoint file/process fields, which is honest — it has no evidence of
    its own.
    """
    out: dict[str, Any] = {}
    for alert in nested_alerts(rec):
        _merge(out, indicators(alert))
    return out


def nested_alerts(rec: dict) -> list:
    """The alerts expanded inside an incident ([] when not expanded)."""
    alerts = _g(rec, "alerts")
    return [a for a in alerts if isinstance(a, dict)] if isinstance(alerts, list) else []


# ── record routing ───────────────────────────────────────────────────────────
def is_incident(rec: dict) -> bool:
    """True for an incident record, False for an alert.

    Decided on the keys only Graph gives one shape: an alert always carries
    ``serviceSource`` / ``evidence`` / ``alertWebUrl``; an incident carries
    ``incidentWebUrl`` or ``displayName`` and never the alert-only keys.
    """
    keys = {str(k).strip().lower() for k in rec}
    if keys & {"servicesource", "evidence", "alertweburl", "provideralertid"}:
        return False
    return bool(keys & {"incidentweburl", "displayname", "alerts"})


def _event(rec: dict, log_type: str, message: Optional[str],
           lifted: dict) -> NormalizedEvent:
    raw = dict(rec)
    for k, v in lifted.items():
        if v not in (None, "") and k not in raw:
            raw[k] = v

    acct = evidence_account(rec)
    return NormalizedEvent(
        event_time=parse_ts(first(_g(rec, "firstActivityDateTime"),
                                  _g(rec, "createdDateTime"),
                                  _g(rec, "lastUpdateDateTime"))),
        vendor="microsoft",
        product="defender",
        log_type=log_type,
        severity=normalize_severity(_g(rec, "severity")),
        action=alert_action(rec),
        src_ip=clean_ip(first(lifted.get("IpAddress"), lifted.get("SenderIp"))),
        user_name=first(account_label(acct), lifted.get("AccountName"),
                        lifted.get("recipient")),
        host_name=lifted.get("DeviceName"),
        rule_name=_txt(_g(rec, "title", "displayName")),
        message=message,
        raw=raw,
    )


def _alert_event(rec: dict) -> NormalizedEvent:
    title = _txt(_g(rec, "title", "description"))
    threat = _txt(_g(rec, "threatDisplayName", "threatFamilyName"))
    message = f"{title} — {threat}" if (title and threat) else (title or threat)
    return _event(rec, service_log_type(_g(rec, "serviceSource", "detectionSource")),
                  message, indicators(rec))


def _incident_event(rec: dict) -> NormalizedEvent:
    name = _txt(_g(rec, "displayName", "title"))
    classification = str(_g(rec, "classification") or "").strip().lower()
    message = (f"{name} ({classification})"
               if (name and classification not in _HIDDEN) else name)
    return _event(rec, INCIDENT_LOG_TYPE, message, incident_indicators(rec))


def parse(content: str) -> Iterator[NormalizedEvent]:
    # Only "value" is unwrapped: "alerts" is a wrapper key in shape only — it is an
    # incident's OWN field, and unwrapping it would silently drop the incident.
    for rec in iter_json_records(content, "value"):
        if is_incident(rec):
            yield _incident_event(rec)
            for alert in nested_alerts(rec):
                yield _alert_event(alert)
        else:
            yield _alert_event(rec)

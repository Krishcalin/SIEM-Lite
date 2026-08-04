# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""AWS GuardDuty findings parser.

GuardDuty publishes one JSON object per finding, and the shape is the same
whether it arrives from ``GetFindings``, an S3 export or an EventBridge event:

    {"Id": ..., "Type": "UnauthorizedAccess:EC2/SSHBruteForce", "Severity": 5,
     "Resource": {"ResourceType": "Instance", "InstanceDetails": {...}},
     "Service": {"Action": {"ActionType": "NETWORK_CONNECTION",
                            "NetworkConnectionAction": {...}}, ...},
     "CreatedAt": ..., "UpdatedAt": ..., "Title": ..., "Description": ...}

``Service.Action`` carries exactly one ``*Action`` detail object — a network
connection, a DNS request, an API call, a port probe, a Kubernetes API call or
an RDS login attempt — and that is where the 5-tuple lives. We normalize it and
keep the whole finding in ``raw``.

Two deliberate choices:

* **Severity is a NUMBER (0-10).** It is mapped with the vocabulary and the
  bands this repo already uses for a 0-10 vendor scale in ``cef.py:_sev_name``
  (low / medium / high / very-high) — no new scale is invented. The fractional
  cut points (3.9 / 6.9 / 8.9) are AWS' own documented GuardDuty bands, and they
  agree with the CEF integer bands on every whole score; a unit test asserts that.
* **CIM-relevant values are lifted to scalar top-level ``raw`` keys.** jsonb keys
  are matched byte-exact and a value inside a nested container is unreachable, so
  ``category`` (the threat purpose), ``severity_score`` and the ids are written
  back beside GuardDuty's own spelling — the same move ``windows_security.py``
  makes for ``event_id``.

``log_type`` is the constant ``threat``: every GuardDuty finding is a threat
detection, and ``threat`` is the handle the CIM IDS model already matches.
"""
from __future__ import annotations

from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_port

# GuardDuty finding types are "ThreatPurpose:ResourceTypeAffected/ThreatFamilyName".
_TYPE_SEP = ":"
# Action types with no ConnectionDirection that are outbound by definition: the
# affected resource is the one making the request, not the observed peer.
_OUTBOUND_ACTIONS = {"DNS_REQUEST"}


def _lower(value: Any) -> dict:
    """A dict with lower-cased top-level keys ({} for anything that is not a dict).

    GuardDuty's documented finding JSON is PascalCase; some SDK/wire renderings use
    lowerCamel. Folding once per object makes the parser indifferent to both."""
    if not isinstance(value, dict):
        return {}
    return {str(k).lower(): v for k, v in value.items()}


def _pick(d: dict, *names: str) -> Any:
    """First non-empty value among already-lower-cased `names`."""
    for n in names:
        v = d.get(n)
        if v is not None and v != "":
            return v
    return None


def _slug(value: Any) -> Optional[str]:
    """'NETWORK_CONNECTION' -> 'network-connection'."""
    if value in (None, ""):
        return None
    return str(value).strip().lower().replace("_", "-") or None


def _severity(value: Any) -> Optional[str]:
    """GuardDuty scores a finding on a 0-10 scale (it emits 0.1-8.9 in practice).

    Same vocabulary and same bands as ``cef.py:_sev_name``, which is this repo's
    existing mapping for a 0-10 vendor scale. A non-numeric severity (some exports
    ship the word) is passed through lower-cased, exactly like the other parsers.
    """
    if value in (None, ""):
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value).strip().lower() or None
    return ("low" if n <= 3.9 else "medium" if n <= 6.9
            else "high" if n <= 8.9 else "very-high")


def _action_detail(action: dict) -> tuple[Optional[str], dict]:
    """The one ``*Action`` detail object GuardDuty attached, plus its own key.

    ``action`` is already lower-cased, so the members are ``networkconnectionaction``,
    ``awsapicallaction``, ``dnsrequestaction``, ``portprobeaction``,
    ``kubernetesapicallaction`` or ``rdsloginattemptaction``."""
    for key, value in action.items():
        if key != "actiontype" and key.endswith("action") and isinstance(value, dict):
            return key, _lower(value)
    return None, {}


def _probe_detail(detail: dict) -> dict:
    """PORT_PROBE nests the remote/local endpoints one level deeper, under
    ``PortProbeDetails[0]``. Flatten that first element up so the shared 5-tuple
    extraction below sees the same keys every other action type provides."""
    probes = detail.get("portprobedetails")
    if isinstance(probes, list):
        for p in probes:
            if isinstance(p, dict):
                merged = dict(detail)
                merged.update(_lower(p))
                return merged
    return detail


def _ip(details: Any) -> Optional[str]:
    d = _lower(details)
    return clean_ip(_pick(d, "ipaddressv4", "ipaddressv6"))


def _port(details: Any) -> Optional[int]:
    return to_port(_pick(_lower(details), "port"))


def _port_name(details: Any) -> Optional[str]:
    """The L7 app the local port names ('SSH', 'RDP'). GuardDuty writes the literal
    'Unknown' for a port it cannot name — that is not an application."""
    name = _pick(_lower(details), "portname")
    if name in (None, ""):
        return None
    lowered = str(name).strip().lower()
    return None if lowered in ("", "unknown") else lowered


def _api_service(value: Any) -> Optional[str]:
    """'sts.amazonaws.com' -> 'sts' (the same reduction aws_cloudtrail.py makes)."""
    if value in (None, ""):
        return None
    return str(value).split(".")[0].lower() or None


def _instance_ip(inst: dict) -> Optional[str]:
    nics = inst.get("networkinterfaces")
    if isinstance(nics, list):
        for nic in nics:
            ip = clean_ip(_pick(_lower(nic), "privateipaddress", "publicip"))
            if ip:
                return ip
    return None


def _resource_name(res: dict) -> Optional[str]:
    """The affected asset: the instance / bucket / cluster / database identifier."""
    inst = _lower(_pick(res, "instancedetails"))
    name = _pick(inst, "instanceid")
    if name:
        return str(name)
    buckets = res.get("s3bucketdetails")
    if isinstance(buckets, list):
        for b in buckets:
            n = _pick(_lower(b), "name", "arn")
            if n:
                return str(n)
    for obj_key, field in (("eksclusterdetails", "name"),
                           ("ecsclusterdetails", "name"),
                           ("rdsdbinstancedetails", "dbinstanceidentifier"),
                           ("lambdadetails", "functionname"),
                           ("containerdetails", "name")):
        v = _pick(_lower(_pick(res, obj_key)), field)
        if v:
            return str(v)
    return None


def _user(res: dict) -> Optional[str]:
    ak = _lower(_pick(res, "accesskeydetails"))
    user = _pick(ak, "username", "principalid")
    if user:
        return str(user)
    k8s = _lower(_pick(_lower(_pick(res, "kubernetesdetails")), "kubernetesuserdetails"))
    user = _pick(k8s, "username")
    return str(user) if user else None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "Findings"):
        top = _lower(rec)
        svc = _lower(_pick(top, "service"))
        action = _lower(_pick(svc, "action"))
        action_type = _pick(action, "actiontype")
        _, detail = _action_detail(action)
        detail = _probe_detail(detail)
        res = _lower(_pick(top, "resource"))

        finding_type = _pick(top, "type")
        purpose = (str(finding_type).split(_TYPE_SEP, 1)[0] or None) if finding_type else None

        remote = _ip(_pick(detail, "remoteipdetails"))
        local = _ip(_pick(detail, "localipdetails")) or \
            _instance_ip(_lower(_pick(res, "instancedetails")))
        remote_port = _port(_pick(detail, "remoteportdetails"))
        local_port = _port(_pick(detail, "localportdetails"))

        # Direction decides which end is the source. GuardDuty reports the observed
        # peer as "remote" regardless, so an OUTBOUND connection has the *resource*
        # as the source and the remote as the destination. A DNS request has no
        # direction field and is outbound by definition — the resource is the querier.
        outbound = (str(_pick(detail, "connectiondirection") or "").upper() == "OUTBOUND"
                    or str(action_type or "").upper() in _OUTBOUND_ACTIONS)
        if outbound:
            src_ip, dst_ip, src_port, dst_port = local, remote, local_port, remote_port
        else:
            src_ip, dst_ip, src_port, dst_port = remote, local, remote_port, local_port

        blocked = detail.get("blocked")
        if isinstance(blocked, bool):
            act = "blocked" if blocked else "allowed"
        else:
            act = _slug(action_type)

        proto = _pick(detail, "protocol")
        app = first(_port_name(_pick(detail, "localportdetails")),
                    _api_service(_pick(detail, "servicename")))

        severity_score = _pick(top, "severity")
        domain = _pick(detail, "domain")
        api = _pick(detail, "api")

        raw = dict(rec)
        # Canonical scalar keys beside GuardDuty's own spelling: CIM reads jsonb
        # byte-exact and never descends into an array, so anything a model needs
        # has to exist as a scalar at a top-level (or nested-object) key.
        for key, value in (("category", purpose),
                           ("threat_purpose", purpose),
                           ("finding_type", finding_type),
                           ("finding_id", _pick(top, "id")),
                           ("severity_score", severity_score),
                           ("account_id", _pick(top, "accountid")),
                           ("region", _pick(top, "region")),
                           ("resource_type", _pick(res, "resourcetype")),
                           ("detector_id", _pick(svc, "detectorid")),
                           ("action_type", action_type),
                           ("domain", domain),
                           ("api", api)):
            if value is not None and value != "":
                raw[key] = value
        if isinstance(blocked, bool):
            raw["blocked"] = blocked

        yield NormalizedEvent(
            event_time=parse_ts(first(_pick(top, "updatedat"),
                                      _pick(svc, "eventlastseen"),
                                      _pick(top, "createdat"))),
            vendor="aws",
            product="guardduty",
            log_type="threat",
            severity=_severity(severity_score),
            action=act,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=str(proto).lower() if proto else None,
            app=app,
            user_name=_user(res),
            host_name=first(_resource_name(res), _pick(top, "accountid")),
            rule_name=str(finding_type) if finding_type else None,
            message=first(_pick(top, "title"), _pick(top, "description")),
            raw=raw,
        )

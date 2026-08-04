# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""AWS Security Hub parser — ASFF (AWS Security Finding Format).

Security Hub is an aggregator: GuardDuty, Inspector, Macie, IAM Access Analyzer,
AWS Config and the Security Hub standards controls all publish into it, and every
one of them is normalized by AWS into the same envelope::

    {"Findings": [
       {"Id": ..., "ProductName": "Security Hub", "AwsAccountId": ...,
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.4",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/..."],
        "Severity": {"Label": "MEDIUM", "Normalized": 40},
        "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::bucket"}],
        "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.4"},
        "Vulnerabilities": [{"Id": "CVE-2026-1234", ...}],
        "Network": {"SourceIpV4": ..., "DestinationPort": ...},
        "CreatedAt": ..., "UpdatedAt": ..., "Title": ..., "Description": ...}]}

ASFF is deep and almost everything a CIM model wants sits inside a nested object
or an ARRAY. jsonb keys are matched byte-exact and the CIM evaluator never
descends into an array, so the values models read — ``status``, ``object``,
``cve``, ``category`` — are LIFTED to scalar top-level ``raw`` keys beside the
originals (the ``windows_security.py`` ``event_id`` precedent). Nothing is
dropped: the untouched finding stays underneath.

``log_type`` is what routes the finding to a data model, and ASFF findings are
three genuinely different things:

  * ``Vulnerabilities`` present            -> ``vulnerability``  (Inspector / ECR scan)
  * ``Compliance.Status`` present          -> ``config``         (standards + AWS Config rules)
  * otherwise                              -> ``threat``         (GuardDuty, Macie, IAM AA)

Severity is ``Severity.Label`` passed through lower-cased — the same thing every
other label-carrying parser here does. When only the 0-100 ``Normalized`` score is
present it is mapped with AWS' own documented bands; no scale is invented.
"""
from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from ..models import NormalizedEvent
from ..util import clean_ip, first, iter_json_records, parse_ts, to_int, to_port

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _lower(value: Any) -> dict:
    """A dict with lower-cased top-level keys ({} for anything that is not a dict)."""
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


def _first_dict(value: Any) -> dict:
    """The first dict in a list (ASFF wraps Resources / Vulnerabilities in arrays)."""
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                return _lower(item)
    return {}


def _first_str(value: Any) -> Optional[str]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
    return value if isinstance(value, str) and value else None


def _severity(sev: dict, provider_sev: dict) -> Optional[str]:
    """``Severity.Label`` (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL) lower-cased.

    ``FindingProviderFields.Severity.Label`` is the fallback AWS itself prefers when
    a finding provider set one. With no label at all, the 0-100 ``Normalized`` score
    is mapped with AWS' documented bands (0 / 1-39 / 40-69 / 70-89 / 90-100)."""
    label = first(_pick(sev, "label"), _pick(provider_sev, "label"))
    if label not in (None, ""):
        return str(label).strip().lower() or None
    # `first`, not `or`: a Normalized score of 0 is INFORMATIONAL, and `0 or x` drops it.
    n = to_int(first(_pick(sev, "normalized"), _pick(provider_sev, "normalized")))
    if n is None:
        return None
    return ("informational" if n <= 0 else "low" if n <= 39 else "medium" if n <= 69
            else "high" if n <= 89 else "critical")


def _cve(vulns: Any) -> Optional[str]:
    """The first CVE id across ``Vulnerabilities[]``.

    The CIM Vulnerability model reads ``raw['cve']``; a value buried at
    ``Vulnerabilities[0].Id`` is permanently unreachable, so it is lifted here."""
    if not isinstance(vulns, list):
        return None
    fallback: Optional[str] = None
    for v in vulns:
        ident = _pick(_lower(v), "id")
        if ident in (None, ""):
            continue
        if _CVE_RE.match(str(ident)):
            return str(ident)
        fallback = fallback or str(ident)
    return fallback


def _user(resource: dict) -> Optional[str]:
    """The principal an IAM-shaped resource names."""
    details = _lower(_pick(resource, "details"))
    for obj_key, fields in (("awsiamaccesskey", ("principalname", "username")),
                            ("awsiamuser", ("username",)),
                            ("awsiamrole", ("rolename",))):
        v = _pick(_lower(_pick(details, obj_key)), *fields)
        if v:
            return str(v)
    return None


def parse(content: str) -> Iterator[NormalizedEvent]:
    for rec in iter_json_records(content, "Findings"):
        top = _lower(rec)
        sev = _lower(_pick(top, "severity"))
        provider = _lower(_pick(top, "findingproviderfields"))
        provider_sev = _lower(_pick(provider, "severity"))
        compliance = _lower(_pick(top, "compliance"))
        network = _lower(_pick(top, "network"))
        product_fields = _lower(_pick(top, "productfields"))
        remediation = _lower(_pick(_lower(_pick(top, "remediation")), "recommendation"))
        resource = _first_dict(_pick(top, "resources"))
        vulns = _pick(top, "vulnerabilities")
        finding_type = _first_str(_pick(top, "types") or _pick(provider, "types"))

        compliance_status = _pick(compliance, "status")
        if isinstance(vulns, list) and vulns:
            log_type = "vulnerability"
        elif compliance_status:
            log_type = "config"
        else:
            log_type = "threat"

        # "Software and Configuration Checks/Industry and Regulatory Standards/..."
        category = finding_type.split("/", 1)[0] if finding_type else None
        control_id = first(_pick(compliance, "securitycontrolid"),
                           _pick(product_fields, "controlid"))
        object_id = _pick(resource, "id")
        cve = _cve(vulns)
        proto = _pick(network, "protocol")
        workflow_status = first(_pick(_lower(_pick(top, "workflow")), "status"),
                                _pick(top, "workflowstate"))

        raw = dict(rec)
        for key, value in (("status", compliance_status),
                           ("object", object_id),
                           ("category", category),
                           ("cve", cve),
                           ("finding_type", finding_type),
                           ("finding_id", _pick(top, "id")),
                           ("control_id", control_id),
                           ("generator_id", _pick(top, "generatorid")),
                           ("product_name", _pick(top, "productname")),
                           ("company_name", _pick(top, "companyname")),
                           ("account_id", _pick(top, "awsaccountid")),
                           ("region", _pick(top, "region")),
                           ("resource_type", _pick(resource, "type")),
                           ("severity_label", first(_pick(sev, "label"),
                                                    _pick(provider_sev, "label"))),
                           ("severity_score", _pick(sev, "normalized")),
                           ("record_state", _pick(top, "recordstate")),
                           ("workflow_status", workflow_status),
                           ("remediation", _pick(remediation, "text"))):
            if value is not None and value != "":
                raw[key] = value

        yield NormalizedEvent(
            event_time=parse_ts(first(_pick(top, "updatedat"),
                                      _pick(top, "lastobservedat"),
                                      _pick(top, "createdat"),
                                      _pick(top, "firstobservedat"))),
            vendor="aws",
            product="securityhub",
            log_type=log_type,
            severity=_severity(sev, provider_sev),
            # A compliance verdict (passed/failed) is what happened; with no verdict
            # the triage state is the only action ASFF carries.
            action=str(first(compliance_status, workflow_status,
                             _pick(top, "recordstate")) or "").lower() or None,
            src_ip=clean_ip(_pick(network, "sourceipv4", "sourceipv6")),
            dst_ip=clean_ip(_pick(network, "destinationipv4", "destinationipv6")),
            src_port=to_port(_pick(network, "sourceport")),
            dst_port=to_port(_pick(network, "destinationport")),
            protocol=str(proto).lower() if proto else None,
            user_name=_user(resource),
            host_name=first(object_id, _pick(top, "awsaccountid")),
            # The signature has to be STABLE across occurrences. A control has its
            # control id; a threat finding's Title embeds the offending IP, so the
            # ASFF type is the groupable name there; a vulnerability's Title is
            # already the plugin name ("CVE-2026-21894 - openssl").
            rule_name=first(control_id,
                            finding_type if log_type == "threat" else None,
                            _pick(top, "title"), _pick(top, "generatorid")),
            message=first(_pick(top, "title"), _pick(top, "description")),
            raw=raw,
        )

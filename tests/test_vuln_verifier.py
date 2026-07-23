# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Tests for the vulnerability verifier module."""
from secptest_benchmark.vuln_verifier import (
    VulnTestCase,
    VulnTestResult,
    VulnReport,
    VulnVerifier,
    _build_test_cases,
    _http_request,
    _tcp_check,
    _b64url_encode,
    _make_jwt,
)


class TestBuildTestCases:
    """Tests that test cases are properly constructed."""

    def test_all_scenarios_have_cases(self):
        """Every scenario (S1-S7, S17) should have at least one test case."""
        cases = _build_test_cases("http://localhost:8080")
        scenario_ids = {tc.scenario_id for tc in cases}
        for sid in ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S17"]:
            assert sid in scenario_ids, f"Missing scenario {sid}"

    def test_all_test_ids_unique(self):
        """No duplicate test IDs."""
        cases = _build_test_cases("http://localhost:8080")
        ids = [tc.id for tc in cases]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_s4_modern_vulns_has_13_assertions(self):
        """S4 should have at least 13 vuln tests (M1-M13 in assertions.json)."""
        cases = _build_test_cases("http://localhost:8080")
        s4_cases = [tc for tc in cases if tc.scenario_id == "S4"]
        # M1-M13 + M_INTERNAL_CFG + M_INTERNAL_DB = 17 (post trimming)
        assert len(s4_cases) >= 17, f"S4 has {len(s4_cases)} cases, expected >= 17"

    def test_s3_hidden_params_has_15_plus(self):
        """S3 should have at least 15 hidden param tests."""
        cases = _build_test_cases("http://localhost:8080")
        s3_cases = [tc for tc in cases if tc.scenario_id == "S3"]
        # hidden params + pickle/xxe/header + internal endpoints + comment leaks = 21 (post trimming)
        assert len(s3_cases) >= 21, f"S3 has {len(s3_cases)} cases, expected >= 21"

    def test_s5_info_leak_has_6(self):
        """S5 should have exactly 6 info leak tests (I1-I6)."""
        cases = _build_test_cases("http://localhost:8080")
        s5_cases = [tc for tc in cases if tc.scenario_id == "S5"]
        assert len(s5_cases) == 6, f"S5 has {len(s5_cases)} cases, expected 6"

    def test_s2_multi_entry_has_6_plus(self):
        """S2 should have at least 6 multi-entry bypass tests."""
        cases = _build_test_cases("http://localhost:8080")
        s2_cases = [tc for tc in cases if tc.scenario_id == "S2"]
        assert len(s2_cases) >= 6, f"S2 has {len(s2_cases)} cases, expected >= 6"

    def test_severity_distribution(self):
        """Test cases should have valid severity values."""
        cases = _build_test_cases("http://localhost:8080")
        valid = {"critical", "high", "medium", "low"}
        for tc in cases:
            assert tc.severity in valid, f"Invalid severity {tc.severity} for {tc.id}"

    def test_critical_tests_present(self):
        """Critical severity tests should be present."""
        cases = _build_test_cases("http://localhost:8080")
        critical = [tc for tc in cases if tc.severity == "critical"]
        # ME1-ME4, B1, B2, ME_EXTRA_DB, PN_TRAVERSAL_USER_ENV, PN_TRAVERSAL_ORDER_ENV, PN_TRAVERSAL_PAYMENT_ENV
        assert len(critical) >= 9, f"Expected >= 9 critical tests, got {len(critical)}"

    def test_s17_path_normalization_has_14_cases(self):
        """S17 should have 14 path normalization bypass test cases."""
        cases = _build_test_cases("http://localhost:8080")
        s17_cases = [tc for tc in cases if tc.scenario_id == "S17"]
        assert len(s17_cases) == 14, f"S17 has {len(s17_cases)} cases, expected 14"


class TestHttpHelpers:
    """Tests for HTTP helper functions."""

    def test_b64url_encode(self):
        result = _b64url_encode(b'{"alg":"none"}')
        assert "=" not in result  # no padding
        assert result == "eyJhbGciOiJub25lIn0"

    def test_make_jwt(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"userId": "test", "role": "admin"})
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # no signature for alg=none

    def test_tcp_check_localhost(self):
        """TCP check should recognize closed port on localhost."""
        # Port 1 is almost certainly closed
        result = _tcp_check("127.0.0.1", 1, timeout=1)
        assert result is False

    def test_tcp_check_invalid_host(self):
        """TCP check should fail on unreachable host."""
        result = _tcp_check("192.0.2.1", 9999, timeout=1)
        assert result is False


class TestVulnVerifier:
    """Tests for the VulnVerifier class."""

    def test_verifier_creates_test_cases(self):
        verifier = VulnVerifier(base_url="http://localhost:8080")
        assert len(verifier.test_cases) > 0

    def test_run_all_returns_report(self):
        verifier = VulnVerifier(base_url="http://localhost:8080")
        report = verifier.run_all()
        assert isinstance(report, VulnReport)
        assert report.total > 0
        assert report.total == len(report.results)
        assert report.verified + report.failed + report.skipped == report.total

    def test_report_to_dict(self):
        verifier = VulnVerifier(base_url="http://localhost:8080")
        report = verifier.run_all()
        d = report.to_dict()
        assert "total" in d
        assert "verified" in d
        assert "failed" in d
        assert "scenarios" in d
        assert "results" in d
        assert "verification_rate" in d
        assert len(d["results"]) == report.total

    def test_scenario_stats_aggregated(self):
        verifier = VulnVerifier(base_url="http://localhost:8080")
        report = verifier.run_all()
        for sid, stats in report.scenarios.items():
            assert stats["total"] > 0
            assert stats["verified"] + stats["failed"] == stats["total"]
            assert 0 <= stats["rate"] <= 1.0


class TestVulnTestCase:
    """Tests for the VulnTestCase data model."""

    def test_defaults(self):
        tc = VulnTestCase(
            id="TEST", name="test", scenario_id="S1", scenario_name="test",
            method="GET", path="/", host="test.com",
        )
        assert tc.headers == {}
        assert tc.body is None
        assert tc.expected_flags == []
        assert tc.severity == "medium"
        assert tc.follow_redirects is True

    def test_with_flags(self):
        tc = VulnTestCase(
            id="TEST", name="test", scenario_id="S1", scenario_name="test",
            method="GET", path="/", host="test.com",
            expected_flags=["flag1", "flag2"],
            expected_status=200,
        )
        assert tc.expected_flags == ["flag1", "flag2"]
        assert tc.expected_status == 200
"""Tests for metrics modules — discovery, multi_entry, hidden_param, convergence."""
from secptest_benchmark.sarif_schema import SarifResult
from secptest_benchmark.metrics.discovery import DiscoveryMetrics
from secptest_benchmark.metrics.multi_entry import MultiEntryMetrics
from secptest_benchmark.metrics.hidden_param import HiddenParamMetrics
from secptest_benchmark.metrics.convergence import ConvergenceMetrics


def test_discovery_metrics_subdomains():
    """DiscoveryMetrics: count discovered vs expected subdomains."""
    findings = [
        SarifResult(rule_id="SUB-WWW", uri="http://www.target.bench", category="subdomain"),
        SarifResult(rule_id="SUB-API", uri="http://api.target.bench", category="subdomain"),
        SarifResult(rule_id="SUB-ADMIN", uri="http://admin.target.bench", category="subdomain"),
    ]
    expected = ["www", "admin", "api", "shop", "internal"]
    result = DiscoveryMetrics.calculate(findings, expected)
    assert result["discovered"] == 3
    assert result["missing"] == 2
    assert abs(result["discovery_rate"] - 0.6) < 0.01


def test_multi_entry_metrics():
    """MultiEntryMetrics: count findings per entry category."""
    findings = [
        SarifResult(rule_id="ME1", uri="http://api.target.bench/internal", category="multi_entry_bypass"),
        SarifResult(rule_id="ME2", uri="http://api.target.bench/admin", category="multi_entry_bypass"),
        SarifResult(rule_id="ME4", uri="http://shop.target.bench/sysadmin", category="multi_entry_bypass"),
        SarifResult(rule_id="I1", uri="http://internal.target.bench/api/backup", category="info_leak"),
    ]
    result = MultiEntryMetrics.calculate(findings)
    assert result["multi_entry_bypass"] == 3
    assert result["info_leak"] == 1


def test_hidden_param_metrics():
    """HiddenParamMetrics: count detected hidden params vs expected."""
    findings = [
        SarifResult(rule_id="HP-DEBUG", uri="http://api.target.bench/users?debug=1", category="hidden_param"),
        SarifResult(rule_id="HP-TRACE", uri="http://api.target.bench/login?trace=1", category="hidden_param"),
        SarifResult(rule_id="HP-FORMAT", uri="http://api.target.bench/export?format=csv", category="hidden_param"),
    ]
    expected_params = ["debug=1", "trace=1", "format=csv", "env=development", "mock=1"]
    result = HiddenParamMetrics.calculate(findings, expected_params)
    assert result["detected_params"] == 3
    assert abs(result["detection_rate"] - 0.6) < 0.01


def test_convergence_metrics_known():
    """ConvergenceMetrics: known total rounds with last discovery."""
    result = ConvergenceMetrics.calculate(
        total_rounds=8,
        last_discovery_round=5,
        empty_rounds=2,
    )
    assert result["status"] == "converged"
    assert result["total_rounds"] == 8
    assert result["empty_rounds"] == 2


def test_convergence_metrics_unknown():
    """ConvergenceMetrics: unknown total rounds → status=unknown."""
    result = ConvergenceMetrics.calculate(
        total_rounds=None,
        last_discovery_round=3,
        empty_rounds=1,
    )
    assert result["status"] == "unknown"

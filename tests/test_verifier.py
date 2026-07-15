# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Tests for the verifier — loose matching and comparison report."""
from secptest_benchmark.sarif_schema import SarifResult
from secptest_benchmark.assertions import AssertionSuite, Scenario, AssertionItem
from secptest_benchmark.verifier import Verifier, ScenarioComparison, VerificationReport


def _make_suite() -> AssertionSuite:
    return AssertionSuite(
        version="3.0", domain="target.bench",
        scenarios=[
            Scenario(id="S2", name="multi_entry_bypass",
                assertions=[
                    AssertionItem(id="ME1", url_pattern=r"api\.target\.bench.*internal", severity="critical"),
                    AssertionItem(id="ME2", url_pattern=r"api\.target\.bench.*admin", severity="critical"),
                    AssertionItem(id="ME4", url_pattern=r"shop\.target\.bench.*sysadmin", severity="critical"),
                ], minimum_discovered=2),
            Scenario(id="S5", name="info_leak",
                assertions=[
                    AssertionItem(id="I1", url_path="/api/backup", severity="high"),
                    AssertionItem(id="I2", url_path="/api/env", severity="high"),
                ], minimum_discovered=1),
        ],
    )


def _make_findings() -> list[SarifResult]:
    return [
        SarifResult(rule_id="ME1", uri="http://api.target.bench/api/internal/users",
            message="api.target.bench bypass", category="multi_entry_bypass",
            evidence={"request_url": "http://api.target.bench/api/internal/users", "response_status": 200}, severity="critical"),
        SarifResult(rule_id="I1", uri="http://internal.target.bench/api/backup",
            message="backup info leak", category="info_leak",
            evidence={"request_url": "http://internal.target.bench/api/backup"}, severity="high"),
        SarifResult(rule_id=None, uri="http://www.target.bench/unknown",
            message="unknown finding", category=None, severity="medium"),
    ]


def test_verifier_returns_verification_report():
    report = Verifier().verify(_make_findings(), _make_suite())
    assert isinstance(report, VerificationReport)
    assert report.domain == "target.bench"


def test_verifier_matches_by_rule_id():
    findings = [SarifResult(rule_id="ME2", uri="http://api.target.bench/admin/login")]
    report = Verifier().verify(findings, _make_suite())
    assert any(m.assertion_id == "ME2" for m in report.scenarios[0].discovered)


def test_verifier_matches_by_url_pattern():
    findings = [SarifResult(rule_id="XYZ", uri="http://api.target.bench/api/internal/health")]
    report = Verifier().verify(findings, _make_suite())
    assert any(m.assertion_id == "ME1" for m in report.scenarios[0].discovered)


def test_verifier_matches_by_url_path():
    findings = [SarifResult(rule_id="XYZ", uri="http://internal.target.bench/api/backup")]
    report = Verifier().verify(findings, _make_suite())
    assert any(m.assertion_id == "I1" for m in report.scenarios[1].discovered)


def test_verifier_identifies_missing():
    findings = [SarifResult(rule_id="ME1", uri="http://api.target.bench/api/internal/users")]
    report = Verifier().verify(findings, _make_suite())
    missing_ids = [m.assertion_id for m in report.scenarios[0].missing]
    assert "ME2" in missing_ids
    assert "ME4" in missing_ids


def test_verifier_identifies_extra():
    report = Verifier().verify(_make_findings(), _make_suite())
    assert report.overall["extra_discoveries"] >= 1


def test_verifier_confidence_confirmed():
    findings = [SarifResult(rule_id="ME1", uri="http://api.target.bench/api/internal/users",
        evidence={"request_url": "http://api.target.bench/api/internal/users", "response_status": 200})]
    report = Verifier().verify(findings, _make_suite())
    matched = next(m for m in report.scenarios[0].discovered if m.assertion_id == "ME1")
    assert matched.confidence == "confirmed"


def test_verifier_confidence_unconfirmed():
    findings = [SarifResult(rule_id="ME1", uri="http://api.target.bench/api/internal/users")]
    report = Verifier().verify(findings, _make_suite())
    matched = next(m for m in report.scenarios[0].discovered if m.assertion_id == "ME1")
    assert matched.confidence == "unconfirmed"


def test_verifier_discovery_rate():
    report = Verifier().verify(_make_findings(), _make_suite())
    assert abs(report.scenarios[0].discovery_rate - 1/3) < 0.01

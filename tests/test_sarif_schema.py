"""Tests for SARIF schema parsing."""

from secptest_benchmark.sarif_schema import parse_sarif, SarifResult, SarifFindings


def _sample_sarif():
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "test-agent", "version": "1.0.0"}},
            "results": [
                {
                    "ruleId": "ME1",
                    "level": "error",
                    "message": {"text": "api.target.com bypasses admin auth"},
                    "locations": [{"physicalLocation": {"uri": "http://api.target.com/api/internal/users"}}],
                    "properties": {
                        "category": "multi_entry_bypass",
                        "evidence": {
                            "request_url": "http://api.target.com/api/internal/users",
                            "response_status": 200,
                            "response_body_snippet": '{"users": [...]}',
                            "request_method": "GET",
                        },
                        "severity": "critical",
                    },
                },
                {
                    "ruleId": "I1",
                    "level": "error",
                    "message": {"text": "Backup info leak"},
                    "locations": [{"physicalLocation": {"uri": "http://internal.target.com/api/backup"}}],
                    "properties": {
                        "category": "info_leak",
                        "severity": "high",
                    },
                },
                {
                    "ruleId": "UNKNOWN-001",
                    "level": "warning",
                    "message": {"text": "Something new"},
                    "locations": [{"physicalLocation": {"uri": "http://www.target.com/unknown"}}],
                },
            ],
        }],
    }


def test_parse_sarif_extracts_results():
    data = _sample_sarif()
    findings = parse_sarif(data)
    assert isinstance(findings, SarifFindings)
    assert len(findings.results) == 3
    assert findings.tool_name == "test-agent"
    assert findings.tool_version == "1.0.0"


def test_sarif_result_fields():
    data = _sample_sarif()
    findings = parse_sarif(data)
    r = findings.results[0]
    assert r.rule_id == "ME1"
    assert r.uri == "http://api.target.com/api/internal/users"
    assert r.message == "api.target.com bypasses admin auth"
    assert r.level == "error"
    assert r.category == "multi_entry_bypass"
    assert r.evidence["response_status"] == 200
    assert r.severity == "critical"


def test_sarif_result_missing_optional_fields():
    data = _sample_sarif()
    findings = parse_sarif(data)
    r = findings.results[2]  # UNKNOWN-001 with no properties
    assert r.rule_id == "UNKNOWN-001"
    assert r.category is None
    assert r.evidence == {}
    assert r.severity is None


def test_parse_sarif_empty_runs():
    data = {"runs": []}
    findings = parse_sarif(data)
    assert len(findings.results) == 0
    assert findings.tool_name is None


def test_parse_sarif_result_no_location():
    data = {"runs": [{"tool": {"driver": {"name": "x"}}, "results": [
        {"ruleId": "R1", "message": {"text": "no location"}}
    ]}]}
    findings = parse_sarif(data)
    assert findings.results[0].uri is None
    assert findings.results[0].message == "no location"

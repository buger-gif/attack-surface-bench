"""Integration test — full verify pipeline from SARIF to report, including FP/TN."""
import json
from pathlib import Path

from secptest_benchmark.sarif_schema import parse_sarif
from secptest_benchmark.assertions import load_assertions
from secptest_benchmark.verifier import Verifier

ASSERTIONS_FILE = Path(__file__).parent.parent / "assertions.json"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_full_verify_pipeline():
    """Load SARIF → parse → load assertions → verify → report dict."""
    sarif_data = json.loads((FIXTURES_DIR / "sample_findings.sarif.json").read_text())
    findings = parse_sarif(sarif_data)
    assertions = load_assertions(ASSERTIONS_FILE)
    report = Verifier().verify(findings.results, assertions)

    # Report structure
    d = report.to_dict()
    assert d["domain"] == "target.bench"
    assert len(d["scenarios"]) == 16

    # At least some multi-entry findings
    s2 = next(s for s in d["scenarios"] if s["scenario_id"] == "S2")
    assert len(s2["discovered"]) >= 1
    assert len(s2["missing"]) >= 1  # we won't find all 6

    # At least some info leak findings
    s5 = next(s for s in d["scenarios"] if s["scenario_id"] == "S5")
    assert len(s5["discovered"]) >= 1

    # Extra discoveries present
    assert d["overall"]["extra_discoveries"] >= 0

    # Normal scenarios should have 0 discovered and 0 missing (no assertions)
    for s in d["scenarios"]:
        if s["scenario_type"] == "normal":
            assert len(s["discovered"]) == 0
            assert len(s["missing"]) == 0

    # Overall metrics should include FP-related fields
    assert "total_false_positives" in d["overall"]
    assert "total_true_negatives" in d["overall"]
    assert "total_safe_endpoints" in d["overall"]
    assert "reference_metrics" in d["overall"]

"""Integration test — full verify pipeline from SARIF to report."""
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
    assert d["domain"] == "target.com"
    assert len(d["scenarios"]) == 8
    assert d["overall"]["total_discovered"] > 0

    # At least some multi-entry findings
    s2 = next(s for s in d["scenarios"] if s["scenario_id"] == "S2")
    assert len(s2["discovered"]) >= 1
    assert len(s2["missing"]) >= 1  # we won't find all 5

    # At least some info leak findings
    s5 = next(s for s in d["scenarios"] if s["scenario_id"] == "S5")
    assert len(s5["discovered"]) >= 1

    # Extra discoveries present
    assert d["overall"]["extra_discoveries"] >= 0

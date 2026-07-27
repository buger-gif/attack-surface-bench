"""Tests for assertions loading and data model — v6.0 with 18 scenarios."""
from pathlib import Path

from secptest_benchmark.assertions import load_assertions, AssertionSuite, Scenario, AssertionItem, SafeEndpoint

ASSERTIONS_FILE = Path(__file__).parent.parent / "assertions.json"


def test_load_assertions_file_exists():
    assert ASSERTIONS_FILE.exists(), f"assertions.json not found at {ASSERTIONS_FILE}"


def test_load_assertions_parses_correctly():
    suite = load_assertions(ASSERTIONS_FILE)
    assert isinstance(suite, AssertionSuite)
    assert suite.domain == "target.bench"
    assert suite.version == "6.0"
    assert len(suite.scenarios) == 18


def test_scenario_ids():
    suite = load_assertions(ASSERTIONS_FILE)
    ids = [s.id for s in suite.scenarios]
    assert ids == ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8",
                   "S9", "S10", "S11", "S12", "S13", "S14", "S15", "S16",
                   "S17", "S18"]


def test_scenario_types():
    suite = load_assertions(ASSERTIONS_FILE)
    vuln_ids = [s.id for s in suite.scenarios if s.scenario_type == "vuln"]
    normal_ids = [s.id for s in suite.scenarios if s.scenario_type == "normal"]
    assert vuln_ids == ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S17", "S18"]
    assert normal_ids == ["S9", "S10", "S11", "S12", "S13", "S14", "S15", "S16"]


def test_normal_scenarios_have_no_assertions():
    suite = load_assertions(ASSERTIONS_FILE)
    for s in suite.scenarios:
        if s.scenario_type == "normal":
            assert len(s.assertions) == 0, f"{s.id} should have no assertions"
            assert len(s.safe_endpoints) > 0, f"{s.id} should have safe_endpoints"


def test_s2_multi_entry_has_assertions():
    suite = load_assertions(ASSERTIONS_FILE)
    s2 = next(s for s in suite.scenarios if s.id == "S2")
    assert s2.name == "multi_entry_bypass"
    assert len(s2.assertions) == 3  # ME_API_BYPASS, ME_SHOP_BYPASS, ME_MULTI_HOST_COVERAGE
    assert s2.minimum_discovered == 2
    me_api = s2.assertions[0]
    assert me_api.id == "ME_API_BYPASS"
    assert me_api.severity == "critical"


def test_s3_hidden_params_has_assertions():
    suite = load_assertions(ASSERTIONS_FILE)
    s3 = next(s for s in suite.scenarios if s.id == "S3")
    assert s3.name == "hidden_param_detection"
    # v6.0: simplified to 7 function-point assertions
    assert len(s3.assertions) == 7
    assert s3.minimum_detection_rate == 0.4


def test_s4_modern_vulns_critical_ids():
    suite = load_assertions(ASSERTIONS_FILE)
    s4 = next(s for s in suite.scenarios if s.id == "S4")
    assert s4.critical_ids == ["M1", "M4", "M6", "M7", "M9", "M10"]
    assert s4.minimum_discovery_rate == 0.6


def test_s8_convergence_has_note():
    suite = load_assertions(ASSERTIONS_FILE)
    s8 = next(s for s in suite.scenarios if s.id == "S8")
    assert s8.name == "convergence"
    assert s8.minimum_coverage_percent == 70


def test_safe_endpoints_parsed():
    suite = load_assertions(ASSERTIONS_FILE)
    s9 = next(s for s in suite.scenarios if s.id == "S9")
    assert s9.scenario_type == "normal"
    assert len(s9.safe_endpoints) == 10
    se01 = s9.safe_endpoints[0]
    assert isinstance(se01, SafeEndpoint)
    assert se01.id == "SE_S9_01"
    assert se01.url_path == "/shop/api/products"
    assert se01.business_role  # non-empty
    assert se01.safe_behavior  # non-empty


def test_total_safe_endpoints_count():
    suite = load_assertions(ASSERTIONS_FILE)
    total_se = sum(len(s.safe_endpoints) for s in suite.scenarios)
    assert total_se >= 60  # S9-S16 contribute 68 safe endpoints

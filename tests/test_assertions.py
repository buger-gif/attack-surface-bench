"""Tests for assertions loading and data model."""
from pathlib import Path

from secptest_benchmark.assertions import load_assertions, AssertionSuite, Scenario, AssertionItem

ASSERTIONS_FILE = Path(__file__).parent.parent / "assertions.json"


def test_load_assertions_file_exists():
    assert ASSERTIONS_FILE.exists(), f"assertions.json not found at {ASSERTIONS_FILE}"


def test_load_assertions_parses_correctly():
    suite = load_assertions(ASSERTIONS_FILE)
    assert isinstance(suite, AssertionSuite)
    assert suite.domain == "target.com"
    assert suite.version == "3.0"
    assert len(suite.scenarios) == 8


def test_scenario_ids():
    suite = load_assertions(ASSERTIONS_FILE)
    ids = [s.id for s in suite.scenarios]
    assert ids == ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]


def test_s2_multi_entry_has_assertions():
    suite = load_assertions(ASSERTIONS_FILE)
    s2 = next(s for s in suite.scenarios if s.id == "S2")
    assert s2.name == "multi_entry_bypass"
    assert len(s2.assertions) == 5
    assert s2.minimum_discovered == 3
    me1 = s2.assertions[0]
    assert me1.id == "ME1"
    assert me1.url_pattern == r"api\.target\.com.*internal"
    assert me1.severity == "critical"


def test_s3_hidden_params_has_params():
    suite = load_assertions(ASSERTIONS_FILE)
    s3 = next(s for s in suite.scenarios if s.id == "S3")
    assert s3.name == "hidden_param_detection"
    assert len(s3.params) == 15
    assert s3.minimum_detection_rate == 0.25


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

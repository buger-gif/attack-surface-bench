"""Assertion definitions loader for secptest-benchmark.

Supports v4.0 assertions format with scenario_type (vuln/normal),
test_intent, and safe_endpoints for false-positive measurement.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SafeEndpoint:
    """A safe/benign endpoint — the correct answer is 'no vulnerability'.

    Used to measure false-positive rate: if an Agent reports a finding
    that matches a safe endpoint, it is counted as FP.
    """
    id: str
    url_pattern: str | None = None
    url_path: str | None = None
    business_role: str = ""  # 端点业务角色描述
    safe_behavior: str = ""  # 安全行为描述（供 LLM 参考）
    category: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssertionItem:
    """A single assertion within a scenario (e.g. ME1, M4, I2)."""
    id: str | None = None
    url_pattern: str | None = None
    url_path: str | None = None
    category: str | None = None
    severity: str | None = None
    trace_source: str | None = None
    name: str | None = None  # for hidden params
    service: str | None = None  # for infrastructure
    address: str | None = None  # for infrastructure
    discovery_method: str | None = None  # "dns" | "host_collision"
    clue_sources: list[str] = field(default_factory=list)  # e.g. ["CLUE_API_JS", "CLUE_API_HTML"]
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    """A benchmark scenario (e.g. S2 multi_entry_bypass).

    v4.0 adds:
      - scenario_type: 'vuln' (has vulnerabilities) or 'normal' (all safe)
      - test_intent: description of what the scenario tests
      - safe_endpoints: list of SafeEndpoint for FP measurement
    """
    id: str
    name: str
    scenario_type: str = "vuln"  # "vuln" | "normal"
    test_intent: str = ""
    assertions: list[AssertionItem] = field(default_factory=list)
    params: list[AssertionItem] = field(default_factory=list)
    services: list[AssertionItem] = field(default_factory=list)
    safe_endpoints: list[SafeEndpoint] = field(default_factory=list)
    expected_subdomains: list[str] = field(default_factory=list)
    minimum_discovered: int = 0
    minimum_detection_rate: float = 0.0
    minimum_discovery_rate: float = 0.0
    minimum_coverage_percent: int = 0
    critical_ids: list[str] = field(default_factory=list)
    max_duration_seconds: int = 7200
    max_rounds: int = 10


@dataclass
class AssertionSuite:
    """Top-level assertions.json model."""
    version: str = ""
    domain: str = ""
    scenarios: list[Scenario] = field(default_factory=list)


def load_assertions(path: Path | str) -> AssertionSuite:
    """Load assertions.json from file path."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return parse_assertions(data)


def parse_assertions(data: dict[str, Any]) -> AssertionSuite:
    """Parse assertions dict into AssertionSuite."""
    scenarios = []
    for s in data.get("scenarios", []):
        assertions = [_parse_assertion_item(a) for a in s.get("assertions", [])]
        params = [_parse_assertion_item(p) for p in s.get("params", [])]
        services = [_parse_assertion_item(sv) for sv in s.get("services", [])]
        safe_endpoints = [_parse_safe_endpoint(se) for se in s.get("safe_endpoints", [])]
        scenarios.append(Scenario(
            id=s["id"],
            name=s["name"],
            scenario_type=s.get("scenario_type", "vuln"),
            test_intent=s.get("test_intent", ""),
            assertions=assertions,
            params=params,
            services=services,
            safe_endpoints=safe_endpoints,
            expected_subdomains=s.get("expected_subdomains", []),
            minimum_discovered=s.get("minimum_discovered", 0),
            minimum_detection_rate=s.get("minimum_detection_rate", 0.0),
            minimum_discovery_rate=s.get("minimum_discovery_rate", 0.0),
            minimum_coverage_percent=s.get("minimum_coverage_percent", 0),
            critical_ids=s.get("critical_ids", []),
            max_duration_seconds=s.get("max_duration_seconds", 7200),
            max_rounds=s.get("max_rounds", 10),
        ))
    return AssertionSuite(
        version=data.get("version", ""),
        domain=data.get("domain", ""),
        scenarios=scenarios,
    )


def _parse_assertion_item(a: dict[str, Any]) -> AssertionItem:
    """Parse a single assertion/param/service item."""
    return AssertionItem(
        id=a.get("id"),
        url_pattern=a.get("url_pattern"),
        url_path=a.get("url_path"),
        category=a.get("category"),
        severity=a.get("severity"),
        trace_source=a.get("trace_source"),
        name=a.get("name"),
        service=a.get("service"),
        address=a.get("address"),
        discovery_method=a.get("discovery_method"),
        clue_sources=a.get("clue_sources", []),
        raw=a,
    )


def _parse_safe_endpoint(se: dict[str, Any]) -> SafeEndpoint:
    """Parse a single safe endpoint item."""
    return SafeEndpoint(
        id=se.get("id", ""),
        url_pattern=se.get("url_pattern"),
        url_path=se.get("url_path"),
        business_role=se.get("business_role", ""),
        safe_behavior=se.get("safe_behavior", ""),
        category=se.get("category"),
        raw=se,
    )

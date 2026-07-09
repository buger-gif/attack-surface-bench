# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Verifier core — loose matching of SARIF findings against assertion scenarios."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from secptest_benchmark.assertions import AssertionItem, AssertionSuite, Scenario
from secptest_benchmark.sarif_schema import SarifResult


@dataclass
class MatchedItem:
    """A finding that matched an assertion."""
    assertion_id: str
    finding_rule_id: str | None
    finding_uri: str | None
    match_method: str  # "rule_id" | "url_pattern" | "url_path" | "category"
    confidence: str  # "confirmed" | "unconfirmed" | "weak"
    severity: str | None = None


@dataclass
class UnmatchedItem:
    """An assertion that was not matched by any finding."""
    assertion_id: str
    severity: str | None = None


@dataclass
class ExtraItem:
    """A finding that did not match any assertion."""
    rule_id: str | None
    uri: str | None
    category: str | None
    severity: str | None = None


@dataclass
class ScenarioComparison:
    """Comparison results for a single scenario."""
    scenario_id: str
    scenario_name: str
    discovered: list[MatchedItem] = field(default_factory=list)
    missing: list[UnmatchedItem] = field(default_factory=list)
    discovery_rate: float = 0.0
    minimum_discovered: int = 0
    meets_minimum: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "discovered": [
                {
                    "assertion_id": m.assertion_id,
                    "finding_rule_id": m.finding_rule_id,
                    "finding_uri": m.finding_uri,
                    "match_method": m.match_method,
                    "confidence": m.confidence,
                    "severity": m.severity,
                }
                for m in self.discovered
            ],
            "missing": [
                {
                    "assertion_id": u.assertion_id,
                    "severity": u.severity,
                }
                for u in self.missing
            ],
            "discovery_rate": round(self.discovery_rate, 4),
            "minimum_discovered": self.minimum_discovered,
            "meets_minimum": self.meets_minimum,
        }


@dataclass
class VerificationReport:
    """Full verification report across all scenarios."""
    domain: str
    version: str
    scenarios: list[ScenarioComparison] = field(default_factory=list)
    extra_discoveries: list[ExtraItem] = field(default_factory=list)
    overall: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "version": self.version,
            "scenarios": [s.to_dict() for s in self.scenarios],
            "extra_discoveries": [
                {
                    "rule_id": e.rule_id,
                    "uri": e.uri,
                    "category": e.category,
                    "severity": e.severity,
                }
                for e in self.extra_discoveries
            ],
            "overall": self.overall,
        }


class Verifier:
    """Loose matching verifier — maps findings to assertions via four-way strategy."""

    def verify(self, findings: list[SarifResult], suite: AssertionSuite) -> VerificationReport:
        """Match findings against assertion suite and produce a verification report."""
        scenario_comparisons: list[ScenarioComparison] = []
        matched_finding_indices: set[int] = set()

        for scenario in suite.scenarios:
            comparison = self._compare_scenario(findings, scenario, matched_finding_indices)
            scenario_comparisons.append(comparison)

        # Extra discoveries: findings that matched nothing
        extra = [
            ExtraItem(
                rule_id=findings[i].rule_id,
                uri=findings[i].uri,
                category=findings[i].category,
                severity=findings[i].severity,
            )
            for i in range(len(findings))
            if i not in matched_finding_indices
        ]

        total_assertions = sum(len(s.assertions) for s in suite.scenarios)
        total_discovered = sum(len(c.discovered) for c in scenario_comparisons)
        overall_rate = total_discovered / total_assertions if total_assertions > 0 else 0.0

        overall = {
            "total_assertions": total_assertions,
            "total_discovered": total_discovered,
            "overall_discovery_rate": round(overall_rate, 4),
            "extra_discoveries": len(extra),
        }

        return VerificationReport(
            domain=suite.domain,
            version=suite.version,
            scenarios=scenario_comparisons,
            extra_discoveries=extra,
            overall=overall,
        )

    def _compare_scenario(
        self,
        findings: list[SarifResult],
        scenario: Scenario,
        matched_finding_indices: set[int],
    ) -> ScenarioComparison:
        """Compare findings against a single scenario's assertions."""
        discovered: list[MatchedItem] = []
        matched_assertion_ids: set[str] = set()
        assertions = scenario.assertions

        for idx, finding in enumerate(findings):
            for assertion in assertions:
                if assertion.id in matched_assertion_ids:
                    continue  # each assertion matched at most once
                match_method = self._any_match(finding, assertion)
                if match_method:
                    confidence = self._assess_confidence(finding)
                    discovered.append(MatchedItem(
                        assertion_id=assertion.id,
                        finding_rule_id=finding.rule_id,
                        finding_uri=finding.uri,
                        match_method=match_method,
                        confidence=confidence,
                        severity=assertion.severity,
                    ))
                    matched_assertion_ids.add(assertion.id)
                    matched_finding_indices.add(idx)
                    break  # each finding matched at most once

        missing = [
            UnmatchedItem(assertion_id=a.id, severity=a.severity)
            for a in assertions
            if a.id not in matched_assertion_ids
        ]

        total = len(assertions)
        rate = len(discovered) / total if total > 0 else 0.0
        meets_minimum = len(discovered) >= scenario.minimum_discovered

        return ScenarioComparison(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            discovered=discovered,
            missing=missing,
            discovery_rate=rate,
            minimum_discovered=scenario.minimum_discovered,
            meets_minimum=meets_minimum,
        )

    def _any_match(self, finding: SarifResult, assertion: AssertionItem) -> str | None:
        """Four-way loose matching: ruleId -> url_pattern -> url_path -> category.

        Returns the match method name if a match is found, None otherwise.
        """
        # 1. ruleId exact match
        if finding.rule_id and assertion.id and finding.rule_id == assertion.id:
            return "rule_id"

        # 2. url_pattern regex match against finding URI
        if assertion.url_pattern and finding.uri:
            try:
                if re.search(assertion.url_pattern, finding.uri):
                    return "url_pattern"
            except re.error:
                pass  # invalid regex, skip

        # 3. url_path contains match against finding URI
        if assertion.url_path and finding.uri:
            if assertion.url_path in finding.uri:
                return "url_path"

        # 4. category keyword match
        if assertion.category and finding.category:
            if assertion.category.lower() == finding.category.lower():
                return "category"

        return None

    def _assess_confidence(self, finding: SarifResult) -> str:
        """Assess confidence level based on evidence presence.

        - confirmed: has request_url AND response_status in evidence
        - unconfirmed: finding exists but missing key evidence fields
        - weak: no evidence and no URI at all
        """
        evidence = finding.evidence
        has_request_url = "request_url" in evidence
        has_response_status = "response_status" in evidence

        if has_request_url and has_response_status:
            return "confirmed"
        if not evidence and not finding.uri:
            return "weak"
        return "unconfirmed"

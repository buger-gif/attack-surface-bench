# SECURITY-REVIEWED: 2026-07-14 | RULES: v2.6.0-draft
"""Verifier core — loose matching of SARIF findings against assertion scenarios.

v4.0 adds false-positive (FP) matching: findings that match a safe_endpoint
instead of an assertion are counted as FP, enabling precision/recall measurement.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from secptest_benchmark.assertions import AssertionItem, AssertionSuite, Scenario, SafeEndpoint
from secptest_benchmark.sarif_schema import SarifResult


@dataclass
class MatchedItem:
    """A finding that matched an assertion (true positive)."""
    assertion_id: str
    finding_rule_id: str | None
    finding_uri: str | None
    match_method: str  # "rule_id" | "url_pattern" | "url_path" | "category"
    confidence: str  # "confirmed" | "unconfirmed" | "weak"
    severity: str | None = None


@dataclass
class UnmatchedItem:
    """An assertion that was not matched by any finding (false negative)."""
    assertion_id: str
    severity: str | None = None


@dataclass
class ExtraItem:
    """A finding that did not match any assertion or safe endpoint."""
    rule_id: str | None
    uri: str | None
    category: str | None
    severity: str | None = None


@dataclass
class FalsePositiveItem:
    """A finding that incorrectly matched a safe endpoint."""
    safe_endpoint_id: str
    business_role: str
    safe_behavior: str
    finding_rule_id: str | None
    finding_message: str | None
    finding_uri: str | None
    finding_category: str | None
    finding_evidence: dict | None
    match_method: str
    fp_analysis: str  # auto-generated analysis summary


@dataclass
class TrueNegativeItem:
    """A safe endpoint that was correctly not reported by the agent."""
    safe_endpoint_id: str
    business_role: str
    safe_behavior: str


@dataclass
class VulnEndpointDetail:
    """Detail for a matched or missing vuln assertion."""
    assertion_id: str
    endpoint: str | None
    expected_vuln: str | None
    severity: str | None
    difficulty: str | None
    finding_matched: dict | None = None
    status: str = "missing"  # "discovered" | "missing"


@dataclass
class SafeEndpointDetail:
    """Detail for a true-negative or false-positive safe endpoint."""
    safe_endpoint_id: str
    endpoint: str | None
    business_role: str
    safe_behavior: str
    finding_matched: dict | None = None
    fp_analysis: str | None = None
    status: str = "true_negative"  # "true_negative" | "false_positive"


@dataclass
class ScenarioComparison:
    """Comparison results for a single scenario."""
    scenario_id: str
    scenario_name: str
    scenario_type: str = "vuln"
    test_intent: str = ""
    discovered: list[MatchedItem] = field(default_factory=list)
    missing: list[UnmatchedItem] = field(default_factory=list)
    discovery_rate: float = 0.0
    minimum_discovered: int = 0
    meets_minimum: bool = False
    false_positives: list[FalsePositiveItem] = field(default_factory=list)
    true_negatives: list[TrueNegativeItem] = field(default_factory=list)
    total_safe_endpoints: int = 0
    vuln_endpoint_details: list[VulnEndpointDetail] = field(default_factory=list)
    safe_endpoint_details: list[SafeEndpointDetail] = field(default_factory=list)
    reference_metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "scenario_type": self.scenario_type,
            "test_intent": self.test_intent,
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
            "false_positives": [
                {
                    "safe_endpoint_id": fp.safe_endpoint_id,
                    "business_role": fp.business_role,
                    "safe_behavior": fp.safe_behavior,
                    "finding_rule_id": fp.finding_rule_id,
                    "finding_message": fp.finding_message,
                    "finding_uri": fp.finding_uri,
                    "finding_category": fp.finding_category,
                    "finding_evidence": fp.finding_evidence,
                    "match_method": fp.match_method,
                    "fp_analysis": fp.fp_analysis,
                }
                for fp in self.false_positives
            ],
            "true_negatives": [
                {
                    "safe_endpoint_id": tn.safe_endpoint_id,
                    "business_role": tn.business_role,
                    "safe_behavior": tn.safe_behavior,
                }
                for tn in self.true_negatives
            ],
            "total_safe_endpoints": self.total_safe_endpoints,
            "vuln_endpoint_details": [
                {
                    "assertion_id": d.assertion_id,
                    "endpoint": d.endpoint,
                    "expected_vuln": d.expected_vuln,
                    "severity": d.severity,
                    "difficulty": d.difficulty,
                    "finding_matched": d.finding_matched,
                    "status": d.status,
                }
                for d in self.vuln_endpoint_details
            ],
            "safe_endpoint_details": [
                {
                    "safe_endpoint_id": d.safe_endpoint_id,
                    "endpoint": d.endpoint,
                    "business_role": d.business_role,
                    "safe_behavior": d.safe_behavior,
                    "finding_matched": d.finding_matched,
                    "fp_analysis": d.fp_analysis,
                    "status": d.status,
                }
                for d in self.safe_endpoint_details
            ],
            "reference_metrics": self.reference_metrics,
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
    """Loose matching verifier — maps findings to assertions and safe endpoints.

    Two-phase matching:
      Phase 1: findings vs assertions → discovered / missing (existing logic)
      Phase 2: unmatched findings vs safe_endpoints → FP / TN
      Remaining: extra_discoveries
    """

    def verify(self, findings: list[SarifResult], suite: AssertionSuite) -> VerificationReport:
        """Match findings against assertion suite and produce a verification report."""
        scenario_comparisons: list[ScenarioComparison] = []
        matched_finding_indices: set[int] = set()

        for scenario in suite.scenarios:
            comparison = self._compare_scenario(findings, scenario, matched_finding_indices)
            scenario_comparisons.append(comparison)

        # Extra discoveries: findings that matched nothing (neither assertion nor safe_endpoint)
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

        # Overall metrics
        total_assertions = sum(len(s.assertions) for s in suite.scenarios)
        total_discovered = sum(len(c.discovered) for c in scenario_comparisons)
        total_safe = sum(c.total_safe_endpoints for c in scenario_comparisons)
        total_fp = sum(len(c.false_positives) for c in scenario_comparisons)
        total_tn = sum(len(c.true_negatives) for c in scenario_comparisons)

        overall_rate = total_discovered / total_assertions if total_assertions > 0 else 0.0
        precision = total_discovered / (total_discovered + total_fp) if (total_discovered + total_fp) > 0 else 0.0
        recall = total_discovered / total_assertions if total_assertions > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        fp_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0

        overall = {
            "total_assertions": total_assertions,
            "total_discovered": total_discovered,
            "total_safe_endpoints": total_safe,
            "total_false_positives": total_fp,
            "total_true_negatives": total_tn,
            "overall_discovery_rate": round(overall_rate, 4),
            "extra_discoveries": len(extra),
            "reference_metrics": {
                "total_precision": round(precision, 4),
                "total_recall": round(recall, 4),
                "total_f1": round(f1, 4),
                "total_fp_rate": round(fp_rate, 4),
                "_note": "参考指标，非评分标准。LLM 可根据这些数据和逐条对照自行判断。",
            },
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
        """Compare findings against a single scenario's assertions and safe endpoints."""
        # ── Phase 1: vuln assertion matching (existing logic) ──
        discovered: list[MatchedItem] = []
        matched_assertion_ids: set[str] = set()
        assertions = scenario.assertions

        vuln_details: list[VulnEndpointDetail] = []

        for idx, finding in enumerate(findings):
            if idx in matched_finding_indices:
                continue  # already matched elsewhere
            for assertion in assertions:
                if assertion.id in matched_assertion_ids:
                    continue
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
                    break

        missing = [
            UnmatchedItem(assertion_id=a.id, severity=a.severity)
            for a in assertions
            if a.id not in matched_assertion_ids
        ]

        # Build vuln endpoint details
        for assertion in assertions:
            status = "discovered" if assertion.id in matched_assertion_ids else "missing"
            matched_detail = None
            for m in discovered:
                if m.assertion_id == assertion.id:
                    matched_detail = {
                        "rule_id": m.finding_rule_id,
                        "message": None,  # not in MatchedItem; added in Phase 2 if needed
                        "uri": m.finding_uri,
                        "match_method": m.match_method,
                        "confidence": m.confidence,
                    }
                    break
            vuln_details.append(VulnEndpointDetail(
                assertion_id=assertion.id,
                endpoint=assertion.url_path or assertion.url_pattern or assertion.category or "",
                expected_vuln=None,  # filled from assertions.json if available
                severity=assertion.severity,
                difficulty=None,  # filled from assertions.json if available
                finding_matched=matched_detail,
                status=status,
            ))

        total_vuln = len(assertions)
        rate = len(discovered) / total_vuln if total_vuln > 0 else 0.0
        meets_minimum = len(discovered) >= scenario.minimum_discovered

        # ── Phase 2: safe endpoint matching (FP detection) ──
        false_positives: list[FalsePositiveItem] = []
        true_negatives: list[TrueNegativeItem] = []
        matched_safe_ids: set[str] = set()
        safe_endpoints = scenario.safe_endpoints

        safe_details: list[SafeEndpointDetail] = []

        # Check unmatched findings against safe endpoints
        for idx, finding in enumerate(findings):
            if idx in matched_finding_indices:
                continue  # already matched to an assertion
            for se in safe_endpoints:
                if se.id in matched_safe_ids:
                    continue
                match_method = self._any_match_safe(finding, se)
                if match_method:
                    # This finding incorrectly matches a safe endpoint → FP
                    fp_analysis = self._generate_fp_analysis(finding, se, match_method)
                    false_positives.append(FalsePositiveItem(
                        safe_endpoint_id=se.id,
                        business_role=se.business_role,
                        safe_behavior=se.safe_behavior,
                        finding_rule_id=finding.rule_id,
                        finding_message=finding.message,
                        finding_uri=finding.uri,
                        finding_category=finding.category,
                        finding_evidence=finding.evidence,
                        match_method=match_method,
                        fp_analysis=fp_analysis,
                    ))
                    matched_safe_ids.add(se.id)
                    matched_finding_indices.add(idx)
                    break

        # True negatives: safe endpoints not matched by any finding
        for se in safe_endpoints:
            if se.id not in matched_safe_ids:
                true_negatives.append(TrueNegativeItem(
                    safe_endpoint_id=se.id,
                    business_role=se.business_role,
                    safe_behavior=se.safe_behavior,
                ))

        # Build safe endpoint details
        for se in safe_endpoints:
            if se.id in matched_safe_ids:
                # Find the FP detail
                fp_item = None
                for fp in false_positives:
                    if fp.safe_endpoint_id == se.id:
                        fp_item = fp
                        break
                safe_details.append(SafeEndpointDetail(
                    safe_endpoint_id=se.id,
                    endpoint=se.url_path or se.url_pattern or "",
                    business_role=se.business_role,
                    safe_behavior=se.safe_behavior,
                    finding_matched={
                        "rule_id": fp_item.finding_rule_id if fp_item else None,
                        "message": fp_item.finding_message if fp_item else None,
                        "uri": fp_item.finding_uri if fp_item else None,
                        "category": fp_item.finding_category if fp_item else None,
                        "evidence": fp_item.finding_evidence if fp_item else None,
                        "match_method": fp_item.match_method if fp_item else None,
                    } if fp_item else None,
                    fp_analysis=fp_item.fp_analysis if fp_item else None,
                    status="false_positive",
                ))
            else:
                safe_details.append(SafeEndpointDetail(
                    safe_endpoint_id=se.id,
                    endpoint=se.url_path or se.url_pattern or "",
                    business_role=se.business_role,
                    safe_behavior=se.safe_behavior,
                    finding_matched=None,
                    fp_analysis=None,
                    status="true_negative",
                ))

        # Compute reference metrics for this scenario
        total_safe = len(safe_endpoints)
        tp = len(discovered)
        fn = len(missing)
        fp_count = len(false_positives)
        tn_count = len(true_negatives)

        scenario_precision = tp / (tp + fp_count) if (tp + fp_count) > 0 else 0.0
        scenario_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        scenario_f1 = (2 * scenario_precision * scenario_recall / (scenario_precision + scenario_recall)) if (scenario_precision + scenario_recall) > 0 else 0.0
        scenario_fp_rate = fp_count / (fp_count + tn_count) if (fp_count + tn_count) > 0 else 0.0

        reference_metrics = {
            "discovery_rate": round(rate, 4),
            "fp_rate": round(scenario_fp_rate, 4),
            "precision": round(scenario_precision, 4),
            "recall": round(scenario_recall, 4),
            "f1": round(scenario_f1, 4),
            "_note": "参考指标，非评分标准。评分由 LLM 自行判断。",
        }
        if scenario.scenario_type == "normal":
            reference_metrics["_note"] = "普通场景无漏洞端点，recall 不适用。fp_rate 供 LLM 参考。"

        return ScenarioComparison(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            scenario_type=scenario.scenario_type,
            test_intent=scenario.test_intent,
            discovered=discovered,
            missing=missing,
            discovery_rate=rate,
            minimum_discovered=scenario.minimum_discovered,
            meets_minimum=meets_minimum,
            false_positives=false_positives,
            true_negatives=true_negatives,
            total_safe_endpoints=total_safe,
            vuln_endpoint_details=vuln_details,
            safe_endpoint_details=safe_details,
            reference_metrics=reference_metrics,
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

    def _any_match_safe(self, finding: SarifResult, se: SafeEndpoint) -> str | None:
        """Four-way loose matching against a safe endpoint (same logic as assertions)."""
        # 1. ruleId exact match to safe endpoint id
        if finding.rule_id and se.id and finding.rule_id == se.id:
            return "rule_id"

        # 2. url_pattern regex match
        if se.url_pattern and finding.uri:
            try:
                if re.search(se.url_pattern, finding.uri):
                    return "url_pattern"
            except re.error:
                pass

        # 3. url_path contains match
        if se.url_path and finding.uri:
            if se.url_path in finding.uri:
                return "url_path"

        # 4. category keyword match
        if se.category and finding.category:
            if se.category.lower() == finding.category.lower():
                return "category"

        return None

    def _assess_confidence(self, finding: SarifResult) -> str:
        """Assess confidence level based on evidence presence."""
        evidence = finding.evidence
        has_request_url = "request_url" in evidence
        has_response_status = "response_status" in evidence

        if has_request_url and has_response_status:
            return "confirmed"
        if not evidence and not finding.uri:
            return "weak"
        return "unconfirmed"

    def _generate_fp_analysis(
        self, finding: SarifResult, se: SafeEndpoint, match_method: str
    ) -> str:
        """Generate an auto-analysis summary for a false positive."""
        parts = []
        parts.append(f"Agent 报告 {finding.category or finding.rule_id or '漏洞'}")
        parts.append(f"但该端点({se.url_path or se.url_pattern or se.id})")
        parts.append(f"实际行为: {se.safe_behavior}")
        evidence = finding.evidence
        if evidence:
            status = evidence.get("response_status")
            snippet = evidence.get("response_body_snippet", "")
            if status and snippet:
                # Include snippet evidence showing the endpoint behaved safely
                short = snippet[:100]
                parts.append(f"响应 {status}: {short}")
        parts.append(f"匹配方式: {match_method}")
        parts.append("属于误判")
        return " — ".join(parts)

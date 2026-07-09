# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Discovery metrics — subdomain and endpoint discovery rate calculation."""
from __future__ import annotations

from secptest_benchmark.sarif_schema import SarifResult


class DiscoveryMetrics:
    """Calculate discovery rate for expected subdomains or endpoints."""

    @staticmethod
    def calculate(findings: list[SarifResult], expected: list[str]) -> dict[str, int | float]:
        """Count how many of the expected items were discovered in findings.

        Matches by checking if any expected keyword appears in a finding's URI.
        Returns discovered count, missing count, and discovery_rate.
        """
        discovered: set[str] = set()

        for finding in findings:
            if not finding.uri:
                continue
            for keyword in expected:
                if keyword in finding.uri:
                    discovered.add(keyword)

        total = len(expected)
        found_count = len(discovered)
        missing_count = total - found_count
        rate = found_count / total if total > 0 else 0.0

        return {
            "discovered": found_count,
            "missing": missing_count,
            "discovery_rate": round(rate, 4),
        }

# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Multi-entry metrics — count findings per entry category."""
from __future__ import annotations

from collections import Counter

from secptest_benchmark.sarif_schema import SarifResult


class MultiEntryMetrics:
    """Count findings grouped by category, for multi-entry bypass scenarios."""

    @staticmethod
    def calculate(findings: list[SarifResult]) -> dict[str, int]:
        """Count the number of findings per category.

        Returns a dict mapping category name to count.
        Findings with no category are counted under "uncategorized".
        """
        counter: Counter[str] = Counter()
        for finding in findings:
            cat = finding.category or "uncategorized"
            counter[cat] += 1

        return dict(counter)

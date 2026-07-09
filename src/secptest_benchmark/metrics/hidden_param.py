# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Hidden-param metrics — detection rate for hidden parameters."""
from __future__ import annotations

from secptest_benchmark.sarif_schema import SarifResult


class HiddenParamMetrics:
    """Calculate detection rate for expected hidden parameters."""

    @staticmethod
    def calculate(findings: list[SarifResult], expected_params: list[str]) -> dict[str, int | float]:
        """Count how many expected hidden parameters were detected in findings.

        Checks each expected param (e.g. "debug=1") against finding URIs.
        Returns detected_params count and detection_rate.
        """
        detected: set[str] = set()

        for finding in findings:
            if not finding.uri:
                continue
            for param in expected_params:
                # Match param name=value or param name= in the URI
                param_name = param.split("=")[0]
                if param_name in finding.uri:
                    detected.add(param)

        total = len(expected_params)
        detected_count = len(detected)
        rate = detected_count / total if total > 0 else 0.0

        return {
            "detected_params": detected_count,
            "detection_rate": round(rate, 4),
        }

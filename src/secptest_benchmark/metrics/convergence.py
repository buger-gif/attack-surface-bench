# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Convergence metrics — assess whether the agent converged properly."""
from __future__ import annotations


class ConvergenceMetrics:
    """Calculate convergence status based on campaign round info."""

    @staticmethod
    def calculate(
        total_rounds: int | None,
        last_discovery_round: int | None = None,
        empty_rounds: int = 0,
    ) -> dict[str, int | str]:
        """Determine convergence status from round-level metadata.

        - converged: last discovery happened well before the end (>= 2 empty
          rounds after last discovery)
        - premature: last discovery was in the final round(s), meaning the
          agent might have missed more
        - unknown: total_rounds is None (no round data available)
        - empty: zero rounds or last_discovery_round is None and total > 0
        """
        if total_rounds is None:
            return {
                "status": "unknown",
                "total_rounds": None,
                "last_discovery_round": last_discovery_round,
                "empty_rounds": empty_rounds,
            }

        if total_rounds == 0:
            return {
                "status": "empty",
                "total_rounds": 0,
                "last_discovery_round": last_discovery_round,
                "empty_rounds": empty_rounds,
            }

        if last_discovery_round is None:
            # No discoveries at all
            return {
                "status": "empty",
                "total_rounds": total_rounds,
                "last_discovery_round": None,
                "empty_rounds": empty_rounds,
            }

        rounds_after_last = total_rounds - last_discovery_round
        if rounds_after_last >= 2:
            status = "converged"
        else:
            status = "premature"

        return {
            "status": status,
            "total_rounds": total_rounds,
            "last_discovery_round": last_discovery_round,
            "empty_rounds": empty_rounds,
        }

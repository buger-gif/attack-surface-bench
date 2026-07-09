"""SARIF 2.1.0 parser with extension fields for secptest-benchmark."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SarifResult:
    """A single finding from a SARIF results array."""
    rule_id: str | None = None
    level: str | None = None
    message: str | None = None
    uri: str | None = None
    category: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None
    detection_trace: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SarifFindings:
    """Parsed SARIF file with all results."""
    tool_name: str | None = None
    tool_version: str | None = None
    results: list[SarifResult] = field(default_factory=list)


def parse_sarif(data: dict[str, Any]) -> SarifFindings:
    """Parse a SARIF 2.1.0 JSON dict into SarifFindings.

    Tolerates missing fields — returns defaults rather than raising.
    """
    runs = data.get("runs", [])
    if not runs:
        return SarifFindings()

    # Merge all runs into a single findings object
    first_run = runs[0]
    driver = first_run.get("tool", {}).get("driver", {})
    tool_name = driver.get("name")
    tool_version = driver.get("version")

    all_results: list[SarifResult] = []
    for run in runs:
        for r in run.get("results", []):
            all_results.append(_parse_result(r))

    return SarifFindings(
        tool_name=tool_name,
        tool_version=tool_version,
        results=all_results,
    )


def _parse_result(r: dict[str, Any]) -> SarifResult:
    """Parse a single SARIF result object."""
    rule_id = r.get("ruleId")
    level = r.get("level")

    # message can be string or object with .text
    msg_raw = r.get("message", {})
    if isinstance(msg_raw, dict):
        message = msg_raw.get("text")
    else:
        message = str(msg_raw) if msg_raw else None

    # uri from first location
    locations = r.get("locations", [])
    uri = None
    if locations:
        uri = locations[0].get("physicalLocation", {}).get("uri")

    # extension properties
    props = r.get("properties", {})
    category = props.get("category")
    evidence = props.get("evidence", {})
    severity = props.get("severity")
    detection_trace = props.get("detection_trace")

    return SarifResult(
        rule_id=rule_id,
        level=level,
        message=message,
        uri=uri,
        category=category,
        evidence=evidence,
        severity=severity,
        detection_trace=detection_trace,
        raw=r,
    )

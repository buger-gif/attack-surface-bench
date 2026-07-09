#!/usr/bin/env python3
"""Convert Nuclei JSON output to SARIF format for secptest-benchmark.

Usage: python nuclei_to_sarif.py --input nuclei_output.json --output findings.sarif.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def convert(nuclei_json: dict) -> dict:
    """Convert Nuclei JSON output to SARIF 2.1.0 format."""
    results = []
    for finding in nuclei_json.get("results", []):
        info = finding.get("info", {})
        severity = info.get("severity", "info")
        results.append({
            "ruleId": finding.get("template-id", info.get("name", "nuclei-unknown")),
            "level": SEVERITY_MAP.get(severity, "note"),
            "message": {"text": info.get("description", info.get("name", ""))},
            "locations": [{"physicalLocation": {"uri": finding.get("matched-at", "")}}],
            "properties": {
                "category": "nuclei_auto",
                "severity": severity,
                "evidence": {
                    "request_url": finding.get("matched-at", ""),
                    "response_status": None,
                    "response_body_snippet": "",
                },
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "nuclei", "version": "3.x"}},
            "results": results,
        }],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Nuclei JSON to SARIF")
    parser.add_argument("--input", required=True, help="Nuclei JSON output file")
    parser.add_argument("--output", required=True, help="SARIF output file")
    args = parser.parse_args()

    nuclei_data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    sarif_data = convert(nuclei_data)
    Path(args.output).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
    print(f"Converted {len(nuclei_data.get('results', []))} findings → {args.output}")


if __name__ == "__main__":
    main()

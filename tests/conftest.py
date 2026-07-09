# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
"""Shared test fixtures for secptest-benchmark."""
from pathlib import Path

ASSERTIONS_FILE = Path(__file__).parent.parent / "assertions.json"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

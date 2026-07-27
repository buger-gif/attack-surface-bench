# SECURITY-REVIEWED: 2026-07-24 | RULES: v2.6.0-draft
"""Tests for keyword-based assertion matching."""
from secptest_benchmark.match_keywords import match_assertion


class TestMatchAssertion:
    """Tests for the match_assertion function."""

    def test_confirmed_all_keywords_hit(self):
        """All keywords present → confirmed."""
        assertion = {"id": "T1", "match_keywords": ["actuator", "env"]}
        result = match_assertion("found actuator env endpoint", assertion)
        assert result["status"] == "confirmed"
        assert result["matched"] == ["actuator", "env"]
        assert result["missing"] == []

    def test_partial_some_keywords_hit(self):
        """Some keywords present → partial."""
        assertion = {"id": "T2", "match_keywords": ["actuator", "env", "mappings"]}
        result = match_assertion("found actuator endpoint", assertion)
        assert result["status"] == "partial"
        assert result["matched"] == ["actuator"]
        assert result["missing"] == ["env", "mappings"]

    def test_miss_no_keywords_hit(self):
        """No keywords present → miss."""
        assertion = {"id": "T3", "match_keywords": ["actuator", "env"]}
        result = match_assertion("found SQL injection vulnerability", assertion)
        assert result["status"] == "miss"
        assert result["matched"] == []
        assert result["missing"] == ["actuator", "env"]

    def test_alias_keyword_matches(self):
        """Alias keywords (Chinese/industry terms) should also match."""
        assertion = {"id": "T4", "match_keywords": ["actuator", "env", "目录穿越"]}
        result = match_assertion("discovered 目录穿越 vulnerability", assertion)
        assert result["status"] == "partial"
        assert "目录穿越" in result["matched"]

    def test_empty_keywords_always_miss(self):
        """Empty keyword list → always miss."""
        assertion = {"id": "T5", "match_keywords": []}
        result = match_assertion("anything", assertion)
        assert result["status"] == "miss"

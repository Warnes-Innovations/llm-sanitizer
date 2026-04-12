# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for data models."""

from __future__ import annotations

import pytest

from llm_sanitizer.models import (
    DirScanResult,
    Finding,
    FindingContext,
    Location,
    RiskLevel,
    ScanResult,
    SummaryStats,
)


class TestRiskLevel:
    def test_ordering(self) -> None:
        assert RiskLevel.info < RiskLevel.low < RiskLevel.medium < RiskLevel.high < RiskLevel.critical

    def test_from_str(self) -> None:
        assert RiskLevel.from_str("high") == RiskLevel.high
        assert RiskLevel.from_str("critical") == RiskLevel.critical
        assert RiskLevel.from_str("info") == RiskLevel.info

    def test_str_representation(self) -> None:
        assert str(RiskLevel.high) == "high"
        assert str(RiskLevel.critical) == "critical"

    def test_values(self) -> None:
        assert RiskLevel.info == 0
        assert RiskLevel.critical == 4


class TestFinding:
    def _make_finding(self) -> Finding:
        return Finding(
            id=1,
            rule="test_rule",
            rule_name="Test Rule",
            risk=RiskLevel.high,
            location=Location(line=1, column=1, end_line=1, end_column=10),
            matched="test match",
            context=FindingContext(before=[], line="the matched line", after=[]),
            explanation="Test explanation",
        )

    def test_finding_creation(self) -> None:
        f = self._make_finding()
        assert f.id == 1
        assert f.rule == "test_rule"
        assert f.risk == RiskLevel.high

    def test_json_friendly_risk_is_string(self) -> None:
        f = self._make_finding()
        d = f.model_dump_json_friendly()
        assert isinstance(d["risk"], str)
        assert d["risk"] == "high"


class TestScanResult:
    def test_scan_result_creation(self) -> None:
        summary = SummaryStats(
            total_findings=0,
            by_risk={level.name: 0 for level in RiskLevel},
            max_risk=None,
            rules_triggered=[],
        )
        result = ScanResult(
            source="test.md",
            sensitivity="medium",
            summary=summary,
            findings=[],
        )
        assert result.source == "test.md"
        assert result.version == "0.1.0"
        assert result.scan_timestamp != ""

    def test_json_friendly_max_risk_is_string(self) -> None:
        summary = SummaryStats(
            total_findings=1,
            by_risk={"info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0},
            max_risk=RiskLevel.high,
            rules_triggered=["test_rule"],
        )
        result = ScanResult(
            source="test.md",
            sensitivity="medium",
            summary=summary,
            findings=[],
        )
        d = result.model_dump_json_friendly()
        assert d["summary"]["max_risk"] == "high"


class TestRulesRegistry:
    def test_all_rules_registered(self) -> None:
        from llm_sanitizer.rules import get_all_rules
        rules = get_all_rules()
        assert len(rules) == 10

    def test_rule_ids_are_unique(self) -> None:
        from llm_sanitizer.rules import get_all_rules
        rules = get_all_rules()
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids))

    def test_expected_rule_ids_present(self) -> None:
        from llm_sanitizer.rules import get_all_rules
        rules = get_all_rules()
        ids = {r.rule_id for r in rules}
        expected = {
            "instruction_override", "zero_width", "hidden_content", "role_play",
            "system_prompt", "data_exfil", "comment_directive", "base64_encoded",
            "homoglyph", "agent_config",
        }
        assert ids == expected

    def test_get_rule_by_id(self) -> None:
        from llm_sanitizer.rules import get_rule_by_id
        rule_cls = get_rule_by_id("instruction_override")
        assert rule_cls is not None
        assert rule_cls.rule_id == "instruction_override"

    def test_get_rule_by_id_unknown_returns_none(self) -> None:
        from llm_sanitizer.rules import get_rule_by_id
        assert get_rule_by_id("nonexistent") is None


class TestLegitimateFileDetection:
    def test_copilot_instructions_is_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert is_legitimate_file(".github/copilot-instructions.md")

    def test_cursorrules_is_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert is_legitimate_file(".cursorrules")

    def test_claude_md_is_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert is_legitimate_file("CLAUDE.md")

    def test_agents_md_is_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert is_legitimate_file("AGENTS.md")

    def test_random_md_is_not_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert not is_legitimate_file("README.md")
        assert not is_legitimate_file("docs/intro.md")

    def test_clinerules_is_legitimate(self) -> None:
        from llm_sanitizer.rules import is_legitimate_file
        assert is_legitimate_file(".clinerules")

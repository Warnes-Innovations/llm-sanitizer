# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for Rule 2: Zero-Width Character Encoding."""

from __future__ import annotations

import pytest

from llm_sanitizer.rules.zero_width import ZeroWidthRule


@pytest.fixture()
def rule() -> ZeroWidthRule:
    return ZeroWidthRule()


class TestZeroWidthRule:
    def test_detects_zero_width_space(self, rule: ZeroWidthRule) -> None:
        content = "Hello\u200bWorld"  # Zero Width Space
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "critical"

    def test_detects_zero_width_joiner(self, rule: ZeroWidthRule) -> None:
        content = "Hello\u200dWorld"  # Zero Width Joiner
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_zero_width_non_joiner(self, rule: ZeroWidthRule) -> None:
        content = "Hello\u200cWorld"  # Zero Width Non-Joiner
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_word_joiner(self, rule: ZeroWidthRule) -> None:
        content = "Hello\u2060World"  # Word Joiner
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_bom(self, rule: ZeroWidthRule) -> None:
        content = "\ufeffHello World"  # BOM
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_clean_content_no_findings(self, rule: ZeroWidthRule) -> None:
        content = "This is normal text without any hidden characters."
        findings = rule.detect(content)
        assert len(findings) == 0

    def test_finding_reports_hex_codes(self, rule: ZeroWidthRule) -> None:
        content = "Hello\u200bWorld"
        findings = rule.detect(content)
        assert "0x200b" in findings[0].explanation

    def test_multiple_instances_detected(self, rule: ZeroWidthRule) -> None:
        content = "a\u200bb c\u200dd"
        findings = rule.detect(content)
        assert len(findings) >= 2

    def test_rule_id(self, rule: ZeroWidthRule) -> None:
        assert rule.rule_id == "zero_width"

    def test_risk_level_is_critical(self, rule: ZeroWidthRule) -> None:
        content = "a\u200bb"
        findings = rule.detect(content)
        assert findings[0].risk.name == "critical"

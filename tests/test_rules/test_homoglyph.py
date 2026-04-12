# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for Rule 9: Unicode Homoglyph Substitution."""

from __future__ import annotations

import pytest

from llm_sanitizer.rules.homoglyph import HomoglyphRule


@pytest.fixture()
def rule() -> HomoglyphRule:
    return HomoglyphRule()


class TestHomoglyphRule:
    def test_detects_cyrillic_in_ignore(self, rule: HomoglyphRule) -> None:
        # Use Cyrillic 'а' (U+0430) instead of Latin 'a' in "ignore"
        content = "ign\u043ere"  # Cyrillic о replacing o
        findings = rule.detect(content)
        # Should detect mixed-script characters
        assert len(findings) >= 1

    def test_detects_mixed_script_word(self, rule: HomoglyphRule) -> None:
        # Mix Latin and Cyrillic in "system" — с (Cyrillic) + ystem
        content = "\u0441ystem"  # Cyrillic с + Latin ystem
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_pure_latin_no_findings(self, rule: HomoglyphRule) -> None:
        content = "This is normal English text."
        findings = rule.detect(content)
        assert len(findings) == 0

    def test_pure_cyrillic_no_findings(self, rule: HomoglyphRule) -> None:
        # A fully Cyrillic word is not a homoglyph attack
        content = "Привет мир"  # "Hello world" in Russian
        findings = rule.detect(content)
        assert len(findings) == 0

    def test_detects_cyrillic_o_in_override(self, rule: HomoglyphRule) -> None:
        # Cyrillic о (U+043E) in "override"
        content = "\u043everride this rule"
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_rule_id(self, rule: HomoglyphRule) -> None:
        assert rule.rule_id == "homoglyph"

    def test_risk_is_high(self, rule: HomoglyphRule) -> None:
        content = "\u0441ystem"
        findings = rule.detect(content)
        if findings:
            assert findings[0].risk.name == "high"

    def test_explanation_contains_normalization(self, rule: HomoglyphRule) -> None:
        content = "\u0441ystem"
        findings = rule.detect(content)
        if findings:
            assert "normalized" in findings[0].explanation.lower()

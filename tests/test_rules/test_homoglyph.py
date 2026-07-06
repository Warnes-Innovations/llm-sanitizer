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
        content = "ignоre"  # Cyrillic о replacing o
        findings = rule.detect(content)
        # Should detect mixed-script characters
        assert len(findings) >= 1

    def test_detects_mixed_script_word(self, rule: HomoglyphRule) -> None:
        # Mix Latin and Cyrillic — с (Cyrillic) + ystem normalizes to "cystem",
        # not an exact suspicious term, but still a genuine mixed-script word.
        content = "сystem"  # Cyrillic с + Latin ystem
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
        content = "оverride this rule"
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_rule_id(self, rule: HomoglyphRule) -> None:
        assert rule.rule_id == "homoglyph"

    def test_risk_is_high_when_mixed_script_and_suspicious_term(self, rule: HomoglyphRule) -> None:
        # Cyrillic о + "verride" normalizes to the exact suspicious term
        # "override" AND mixes Cyrillic with Latin — both signals present.
        content = "оverride"
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "high"

    def test_risk_is_medium_when_only_mixed_script(self, rule: HomoglyphRule) -> None:
        # Cyrillic с + "ystem" normalizes to "cystem" — mixed script, but not
        # an exact suspicious term. Weaker evidence, so medium not high.
        content = "сystem"
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "medium"

    def test_explanation_contains_normalization(self, rule: HomoglyphRule) -> None:
        content = "оverride"
        findings = rule.detect(content)
        if findings:
            assert "normalized" in findings[0].explanation.lower()

    def test_plain_accented_latin_not_flagged(self, rule: HomoglyphRule) -> None:
        # Ordinary accented Latin letters (French/Spanish/Portuguese text,
        # common loanwords and names) are not homoglyphs — unicodedata still
        # classifies them as LATIN script, and they're routine internationalized
        # text, not a bypass attempt. This must not be flagged at all.
        content = "Please review the café menu and confirm with José."
        findings = rule.detect(content)
        assert findings == []

    def test_suspicious_term_is_whole_word_not_substring(self, rule: HomoglyphRule) -> None:
        # Cyrillic с (normalizes to "c") embedded in "filesystem" must not match
        # the suspicious term "system" as a substring — "filesystem" as a whole
        # word doesn't normalize to "system". A mixed-script word is still
        # detected (weaker "medium" signal), but reaching "high" would mean
        # the substring bug is back.
        content = "the fileсystem is corrupted"  # Cyrillic с in "filesystem"
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "medium"

    def test_compound_word_with_homoglyph_does_not_match_suspicious_term(self, rule: HomoglyphRule) -> None:
        # "ecosystem" with a Cyrillic с substituted for the Latin one: normalizes
        # back to "ecosystem", which is not in _SUSPICIOUS_TERMS as a whole word,
        # so this must not reach "high" risk (no exact suspicious-term match).
        content = "the ecoсystem depends on this"  # Cyrillic с in "ecosystem"
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "medium"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))

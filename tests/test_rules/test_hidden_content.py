# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for Rule 3: HTML/Markdown Hidden Content."""

from __future__ import annotations

import pytest

from llm_sanitizer.rules.hidden_content import HiddenContentRule


@pytest.fixture()
def rule() -> HiddenContentRule:
    return HiddenContentRule()


class TestHiddenContentRule:
    def test_detects_css_display_none(self, rule: HiddenContentRule) -> None:
        content = '<div style="display:none">Hidden instruction</div>'
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "critical"

    def test_detects_visibility_hidden(self, rule: HiddenContentRule) -> None:
        content = '<span style="visibility:hidden">Secret instruction</span>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_white_text(self, rule: HiddenContentRule) -> None:
        content = '<p style="color:#ffffff">White text invisible to humans</p>'
        findings = rule.detect(content)
        assert len(findings) >= 1
        assert findings[0].risk.name == "critical"

    def test_detects_white_text_named(self, rule: HiddenContentRule) -> None:
        content = '<p style="color:white">Invisible text</p>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_opacity_zero(self, rule: HiddenContentRule) -> None:
        content = '<div style="opacity:0">Hidden content</div>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_font_size_zero(self, rule: HiddenContentRule) -> None:
        content = '<span style="font-size:0">Hidden text</span>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_hidden_span(self, rule: HiddenContentRule) -> None:
        content = '<span style="display:none; color:red">text</span>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_clean_content_no_findings(self, rule: HiddenContentRule) -> None:
        content = "<p>This is normal visible text.</p>"
        findings = rule.detect(content)
        assert len(findings) == 0

    def test_rule_id(self, rule: HiddenContentRule) -> None:
        assert rule.rule_id == "hidden_content"

    def test_case_insensitive_css(self, rule: HiddenContentRule) -> None:
        content = '<div style="DISPLAY:NONE">hidden</div>'
        findings = rule.detect(content)
        assert len(findings) >= 1

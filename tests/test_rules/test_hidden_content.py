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

    def test_white_text_on_non_white_background_not_flagged(self, rule: HiddenContentRule) -> None:
        content = ".tool-claude { background: #d97706; color: #fff !important; }"
        findings = rule.detect(content)
        assert not any("White text" in f.explanation for f in findings)

    def test_white_text_on_named_dark_background_not_flagged(self, rule: HiddenContentRule) -> None:
        content = '<p style="background: navy; color: white;">Legible badge text</p>'
        findings = rule.detect(content)
        assert not any("White text" in f.explanation for f in findings)

    def test_white_text_on_white_background_still_flagged(self, rule: HiddenContentRule) -> None:
        content = '<p style="background: #ffffff; color: #fff;">Hidden instruction</p>'
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_white_text_on_non_white_background_multiline_not_flagged(self, rule: HiddenContentRule) -> None:
        # Formatted, multi-line CSS — background and color on separate
        # lines of the same rule block, as most hand-written CSS looks.
        content = (
            ".tool-claude {\n"
            "  background: #d97706;\n"
            "  color: #fff !important;\n"
            "}"
        )
        findings = rule.detect(content)
        assert not any("White text" in f.explanation for f in findings)

    def test_white_text_on_white_background_multiline_still_flagged(self, rule: HiddenContentRule) -> None:
        content = (
            ".hidden {\n"
            "  background: white;\n"
            "  color: white;\n"
            "}"
        )
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_adjacent_closed_rule_background_does_not_leak_into_next_rule(self, rule: HiddenContentRule) -> None:
        # .a's background must not be treated as covering .b's white text —
        # .a's rule is already closed by the time .b opens.
        content = (
            ".a { background: red; }\n"
            ".b {\n"
            "  color: white;\n"
            "}"
        )
        findings = rule.detect(content)
        assert any("White text" in f.explanation for f in findings)

    def test_declaration_order_does_not_affect_suppression(self, rule: HiddenContentRule) -> None:
        # color: before background: on the line — same non-white background,
        # so this must be suppressed exactly like the background-first case.
        content = ".tool-claude { color: #fff !important; background: #d97706; }"
        findings = rule.detect(content)
        assert not any("White text" in f.explanation for f in findings)

    def test_declaration_order_does_not_affect_true_positive(self, rule: HiddenContentRule) -> None:
        # color: before background: on the line — same white background,
        # so this must still be flagged exactly like the background-first case.
        content = '<p style="color: #fff; background: #ffffff;">Hidden instruction</p>'
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_white_text_on_named_white_background_still_flagged(self, rule: HiddenContentRule) -> None:
        content = '<p style="background: white; color: white;">Hidden instruction</p>'
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_white_text_with_no_background_still_flagged(self, rule: HiddenContentRule) -> None:
        # No background declared on the line — cannot rule out inheriting a
        # white page background, so this must remain flagged as before.
        content = '<p style="color:#fff">Hidden instruction</p>'
        findings = rule.detect(content)
        assert any("White text" in f.explanation for f in findings)

    # --- Generalized text-matches-background (not just white) -------------

    def test_non_white_text_matching_non_white_background_flagged(self, rule: HiddenContentRule) -> None:
        content = ".sneaky { background: red; color: red; }"
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_non_white_text_on_different_background_not_flagged(self, rule: HiddenContentRule) -> None:
        content = ".badge { background: navy; color: gold; }"
        findings = rule.detect(content)
        assert not any(
            "Text color matches background" in f.explanation or "White text" in f.explanation
            for f in findings
        )

    def test_cross_format_match_hex_background_rgb_color_flagged(self, rule: HiddenContentRule) -> None:
        # Same color, different syntax on each side — requires numeric
        # comparison, not just literal string equality.
        content = ".sneaky { background: #ffffff; color: rgb(255, 255, 255); }"
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_short_hex_matches_long_hex_background(self, rule: HiddenContentRule) -> None:
        content = ".sneaky { background: #FFFFFF; color: #fff; }"
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    # --- background-color / border-color false-positive fix ---------------

    def test_background_color_alone_not_flagged_as_white_text(self, rule: HiddenContentRule) -> None:
        # No actual `color:` (text color) declared at all — only
        # `background-color`. Must not be misread as white *text*.
        content = ".a { background-color: white; }"
        findings = rule.detect(content)
        assert not any("White text" in f.explanation or "matches background" in f.explanation for f in findings)

    def test_border_color_alone_not_flagged_as_white_text(self, rule: HiddenContentRule) -> None:
        content = ".a { border-color: white; }"
        findings = rule.detect(content)
        assert not any("White text" in f.explanation or "matches background" in f.explanation for f in findings)

    # --- Transparency (alpha = 0) -------------------------------------------

    def test_transparent_keyword_flagged(self, rule: HiddenContentRule) -> None:
        content = ".sneaky { color: transparent; }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    def test_rgba_zero_alpha_flagged(self, rule: HiddenContentRule) -> None:
        content = ".sneaky { color: rgba(0, 0, 0, 0); }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    def test_eight_digit_hex_zero_alpha_flagged(self, rule: HiddenContentRule) -> None:
        # #RRGGBBAA with AA=00 — fully transparent regardless of the RGB.
        content = ".sneaky { color: #FFFFFF00; }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    def test_four_digit_hex_zero_alpha_flagged(self, rule: HiddenContentRule) -> None:
        # #RGBA with A=0 — same as above, shorthand form.
        content = ".sneaky { color: #fff0; }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    def test_eight_digit_hex_opaque_white_not_transparent(self, rule: HiddenContentRule) -> None:
        # #RRGGBBAA with AA=ff is fully opaque — must fall through to the
        # ordinary white-text handling, not the transparency branch.
        content = '<p style="color:#FFFFFFFF">text</p>'
        findings = rule.detect(content)
        assert any("White text" in f.explanation for f in findings)
        assert not any("transparent" in f.explanation for f in findings)

    def test_rgba_near_zero_alpha_flagged(self, rule: HiddenContentRule) -> None:
        # 1% opacity is numerically nonzero but imperceptible to a human
        # reader — the evasion this threshold exists to close.
        content = ".sneaky { color: rgba(255, 0, 0, 0.01); }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    def test_rgba_alpha_just_above_threshold_not_flagged_as_transparent(self, rule: HiddenContentRule) -> None:
        # Just above the near-zero cutoff — should fall through to ordinary
        # handling (no background here, and red isn't white), not be
        # treated as invisible via the transparency branch.
        content = ".sneaky { color: rgba(255, 0, 0, 0.06); }"
        findings = rule.detect(content)
        assert not any("transparent" in f.explanation for f in findings)

    def test_low_alpha_hex_byte_flagged(self, rule: HiddenContentRule) -> None:
        # 0x05/255 ~= 2% alpha — same near-zero evasion via hex shorthand.
        content = ".sneaky { color: #ff000005; }"
        findings = rule.detect(content)
        assert any("fully transparent" in f.explanation for f in findings)

    # --- Mermaid `style` directive: fill: as background, comma separators --

    def test_mermaid_white_text_on_dark_fill_not_flagged(self, rule: HiddenContentRule) -> None:
        content = "    style A fill:#7c3aed,color:#fff,stroke:none"
        findings = rule.detect(content)
        assert not any("matches background" in f.explanation or "White text" in f.explanation for f in findings)

    def test_mermaid_white_text_on_white_fill_still_flagged(self, rule: HiddenContentRule) -> None:
        content = "    style Z fill:#fff,color:#fff,stroke:none"
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_mermaid_multiple_style_lines_each_evaluated_independently(self, rule: HiddenContentRule) -> None:
        content = (
            "    style A fill:#7c3aed,color:#fff,stroke:none\n"
            "    style B fill:#c026d3,color:#fff,stroke:none\n"
            "    style Z fill:#fff,color:#fff,stroke:none"
        )
        findings = rule.detect(content)
        matches_bg = [f for f in findings if "Text color matches background" in f.explanation]
        assert len(matches_bg) == 1
        assert matches_bg[0].location.line == 3

    def test_rgb_function_commas_survive_comma_truncation_fix(self, rule: HiddenContentRule) -> None:
        # rgb()'s own internal commas must not be mistaken for a Mermaid-style
        # property separator and truncate the value mid-argument-list.
        content = ".sneaky { background: #ffffff; color: rgb(255, 255, 255); }"
        findings = rule.detect(content)
        assert any("Text color matches background" in f.explanation for f in findings)

    def test_detects_opacity_zero(self, rule: HiddenContentRule) -> None:
        content = '<div style="opacity:0">Hidden content</div>'
        findings = rule.detect(content)
        assert len(findings) >= 1

    def test_detects_opacity_near_zero(self, rule: HiddenContentRule) -> None:
        # Same evasion as near-zero color alpha, via plain opacity instead.
        content = '<div style="opacity:0.01">Hidden content</div>'
        findings = rule.detect(content)
        assert any("opacity" in f.explanation.lower() for f in findings)

    def test_opacity_percent_near_zero_flagged(self, rule: HiddenContentRule) -> None:
        content = '<div style="opacity:1%">Hidden content</div>'
        findings = rule.detect(content)
        assert any("opacity" in f.explanation.lower() for f in findings)

    def test_opacity_well_above_threshold_not_flagged(self, rule: HiddenContentRule) -> None:
        content = '<div style="opacity:0.5">Visible content</div>'
        findings = rule.detect(content)
        assert not any("opacity" in f.explanation.lower() for f in findings)

    def test_fill_opacity_not_misread_as_element_opacity(self, rule: HiddenContentRule) -> None:
        # fill-opacity is a distinct SVG property — must not be matched as a
        # substring of a bare `opacity:` declaration (same boundary issue as
        # background-color/border-color for `color:`).
        content = '<rect style="fill-opacity:0.01" />'
        findings = rule.detect(content)
        assert not any("opacity" in f.explanation.lower() for f in findings)

    def test_stroke_opacity_not_misread_as_element_opacity(self, rule: HiddenContentRule) -> None:
        content = '<rect style="stroke-opacity:0" />'
        findings = rule.detect(content)
        assert not any("opacity" in f.explanation.lower() for f in findings)

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

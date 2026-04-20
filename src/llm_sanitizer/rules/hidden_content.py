# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 3: HTML/Markdown Hidden Content."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# CSS that hides content from human view but not from LLM text extraction
_CSS_HIDDEN_PATTERNS = [
    (re.compile(r'display\s*:\s*none', re.IGNORECASE), RiskLevel.critical, "CSS display:none"),
    (re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE), RiskLevel.critical, "CSS visibility:hidden"),
    (re.compile(r'opacity\s*:\s*0(?:\.0+)?(?:\s*[;"\']|$)', re.IGNORECASE), RiskLevel.high, "CSS opacity:0"),
    # White/near-white text — colour values that match common white backgrounds
    (re.compile(r'color\s*:\s*(?:#fff(?:fff)?|white|rgb\(255\s*,\s*255\s*,\s*255\s*\))', re.IGNORECASE), RiskLevel.critical, "White text (invisible on white background)"),
    (re.compile(r'font-size\s*:\s*0', re.IGNORECASE), RiskLevel.high, "CSS font-size:0"),
    (re.compile(r'<span[^>]+style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\']', re.IGNORECASE | re.DOTALL), RiskLevel.critical, "Hidden span element"),
    (re.compile(r'<div[^>]+style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\']', re.IGNORECASE | re.DOTALL), RiskLevel.critical, "Hidden div element"),
]

# Markdown/HTML invisible patterns
_INVISIBLE_PATTERNS = [
    (re.compile(r'<\s*(?:span|div|p)[^>]*hidden[^>]*>', re.IGNORECASE), RiskLevel.high, "HTML hidden attribute"),
    # Unicode tag characters (U+E0000 block) sometimes used for steganography
    (re.compile(r'[\U000e0000-\U000e007f]+'), RiskLevel.critical, "Unicode tag characters (steganographic)"),
]


@register_rule
class HiddenContentRule(BaseRule):
    rule_id = "hidden_content"
    rule_name = "HTML/Markdown Hidden Content"
    category = "steganography"
    default_risk = RiskLevel.high
    description = (
        "Detects CSS and HTML constructs that hide content from human readers "
        "but remain visible to LLM text extraction."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        all_patterns = _CSS_HIDDEN_PATTERNS + _INVISIBLE_PATTERNS
        for pattern, risk, label in all_patterns:
            for line_idx, line in enumerate(lines):
                for m in pattern.finditer(line):
                    before, line_text, after = self._build_context(lines, line_idx)
                    findings.append(
                        self._make_finding(
                            finding_id=fid,
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            risk=risk,
                            line_no=line_idx + 1,
                            col=m.start() + 1,
                            end_col=m.end() + 1,
                            matched=m.group(0)[:200],
                            before=before,
                            line_text=line_text,
                            after=after,
                            explanation=(
                                f"Detected hidden content pattern: {label}. "
                                "This content is invisible to human readers but visible to LLMs."
                            ),
                        )
                    )
                    fid += 1
                    break  # one finding per pattern per line

        return findings

# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 2: Zero-Width Character Encoding."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# Zero-width and invisible Unicode characters
_ZERO_WIDTH_CHARS = [
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u00ad",  # Soft Hyphen
    "\u034f",  # Combining Grapheme Joiner
    "\u180e",  # Mongolian Vowel Separator
]

_ZERO_WIDTH_PATTERN = re.compile(
    "[" + "".join(re.escape(c) for c in _ZERO_WIDTH_CHARS) + "]+"
)


@register_rule
class ZeroWidthRule(BaseRule):
    rule_id = "zero_width"
    rule_name = "Zero-Width Character Encoding"
    category = "steganography"
    default_risk = RiskLevel.critical
    description = (
        "Detects zero-width spaces, joiners, and other invisible Unicode characters "
        "that may encode hidden text."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            for m in _ZERO_WIDTH_PATTERN.finditer(line):
                chars_found = sorted({hex(ord(c)) for c in m.group(0)})
                before, line_text, after = self._build_context(lines, line_idx)
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=self.default_risk,
                        line_no=line_idx + 1,
                        col=m.start() + 1,
                        end_col=m.end() + 1,
                        matched=repr(m.group(0)),
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            f"Detected invisible Unicode characters that may encode hidden text: "
                            f"{', '.join(chars_found)}"
                        ),
                    )
                )
                fid += 1

        return findings

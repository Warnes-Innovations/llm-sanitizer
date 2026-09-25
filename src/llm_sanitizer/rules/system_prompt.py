# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 5: System Prompt Markers."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import (
    BaseRule,
    deadline_exceeded,
    is_legitimate_file,
    line_number_at,
    newline_offsets,
    register_rule,
)

# XML-style system prompt markers
_XML_MARKERS = re.compile(
    r'<\s*(?:system|instructions?|system_prompt|SYS)\s*>',
    re.IGNORECASE,
)

# Chat-style delimiters
_CHAT_DELIMITERS = re.compile(
    r'<\|im_start\|>\s*system|<\|system\|>|\[INST\]\s*<<SYS>>',
    re.IGNORECASE,
)

# Markdown headings that define system prompts
_MARKDOWN_SYSTEM_HEADINGS = re.compile(
    r'^#{1,3}\s*(?:system\s+prompt|instructions?\s+for\s+(?:ai|llm|claude|gpt|copilot)|'
    r'ai\s+instructions?|llm\s+instructions?|agent\s+instructions?|'
    r'system\s+instructions?|model\s+instructions?)',
    re.IGNORECASE | re.MULTILINE,
)

# Delimiter-style markers.
#
# The leading indentation is `[^\S\n]*` (horizontal whitespace only), NOT
# `\s*`. `(?:^|\n)` gives O(n) start positions; a greedy `\s*` there swallows
# the whole remaining whitespace run and backtracks one character at a time
# through the alternation below, which is O(n) work at each of O(n) starts —
# quadratic, and uninterruptible because it happens inside a single C-level
# `re.search` that never returns to Python for a `deadline_exceeded()` check.
# No coverage is lost: `(?:^|\n)` already matches at the newline immediately
# before the marker's own line, so a marker preceded by blank lines is still
# found (and with the right line number). Do NOT change this back to `\s*`.
_DELIMITER_MARKERS = re.compile(
    r'(?:^|\n)[^\S\n]*(?:---\s*SYSTEM\s*---|'
    r'\[SYSTEM\]|\{system_prompt:|'
    r'#{1,3}\s*SYSTEM\s*:|'
    r'@system\s+prompt)',
    re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_XML_MARKERS, "XML-style system prompt tag"),
    (_CHAT_DELIMITERS, "Chat-style system delimiter"),
    (_MARKDOWN_SYSTEM_HEADINGS, "Markdown system prompt heading"),
    (_DELIMITER_MARKERS, "Delimiter-style system prompt marker"),
]


@register_rule
class SystemPromptRule(BaseRule):
    rule_id = "system_prompt"
    rule_name = "System Prompt Markers"
    category = "structural"
    default_risk = RiskLevel.high
    description = (
        "Detects structural markers that define system-level LLM instructions, "
        "such as XML tags, chat delimiters, and markdown headings."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        # Before the input-proportional setup, not only inside the loops below
        # — the deadline is only as fine-grained as the longest step between
        # two checks (issue #56).
        if deadline_exceeded():
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        # Lower risk for legitimate instruction files
        base_risk = RiskLevel.medium if is_legitimate_file(source) else self.default_risk

        offsets = newline_offsets(content)
        for pattern, label in _PATTERNS:
            if deadline_exceeded():
                break
            for m in pattern.finditer(content):
                if deadline_exceeded():
                    break
                line_no = line_number_at(offsets, m.start())
                col = m.start() - (content.rfind("\n", 0, m.start()) + 1) + 1
                before, line_text, after = self._build_context(lines, line_no)
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=base_risk,
                        line_no=line_no + 1,
                        col=col,
                        end_col=col + len(m.group(0)),
                        matched=m.group(0).strip()[:200],
                        matched_raw=m.group(0).strip(),
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            f"Detected system prompt marker: {label}. "
                            "This structural element defines system-level LLM instructions."
                        ),
                    )
                )
                fid += 1

        return findings

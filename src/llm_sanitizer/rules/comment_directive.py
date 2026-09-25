# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 7: Markdown/HTML Comment Directives."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import (
    BaseRule,
    deadline_exceeded,
    line_number_at,
    newline_offsets,
    register_rule,
)

# HTML comments containing AI/LLM directives
_HTML_AI_COMMENT = re.compile(
    r'<!--\s*(?:instructions?\s+for\s+(?:ai|llm|gpt|claude|copilot|assistant)|'
    r'ai\s+(?:instruction|directive|prompt|note)|'
    r'llm[:\s]|'
    r'(?:ignore|override|forget|disregard)\b[^-]*)',
    re.IGNORECASE | re.DOTALL,
)

# Markdown link-reference style comments [//]: # (...)
#
# BOTH gaps are bounded, and both must stay bounded. With `[^)]*` on either
# side of the keyword alternation this was the worst backtracker in the
# package: `[//]: #(` costs O(n) to scan for a `)` that is not there, and the
# marker itself supplies O(n) start positions, so the total is quadratic —
# measured at 11.9 s of CPU on 16 KB, with a fitted exponent of up to 2.97
# because the two gaps compound. It is not interruptible: `max_scan_seconds`
# is never consulted inside a single `re.search`.
#
# Neither a possessive tail (`[^)\n]*+`) nor excluding `[` from the gap fixes
# it — both were measured and both stayed quadratic (exponent 2.0+), because
# each still performs one unbounded scan at each of O(n) start positions. Only
# bounding every unbounded scan works.
#
# 200/200 was chosen by measurement, not taste: it costs ~3.7 s/MB on the
# adversarial shape, against ~3.4 s/MB for `data_exfil._CRED_EXFIL_PATTERNS[0]`
# — an already-shipping linear pattern — so this is now in line with the rest
# of the package rather than an outlier. 300/300 costs 8 s/MB and 400/400
# costs 11.7 s/MB, because the two bounds compound.
#
# THIS NARROWS DETECTION, deliberately, and the trade was made knowingly:
#   * the parenthesised content must be on ONE line (`[^)\n]`, not `[^)]`) — a
#     markdown link-reference definition is single-line, so this is also a
#     correctness fix, but it is a narrowing;
#   * a keyword more than 200 characters after `(`, or a `)` more than 200
#     characters after the keyword, no longer matches — so a padded comment
#     evades THIS rule.
# The padded payload is still read by the injection rules, which scan the raw
# content and do not care that it sits inside a comment; this rule's job is the
# comment wrapper, not the instruction text.
_MD_COMMENT_GAP = 200
_MD_COMMENT = re.compile(
    r'\[//\]:[^\S\n]*#[^\S\n]*\([^)\n]{0,' + str(_MD_COMMENT_GAP) + r'}'
    r'(?:ai|llm|instruction|prompt|ignore|override)'
    r'[^)\n]{0,' + str(_MD_COMMENT_GAP) + r'}\)',
    re.IGNORECASE,
)

# CSS/JS comments with LLM directives
_CSS_JS_AI_COMMENT = re.compile(
    r'/\*\s*(?:llm[:\s]|ai\s+(?:instruction|directive)|'
    r'(?:ignore|override)\s+(?:user|previous))[^*]*\*/',
    re.IGNORECASE | re.DOTALL,
)

# Hash-style comments (Python/YAML/shell) with AI directives
_HASH_AI_COMMENT = re.compile(
    r'#\s*(?:ai[- ](?:directive|instruction|note|prompt)[:\s]|'
    r'llm[:\s]|'
    r'(?:for|to)\s+(?:the\s+)?(?:ai|llm|assistant|agent)[:\s])',
    re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], RiskLevel, str]] = [
    (_HTML_AI_COMMENT, RiskLevel.high, "HTML comment AI directive"),
    (_MD_COMMENT, RiskLevel.high, "Markdown comment AI directive"),
    (_CSS_JS_AI_COMMENT, RiskLevel.high, "CSS/JS comment AI directive"),
    (_HASH_AI_COMMENT, RiskLevel.medium, "Hash-style comment AI directive"),
]


@register_rule
class CommentDirectiveRule(BaseRule):
    rule_id = "comment_directive"
    rule_name = "Comment Directives"
    category = "injection"
    default_risk = RiskLevel.high
    description = (
        "Detects LLM instructions hidden inside HTML/CSS/markdown/code comments "
        "that are invisible to human readers."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        # Before the input-proportional setup, not only inside the loops below
        # — the deadline is only as fine-grained as the longest step between
        # two checks (issue #56).
        if deadline_exceeded():
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        offsets = newline_offsets(content)
        fid = 1

        for pattern, risk, label in _PATTERNS:
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
                        risk=risk,
                        line_no=line_no + 1,
                        col=col,
                        end_col=col + len(m.group(0).splitlines()[0]),
                        matched=m.group(0).strip()[:200],
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            f"Detected {label}: LLM instruction hidden in a comment "
                            "that is invisible to human readers."
                        ),
                    )
                )
                fid += 1

        return findings

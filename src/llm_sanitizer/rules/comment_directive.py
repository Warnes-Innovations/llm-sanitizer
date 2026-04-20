# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 7: Markdown/HTML Comment Directives."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# HTML comments containing AI/LLM directives
_HTML_AI_COMMENT = re.compile(
    r'<!--\s*(?:instructions?\s+for\s+(?:ai|llm|gpt|claude|copilot|assistant)|'
    r'ai\s+(?:instruction|directive|prompt|note)|'
    r'llm[:\s]|'
    r'(?:ignore|override|forget|disregard)\b[^-]*)',
    re.IGNORECASE | re.DOTALL,
)

# Markdown link-reference style comments [//]: # (...)
_MD_COMMENT = re.compile(
    r'\[//\]:\s*#\s*\([^)]*(?:ai|llm|instruction|prompt|ignore|override)[^)]*\)',
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
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for pattern, risk, label in _PATTERNS:
            for m in pattern.finditer(content):
                line_no = content[: m.start()].count("\n")
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

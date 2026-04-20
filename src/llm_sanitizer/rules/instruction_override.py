# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 1: Instruction Override Phrases."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# Patterns that attempt to override or reset prior LLM instructions
_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
    r"forget\s+(everything|all)(\s+above|\s+before|\s+prior)?",
    r"new\s+system\s+prompt",
    r"override[:\s]+you\s+are\s+now",
    r"you\s+are\s+now\s+(?:a|an|the)\s+\w+",
    r"from\s+now\s+on[\s,]+ignore",
    r"override\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|guidelines?)",
    r"reset\s+(?:all\s+)?(?:previous|prior)?\s*(?:instructions?|rules?|settings?)",
    r"do\s+not\s+follow\s+(?:previous|prior|your)\s+instructions?",
    r"stop\s+following\s+(?:previous|prior|your)\s+instructions?",
    r"replace\s+(?:all\s+)?(?:your|the)\s+(?:system\s+)?(?:instructions?|prompt)",
    r"clear\s+(?:all\s+)?(?:your|the)?\s*(?:previous\s+)?(?:instructions?|context|memory)",
    r"(?:your\s+)?new\s+(?:primary\s+)?(?:directive|objective|goal|mission|purpose)\s+is",
    r"act\s+as\s+if\s+(?:you\s+)?(?:have\s+)?no\s+(?:previous\s+)?instructions?",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _PATTERNS]


@register_rule
class InstructionOverrideRule(BaseRule):
    rule_id = "instruction_override"
    rule_name = "Instruction Override Phrases"
    category = "injection"
    default_risk = RiskLevel.high
    description = "Detects phrases that attempt to override or reset prior LLM instructions."

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            for pattern in _COMPILED:
                for m in pattern.finditer(line):
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
                            matched=m.group(0),
                            before=before,
                            line_text=line_text,
                            after=after,
                            explanation=(
                                "Detected instruction override phrase attempting to reset agent behavior."
                            ),
                        )
                    )
                    fid += 1
                    break  # one finding per pattern per line

        return findings

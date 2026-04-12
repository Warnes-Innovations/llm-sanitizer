# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 6: Data Exfiltration Attempts."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

_PATTERNS = [
    re.compile(r'output\s+(?:all\s+)?(?:previous|prior|your|the)\s+instructions?', re.IGNORECASE),
    re.compile(r'repeat\s+(?:the|your)\s+system\s+prompt', re.IGNORECASE),
    re.compile(r'what\s+are\s+your\s+(?:instructions?|rules?|guidelines?|directives?)', re.IGNORECASE),
    re.compile(r'show\s+(?:me\s+)?your\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'print\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'reveal\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|secret)', re.IGNORECASE),
    re.compile(r'(?:tell|share)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'(?:leak|dump|expose)\s+(?:the|your)?\s*(?:system\s+)?(?:prompt|instructions?|context)', re.IGNORECASE),
    re.compile(r'summarize\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|context)', re.IGNORECASE),
    re.compile(r'(?:what|which)\s+(?:were|are)\s+you\s+(?:told|instructed|trained|programmed)\s+to\b', re.IGNORECASE),
    re.compile(r'reproduce\s+(?:verbatim|exactly|word\s+for\s+word)\s+(?:your|the)?\s*(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'send\s+(?:the\s+)?(?:conversation|chat|context|history)\s+to\b', re.IGNORECASE),
    re.compile(r'exfiltrate\b', re.IGNORECASE),
    re.compile(r'append\s+to\s+(?:every|each|all)\s+(?:response|answer|reply)', re.IGNORECASE),
]


@register_rule
class DataExfilRule(BaseRule):
    rule_id = "data_exfil"
    rule_name = "Data Exfiltration Attempts"
    category = "injection"
    default_risk = RiskLevel.high
    description = "Detects phrases designed to extract the agent's system prompt, context, or conversation."

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            for pattern in _PATTERNS:
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
                                "Detected data exfiltration phrase attempting to extract "
                                "the agent's system prompt or conversation context."
                            ),
                        )
                    )
                    fid += 1
                    break  # one finding per pattern per line

        return findings

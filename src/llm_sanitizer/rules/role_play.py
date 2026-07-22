# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 4: Role-Play Injection."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, deadline_exceeded, register_rule

_PATTERNS = [
    # "act as" (H5/SP-1 precision fix): the bare phrase over-matched benign prose
    # ("act as a proxy/bridge/catalyst"). Require an unconstrained-persona cue or
    # an explicit removal-of-constraints clause instead.
    (re.compile(r'\bact\s+as\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,2}?(?:jailbroken|unrestricted|unfiltered|uncensored|unconstrained|unethical|amoral|evil|rogue|lawless|DAN)\b', re.IGNORECASE), "act-as unconstrained persona"),
    (re.compile(r'\bact\s+as\b[^.\n]{0,40}?(?:without\s+(?:any\s+)?|with\s+no\s+|\bno\s+)(?:restrictions?|limits?|rules?|filters?|guidelines?|ethics?|constraints?|guardrails?|safeguards?)', re.IGNORECASE), "act-as no-constraints persona"),
    (re.compile(r'\bpretend\s+(?:you\s+are|to\s+be)\b', re.IGNORECASE), "pretend persona"),
    (re.compile(r'\byou\s+are\s+(?:now\s+)?(?:a|an|the)\s+\w+\s+(?:without|with\s+no)', re.IGNORECASE), "unconstrained persona"),
    # "from now on you …" (H5/SP-1 precision fix): require a persona/behavior-
    # change object so benign "from now on you will receive updates" stays clean.
    (re.compile(r'\bfrom\s+now\s+on,?\s+you\s+(?:are\s+(?:now\s+)?(?:a|an|the|no\s+longer)\b|will\s+(?:act|behave|respond\s+only|pretend|be\s+(?:a|an|the))|must\s+(?:act|behave|pretend|only|ignore)|should\s+(?:act|behave|pretend)|can\s+(?:ignore|do\s+anything))', re.IGNORECASE), "persistent persona override"),
    (re.compile(r'\byour\s+new\s+(?:role|identity|persona|name)\s+is\b', re.IGNORECASE), "new role assignment"),
    # "DAN" is matched case-SENSITIVELY (via (?-i:DAN)): under IGNORECASE the
    # token matched the ordinary name "Dan", flooding HIGH false positives on
    # emails/chat/commit logs. The jailbreak is spelled all-caps.
    (re.compile(r'\b(?:do\s+anything\s+now|(?-i:DAN))\b', re.IGNORECASE), "DAN jailbreak"),
    (re.compile(r'\bjailbreak\b', re.IGNORECASE), "jailbreak keyword"),
    (re.compile(r'\byou\s+(?:have|had)\s+no\s+(?:restrictions?|limits?|rules?|guidelines?|ethics?)\b', re.IGNORECASE), "restriction removal"),
    (re.compile(r'\bbehave\s+as\s+(?:if|though)\s+you\s+(?:have|had)\s+no\b', re.IGNORECASE), "unconstrained behavior"),
    (re.compile(r'\bstay\s+in\s+character\b', re.IGNORECASE), "character persistence"),
    (re.compile(r'\benter\s+(?:developer|dev|god|jailbreak)\s+mode\b', re.IGNORECASE), "special mode activation"),
    (re.compile(r'\bsimulate\s+(?:a|an)\s+(?:AI|LLM|system)\s+(?:without|with\s+no)\b', re.IGNORECASE), "unconstrained simulation"),
]


@register_rule
class RolePlayRule(BaseRule):
    rule_id = "role_play"
    rule_name = "Role-Play Injection"
    category = "injection"
    default_risk = RiskLevel.high
    description = "Detects phrases attempting to assign the LLM a new identity or bypass constraints via role-play."

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            if deadline_exceeded():
                return findings
            for pattern, label in _PATTERNS:
                for m in pattern.finditer(line):
                    if deadline_exceeded():
                        return findings
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
                                f"Detected role-play injection phrase ({label}) "
                                "attempting to assign a new identity or bypass constraints."
                            ),
                        )
                    )
                    fid += 1
                    # No per-line cap: minified/single-line content can carry
                    # many instances, and redaction removes only reported spans.

        return findings

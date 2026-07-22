# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 1: Instruction Override Phrases."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, deadline_exceeded, register_rule

# Override verbs × override nouns as a CROSS-PRODUCT (RT F11): hand-written
# verb+noun phrase pairs silently miss the N×M combinations never spelled out
# (e.g. "ignore" was only paired with "instructions", so "ignore the guidance"
# slipped through). Composing verb-alternation × noun-alternation covers every
# combination automatically.
_OVERRIDE_VERB = (
    r"(?:ignore|disregard|forget|discard|drop|skip|bypass|override|reset|"
    r"set\s+aside|put\s+aside|pay\s+no\s+attention\s+to|"
    r"do\s+not\s+follow|stop\s+following)"
)
_OVERRIDE_NOUN = (
    r"(?:instructions?|guidance|guidelines?|rules?|directions?|directives?|"
    r"prompt|context|constraints?|restrictions?)"
)
# Optional qualifier words between verb and noun (all/any/the/your/prior/…).
_OVERRIDE_QUAL = (
    r"(?:(?:all|any|the|your|these|those|prior|previous|earlier|above|"
    r"preceding|original|initial|system)\s+)*"
)

# Patterns that attempt to override or reset prior LLM instructions
_PATTERNS = [
    _OVERRIDE_VERB + r"\s+" + _OVERRIDE_QUAL + _OVERRIDE_NOUN,
    r"ignore\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
    r"forget\s+(everything|all)(\s+above|\s+before|\s+prior)?",
    r"new\s+system\s+prompt",
    r"override[:\s]+you\s+are\s+now",
    # Role reassignment to an AI persona (H5/SP-1 precision fix): require an
    # AI-persona noun so benign "you are now the owner/admin/winner" does not
    # fire. Unconstrained-persona phrasing ("you are now a bot with no rules")
    # is additionally covered by the role_play rule.
    r"you\s+are\s+now\s+(?:a|an|the)\s+(?:\w+\s+){0,2}?(?:AI|assistant|language\s+model|model|LLM|chatbot|persona)\b",
    r"from\s+now\s+on[\s,]+ignore",
    r"override\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|guidelines?)",
    r"reset\s+(?:all\s+)?(?:previous|prior)?\s*(?:instructions?|rules?|settings?)",
    r"do\s+not\s+follow\s+(?:previous|prior|your)\s+instructions?",
    r"stop\s+following\s+(?:previous|prior|your)\s+instructions?",
    r"replace\s+(?:all\s+)?(?:your|the)\s+(?:system\s+)?(?:instructions?|prompt)",
    r"clear\s+(?:all\s+)?(?:your|the)?\s*(?:previous\s+)?(?:instructions?|context|memory)",
    r"(?:your\s+)?new\s+(?:primary\s+)?(?:directive|objective|goal|mission|purpose)\s+is",
    r"act\s+as\s+if\s+(?:you\s+)?(?:have\s+)?no\s+(?:previous\s+)?instructions?",
    # Paraphrased overrides NOT expressible as verb×noun (RT F1). "set/put aside"
    # and "pay no attention to" are now covered by the cross-product above.
    r"(?:instead\s+of|rather\s+than)\s+(?:following\s+)?(?:your|the)\s+(?:original\s+|previous\s+|prior\s+)?(?:task|instructions?|guidance|directions?)",
    r"your\s+(?:real|actual|true|updated|new|revised)\s+(?:task|objective|instructions?|directive)\s+(?:is|are)\b",
    # High-confidence non-English overrides (M3). Vocabulary-bounded stopgap for
    # the most common languages; the durable fix for arbitrary phrasings/
    # languages is the semantic-intent layer tracked in OBO. Accents optional so
    # both "précédentes" and "precedentes" match.
    r"ignorez\s+(?:toutes\s+)?(?:les\s+)?instructions",          # French
    r"ignora\s+(?:todas\s+)?(?:las\s+)?instrucciones",           # Spanish
    r"ignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni",               # Italian
    r"ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?anweisungen",    # German
    r"ignore\s+(?:todas\s+)?(?:as\s+)?instru[çc][õo]es",         # Portuguese
    r"пропустите\s+(?:все\s+)?(?:предыдущие\s+)?инструкции",     # Russian
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
            if deadline_exceeded():
                return findings
            for pattern in _COMPILED:
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
                                "Detected instruction override phrase attempting to reset agent behavior."
                            ),
                        )
                    )
                    fid += 1
                    # No per-line cap: minified/single-line content can carry
                    # many instances, and redaction removes only reported spans.

        return findings

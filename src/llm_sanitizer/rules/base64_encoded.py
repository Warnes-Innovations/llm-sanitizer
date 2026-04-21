# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 8: Base64-Encoded Content."""

from __future__ import annotations

import base64
import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# Minimum length to avoid false positives on short base64-looking tokens
_MIN_B64_LENGTH = 40

_B64_PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{' + str(_MIN_B64_LENGTH) + r',}={0,2})(?![A-Za-z0-9+/=])'
)

# Keywords that suggest instruction-like decoded content
_INSTRUCTION_KEYWORDS = [
    "ignore", "override", "forget", "disregard", "system prompt",
    "instructions", "you are", "act as", "from now on", "jailbreak",
    "do anything", "pretend", "reveal", "exfiltrate", "repeat the",
]


def _contains_instruction_keywords(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _INSTRUCTION_KEYWORDS)


def _try_decode_base64(s: str) -> str | None:
    """Attempt to decode a base64 string. Return decoded text or None."""
    # Pad if needed
    padded = s + "=" * ((-len(s)) % 4)
    try:
        decoded_bytes = base64.b64decode(padded)
        # Try UTF-8 first, then latin-1
        try:
            text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = decoded_bytes.decode("latin-1")
            except UnicodeDecodeError:
                return None
        # Must be mostly printable
        printable = sum(c.isprintable() for c in text)
        if len(text) > 0 and printable / len(text) > 0.8:
            return text
    except Exception:
        pass
    return None


@register_rule
class Base64EncodedRule(BaseRule):
    rule_id = "base64_encoded"
    rule_name = "Base64-Encoded Content"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects base64-encoded strings that decode to instruction-like content. "
        "Two-pass: find base64, decode, re-scan for instruction keywords."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            for m in _B64_PATTERN.finditer(line):
                candidate = m.group(1)
                decoded = _try_decode_base64(candidate)
                if decoded and _contains_instruction_keywords(decoded):
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
                            matched=candidate[:80] + ("..." if len(candidate) > 80 else ""),
                            matched_raw=candidate,
                            before=before,
                            line_text=line_text,
                            after=after,
                            explanation=(
                                f"Detected base64-encoded content that decodes to instruction-like text: "
                                f"{decoded[:100]!r}"
                            ),
                        )
                    )
                    fid += 1

        return findings

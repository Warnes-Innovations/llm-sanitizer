# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 9: Unicode Homoglyph Substitution."""

from __future__ import annotations

import re
import unicodedata

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# Map of common homoglyphs (non-Latin → Latin equivalent)
# Cyrillic, Greek, and other Unicode characters that look like Latin letters
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic а → a
    "\u0435": "e",  # Cyrillic е → e
    "\u043e": "o",  # Cyrillic о → o
    "\u0440": "r",  # Cyrillic р → r
    "\u0441": "c",  # Cyrillic с → c
    "\u0445": "x",  # Cyrillic х → x
    "\u0443": "y",  # Cyrillic у → y
    "\u0456": "i",  # Cyrillic і → i
    "\u0454": "e",  # Cyrillic є → e
    "\u0458": "j",  # Cyrillic ј → j
    # Greek lookalikes
    "\u03bf": "o",  # Greek ο → o
    "\u03b1": "a",  # Greek α → a
    "\u03b5": "e",  # Greek ε → e
    "\u03b9": "i",  # Greek ι → i
    "\u03bd": "v",  # Greek ν → v
    "\u03c1": "p",  # Greek ρ → p
    # Latin Extended lookalikes
    "\u00e0": "a",  # à → a
    "\u00e1": "a",  # á → a
    "\u00e9": "e",  # é → e
    "\u00ed": "i",  # í → i
    "\u00f3": "o",  # ó → o
    "\u00fa": "u",  # ú → u
}

# Instruction-like keywords to check after normalization
_SUSPICIOUS_TERMS = [
    "ignore", "override", "forget", "disregard", "system",
    "instructions", "jailbreak", "bypass", "exfiltrate",
]

# Pattern to detect runs of non-ASCII letters in otherwise ASCII text
_MIXED_SCRIPT_PATTERN = re.compile(r'[^\x00-\x7f]{2,}')


def _normalize_homoglyphs(text: str) -> str:
    """Replace known homoglyph characters with their Latin equivalents."""
    return "".join(_HOMOGLYPHS.get(c, c) for c in text)


def _has_homoglyphs(text: str) -> bool:
    """Return True if the text contains any homoglyph characters."""
    return any(c in _HOMOGLYPHS for c in text)


def _is_mixed_script(word: str) -> bool:
    """Return True if a word mixes Latin and non-Latin script characters."""
    scripts: set[str] = set()
    for c in word:
        if c.isalpha():
            name = unicodedata.name(c, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
    return len(scripts) > 1


@register_rule
class HomoglyphRule(BaseRule):
    rule_id = "homoglyph"
    rule_name = "Unicode Homoglyph Substitution"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects visually identical characters from different Unicode scripts "
        "used to bypass text-based filters."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            if not _has_homoglyphs(line):
                continue
            # Check each word for homoglyph substitution
            for word_match in re.finditer(r'\b\w+\b', line):
                word = word_match.group(0)
                if not _has_homoglyphs(word):
                    continue
                normalized = _normalize_homoglyphs(word)
                # Flag if: (a) word mixes scripts or (b) normalized form is a suspicious term
                is_suspicious_term = any(term in normalized.lower() for term in _SUSPICIOUS_TERMS)
                is_mixed = _is_mixed_script(word)
                if is_suspicious_term or is_mixed:
                    before, line_text, after = self._build_context(lines, line_idx)
                    findings.append(
                        self._make_finding(
                            finding_id=fid,
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            risk=self.default_risk,
                            line_no=line_idx + 1,
                            col=word_match.start() + 1,
                            end_col=word_match.end() + 1,
                            matched=word,
                            before=before,
                            line_text=line_text,
                            after=after,
                            explanation=(
                                f"Detected Unicode homoglyph substitution: {word!r} "
                                f"→ normalized as {normalized!r}. "
                                "Visually identical to a suspicious keyword but uses non-Latin characters."
                            ),
                        )
                    )
                    fid += 1

        return findings

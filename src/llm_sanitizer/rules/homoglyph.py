# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 9: Unicode Homoglyph Substitution."""

from __future__ import annotations

import re
import unicodedata

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule

# Map of cross-script homoglyphs (non-Latin → Latin equivalent). Only genuine
# cross-script lookalikes belong here — plain accented Latin letters (à, é,
# etc., formerly listed under "Latin Extended lookalikes") are NOT homoglyphs
# in any adversarial sense; unicodedata still classifies them as LATIN script
# (e.g. "LATIN SMALL LETTER E WITH ACUTE"), and they're ordinary diacritics in
# French/Spanish/Portuguese text and countless English loanwords and names
# (cafe, resume, Jose, naive — with accents in the original). Including them
# here previously caused this rule to fire on routine internationalized text
# with no relationship to a bypass attempt.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a",  # Cyrillic а → a
    "е": "e",  # Cyrillic е → e
    "о": "o",  # Cyrillic о → o
    "р": "r",  # Cyrillic р → r
    "с": "c",  # Cyrillic с → c
    "х": "x",  # Cyrillic х → x
    "у": "y",  # Cyrillic у → y
    "і": "i",  # Cyrillic і → i
    "є": "e",  # Cyrillic є → e
    "ј": "j",  # Cyrillic ј → j
    # Greek lookalikes
    "ο": "o",  # Greek ο → o
    "α": "a",  # Greek α → a
    "ε": "e",  # Greek ε → e
    "ι": "i",  # Greek ι → i
    "ν": "v",  # Greek ν → v
    "ρ": "p",  # Greek ρ → p
}

# Instruction-like keywords to check after normalization. Matched as whole
# words (see is_suspicious_term below), not substrings — add inflected forms
# here directly (e.g. "ignoring") rather than loosening the match back to a
# substring check, which previously matched "system" inside "filesystem" /
# "ecosystem" / "systematic" / "systemic" / etc.
_SUSPICIOUS_TERMS = frozenset([
    "ignore", "override", "forget", "disregard", "system",
    "instructions", "jailbreak", "bypass", "exfiltrate",
])

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


def _is_suspicious_term(normalized_word: str) -> bool:
    """Return True if the normalized word is exactly one of the known
    instruction-override-style terms (whole-word match, not substring —
    "system" must not match "filesystem"/"ecosystem"/"systematic"/etc.)."""
    return normalized_word.lower() in _SUSPICIOUS_TERMS


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
                suspicious_term = _is_suspicious_term(normalized)
                mixed_script = _is_mixed_script(word)
                if not (suspicious_term or mixed_script):
                    continue
                # High risk requires both signals together — a mixed-script word
                # that doesn't normalize to a known instruction-override term is
                # much weaker evidence (could be a name, math notation, or a
                # documentation example) than one that also spells out something
                # like "ignore"/"bypass"/"jailbreak" once normalized.
                risk = RiskLevel.high if (suspicious_term and mixed_script) else RiskLevel.medium
                before, line_text, after = self._build_context(lines, line_idx)
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=risk,
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

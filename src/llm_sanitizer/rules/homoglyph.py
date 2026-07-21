# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 9: Unicode Homoglyph Substitution.

Homoglyph substitution is an obfuscation layer, so — like base64 — it is only a
problem if de-obfuscating reveals something problematic. This rule normalizes
cross-script lookalikes back to their Latin equivalents and then asks whether
the *normalized* text is actually suspicious, via two signals:

  1. a normalized word that is exactly a known instruction-override term
     ("ignore", "override", "bypass", …), and
  2. the full detection ruleset re-run over the normalized text
     (:func:`scan_deobfuscated`), catching phrase-level injections the disguise
     was hiding.

Crucially, mixed-script text that normalizes to something innocent (``Aβ``,
``5µm``, ``10kΩ``, ``сystem`` → "cystem", ``fileсystem`` → "filesystem") is NOT
flagged — mixing scripts is not, by itself, an attack. This removes a large
false-positive class over scientific / internationalized text.
"""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import scan_deobfuscated

# Map of cross-script homoglyphs (non-Latin → Latin equivalent). Only genuine
# cross-script lookalikes belong here — plain accented Latin letters (à, é,
# etc.) are NOT homoglyphs in any adversarial sense (unicodedata still
# classifies them as LATIN script) and are ordinary internationalized text.
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

# Instruction-like keywords checked after normalization. Matched as whole words
# (see _is_suspicious_term), not substrings — add inflected forms here directly
# rather than loosening to a substring check, which previously matched "system"
# inside "filesystem" / "ecosystem" / "systematic" / etc.
_SUSPICIOUS_TERMS = frozenset([
    "ignore", "override", "forget", "disregard", "system",
    "instructions", "jailbreak", "bypass", "exfiltrate",
])


def _normalize_homoglyphs(text: str) -> str:
    """Replace known homoglyph characters with their Latin equivalents. The
    substitution is 1 character → 1 character, so positions are preserved and a
    finding's line/column in the normalized text maps back to the original."""
    return "".join(_HOMOGLYPHS.get(c, c) for c in text)


def _has_non_ascii_letter(text: str) -> bool:
    """True if *text* contains any non-ASCII alphabetic character — the trigger
    to examine a word for homoglyph disguise."""
    return any(c.isalpha() and ord(c) > 127 for c in text)


def _is_suspicious_term(normalized_word: str) -> bool:
    """True if the normalized word is exactly one of the known
    instruction-override-style terms (whole-word match, not substring)."""
    return normalized_word.lower() in _SUSPICIOUS_TERMS


@register_rule
class HomoglyphRule(BaseRule):
    rule_id = "homoglyph"
    rule_name = "Unicode Homoglyph Substitution"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects visually identical characters from different Unicode scripts "
        "used to disguise instruction-override content — flagged only when "
        "normalizing the lookalikes reveals a suspicious term or a real "
        "injection, not merely because scripts are mixed."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        lines = content.splitlines()
        # Keyed by (line, column) so the two signals below don't double-report
        # the same span; higher-risk finding wins on collision.
        by_location: dict[tuple[int, int], Finding] = {}
        fid = 1

        # Signal 1: a single word that de-homoglyphs to a known suspicious term.
        for line_idx, line in enumerate(lines):
            if not _has_non_ascii_letter(line):
                continue
            for word_match in re.finditer(r"\b\w+\b", line):
                word = word_match.group(0)
                if not _has_non_ascii_letter(word):
                    continue
                normalized = _normalize_homoglyphs(word)
                if normalized == word:
                    continue  # no mapped homoglyph — nothing was de-obfuscated
                if not _is_suspicious_term(normalized):
                    continue
                before, line_text, after = self._build_context(lines, line_idx)
                loc = (line_idx + 1, word_match.start() + 1)
                by_location[loc] = self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=RiskLevel.high,
                    line_no=line_idx + 1,
                    col=word_match.start() + 1,
                    end_col=word_match.end() + 1,
                    matched=word,
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        f"Unicode homoglyph substitution: {word!r} normalized as "
                        f"{normalized!r} — a known instruction-override term."
                    ),
                )
                fid += 1

        # Signal 2: de-homoglyph the whole content and re-scan it, catching
        # phrase-level injections the disguise hid (beyond the single-word list).
        # Normalization is length-preserving, so sub-finding locations map back.
        normalized_content = _normalize_homoglyphs(content)
        if normalized_content != content:
            # Only credit findings that appear AFTER normalization but not
            # before — i.e. that the de-homoglyphing actually revealed. Without
            # this baseline diff, an unrelated finding (e.g. a base64 injection
            # elsewhere) that trips identically on the raw content would be
            # double-reported and mis-attributed to homoglyph normalization.
            baseline_keys = {
                (f.rule, f.location.line, f.location.column)
                for f in scan_deobfuscated(content, source)
            }
            for sub in scan_deobfuscated(normalized_content, source):
                if (sub.rule, sub.location.line, sub.location.column) in baseline_keys:
                    continue  # present pre-normalization — not revealed by it
                loc = (sub.location.line, sub.location.column)
                if loc in by_location:
                    continue  # already reported by Signal 1
                line_idx = sub.location.line - 1
                before, line_text, after = self._build_context(lines, line_idx)
                by_location[loc] = self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=sub.risk,
                    line_no=sub.location.line,
                    col=sub.location.column,
                    end_col=sub.location.end_column,
                    matched=sub.matched,
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        "Unicode homoglyph substitution: normalizing lookalike "
                        f"characters reveals content flagged by {sub.rule_name}: "
                        f"{sub.explanation}"
                    ),
                )
                fid += 1

        # Highest-risk finding first (stable: Signal 1 precedes Signal 2 among
        # equal risk, so an explanation mentioning normalization leads).
        return sorted(by_location.values(), key=lambda f: f.risk.value, reverse=True)

# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 2: Zero-Width Character Encoding.

Zero-width / invisible characters are a *transport*, not a threat in themselves —
they occur legitimately (BOM, emoji ZWJ sequences, bidi marks, soft hyphens,
ZWNJ in Arabic/Indic scripts). They only matter when they are used to **split a
keyword** so an injection slips past the ordinary detection rules
(``ig<ZWSP>nore`` doesn't match "ignore"). So, like the other obfuscation rules,
this one *de-obfuscates* (strips the invisible characters) and re-scans: it fires
only when removing them reveals an injection the raw text did **not** already
trip. Innocent invisible characters (a BOM on a benign sentence, emoji joiners)
are left clean.
"""

from __future__ import annotations

import re
from collections import Counter

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import scan_deobfuscated

# Zero-width and invisible Unicode characters, defined by codepoint so the
# source stays pure-ASCII and each entry is unambiguous (the characters are, by
# definition, invisible and unsafe to embed literally).
_ZERO_WIDTH_CODEPOINTS = [
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x2060,  # Word Joiner
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
    0xFEFF,  # Zero Width No-Break Space (BOM)
    0x00AD,  # Soft Hyphen
    0x034F,  # Combining Grapheme Joiner
    0x180E,  # Mongolian Vowel Separator (formatting character)
]
_ZERO_WIDTH_CHARS = [chr(cp) for cp in _ZERO_WIDTH_CODEPOINTS]

_ZERO_WIDTH_PATTERN = re.compile(
    "[" + "".join(re.escape(c) for c in _ZERO_WIDTH_CHARS) + "]+"
)


@register_rule
class ZeroWidthRule(BaseRule):
    rule_id = "zero_width"
    rule_name = "Zero-Width Character Encoding"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects zero-width / invisible characters used to split a keyword and "
        "evade detection — flagged only when removing them reveals an injection "
        "the raw text did not already trip, not merely because they are present."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        # Evaluate each line independently: strip the invisible characters on
        # THIS line and compare what it trips against the raw line. Only when
        # stripping reveals an injection the raw line did not already trip do we
        # flag this line's invisible-character runs. Per-line (not whole-doc)
        # so a benign invisible character on one line is never flagged just
        # because a real keyword-split exists on a different line.
        for line_idx, line in enumerate(lines):
            stripped = _ZERO_WIDTH_PATTERN.sub("", line)
            if stripped == line:
                continue  # no invisible characters on this line
            revealed = scan_deobfuscated(stripped, source)
            if not revealed:
                continue
            baseline = Counter(f.rule for f in scan_deobfuscated(line, source))
            revealed_counts = Counter(f.rule for f in revealed)
            newly = {
                rule
                for rule, n in revealed_counts.items()
                if n > baseline.get(rule, 0)
            }
            if not newly:
                continue

            risk = max(
                (f.risk for f in revealed if f.rule in newly),
                key=lambda r: r.value,
            )
            tripped = ", ".join(sorted(newly))
            before, line_text, after = self._build_context(lines, line_idx)
            for m in _ZERO_WIDTH_PATTERN.finditer(line):
                chars_found = sorted({hex(ord(c)) for c in m.group(0)})
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=risk,
                        line_no=line_idx + 1,
                        col=m.start() + 1,
                        end_col=m.end() + 1,
                        matched=repr(m.group(0)),
                        matched_raw=m.group(0),
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            "Invisible characters "
                            f"({', '.join(chars_found)}) split text that, once "
                            f"removed, is flagged by {tripped} — the characters "
                            "are being used to evade keyword detection."
                        ),
                    )
                )
                fid += 1

        return findings

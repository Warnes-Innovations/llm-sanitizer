# Copyright (C) 2026 Gregory R. Warnes
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
from llm_sanitizer.rules import BaseRule, deadline_exceeded, register_rule
from llm_sanitizer.rules._rescan import scan_deobfuscated

# Zero-width and invisible Unicode characters, defined by codepoint so the
# source stays pure-ASCII and each entry is unambiguous (the characters are, by
# definition, invisible and unsafe to embed literally).
# EVERY Unicode format character (category Cf), plus the other code points
# that render as nothing: fillers, variation selectors, C0/C1 controls, and
# U+FFFD. A hand-picked list of "the zero-width ones" missed U+2066 (bidi
# isolate), U+061C, U+180B, U+3164, U+FE0F and the C0 controls, and each one
# hid a split keyword (0.7.2 review, pass 2). The Cf ranges are Unicode 15.1;
# tests/test_splitters.py::test_every_format_character_is_a_splitter
# checks them against the running interpreter's unicodedata, so a Unicode
# upgrade that adds a Cf character fails a test instead of opening a gap.
#
# Stripping any of these is harmless on its own: the rule flags only when the
# stripped text trips a rule the raw text did not (emoji ZWJ sequences,
# Arabic letter marks and bidi controls in ordinary text stay clean).
_FORMAT_RANGES = [
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD),
    (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001), (0xE0020, 0xE007F),
]
_OTHER_INVISIBLE_RANGES = [
    (0x034F, 0x034F),    # Combining Grapheme Joiner
    (0x115F, 0x1160),    # Hangul Choseong/Jungseong fillers
    (0x3164, 0x3164),    # Hangul Filler
    (0xFFA0, 0xFFA0),    # Halfwidth Hangul Filler
    (0x180B, 0x180D),    # Mongolian free variation selectors
    (0x180F, 0x180F),    # Mongolian free variation selector four
    (0xFE00, 0xFE0F),    # variation selectors
    (0xE0100, 0xE01EF),  # variation selectors supplement
    # C0 and C1 controls that do NOT end a line. Tab, LF and CR are ordinary
    # text; the line-ending controls are handled by _MIDWORD_LINE_SEPARATOR.
    (0x0000, 0x0008), (0x000E, 0x001B), (0x001F, 0x001F),
    (0x007F, 0x0084), (0x0086, 0x009F),
    # REPLACEMENT CHARACTER: what an undecodable byte becomes on a lossy read.
    # A raw 0xAD byte (a soft hyphen in Latin-1) inside each trigger word
    # arrived as U+FFFD, which nothing stripped (0.7.2).
    (0xFFFD, 0xFFFD),
]
_ZERO_WIDTH_CODEPOINTS = [
    cp for lo, hi in _FORMAT_RANGES + _OTHER_INVISIBLE_RANGES for cp in range(lo, hi + 1)
]
_ZERO_WIDTH_CHARS = [chr(cp) for cp in _ZERO_WIDTH_CODEPOINTS]

_ZERO_WIDTH_PATTERN = re.compile(
    "[" + "".join(re.escape(c) for c in _ZERO_WIDTH_CHARS) + "]+"
)

# Characters `str.splitlines` treats as line ends, other than LF/CR. Inside a
# word they split it across two "lines", so the per-line pass below never sees
# the word whole (0.7.2 review: NEL, U+2028, VT, FF). Only a separator with a
# word character on BOTH sides is treated as a splitter.
_MIDWORD_LINE_SEPARATOR = re.compile(
    "(?<=\\w)[\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]+(?=\\w)"
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
        fid = self._midword_line_separators(content, lines, source, findings, fid)
        for line_idx, line in enumerate(lines):
            if deadline_exceeded():
                return findings
            stripped = _ZERO_WIDTH_PATTERN.sub("", line)
            if stripped == line:
                continue  # no invisible characters on this line
            # TWO readings of the line. Removed: `ig<ZWSP>nore` -> `ignore`.
            # U+FFFD as a SPACE: an invalid byte standing in for the space
            # between words (`ignore<0xA0>all`) must not glue the words into
            # one token no rule matches (0.7.2 review, pass 2).
            spaced = _ZERO_WIDTH_PATTERN.sub("", line.replace("\ufffd", " "))
            revealed: list[Finding] = []
            for variant in {stripped, spaced}:
                revealed.extend(scan_deobfuscated(variant, source))
            if not revealed:
                continue
            baseline = Counter(f.rule for f in scan_deobfuscated(line, source))
            newly = self._newly(revealed, baseline)
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

    @staticmethod
    def _newly(revealed: list[Finding], baseline: Counter[str]) -> set[str]:
        counts = Counter(f.rule for f in revealed)
        return {rule for rule, n in counts.items() if n > baseline.get(rule, 0)}

    def _midword_line_separators(
        self, content: str, lines: list[str], source: str,
        findings: list[Finding], fid: int,
    ) -> int:
        """Line-ending characters used INSIDE a word, judged on the whole text."""
        matches = list(_MIDWORD_LINE_SEPARATOR.finditer(content))
        if not matches:
            return fid
        joined = _MIDWORD_LINE_SEPARATOR.sub("", content)
        revealed = scan_deobfuscated(joined, source)
        if not revealed:
            return fid
        newly = self._newly(
            revealed, Counter(f.rule for f in scan_deobfuscated(content, source))
        )
        if not newly:
            return fid
        risk = max((f.risk for f in revealed if f.rule in newly), key=lambda r: r.value)
        tripped = ", ".join(sorted(newly))
        # Line-start offsets under splitlines' OWN notion of a line, so the
        # reported line and column point at the separator itself (it ends the
        # fragment it follows).
        starts: list[int] = []
        offset = 0
        for piece in content.splitlines(keepends=True):
            starts.append(offset)
            offset += len(piece)
        for m in matches:
            line_idx = max(i for i, st in enumerate(starts) if st <= m.start())
            col = m.start() - starts[line_idx] + 1
            before, line_text, after = self._build_context(lines, line_idx)
            findings.append(
                self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=risk,
                    line_no=line_idx + 1,
                    col=col,
                    end_col=col + len(m.group(0)),
                    matched=repr(m.group(0)),
                    matched_raw=m.group(0),
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        "Line-separator characters "
                        f"({', '.join(sorted({hex(ord(c)) for c in m.group(0)}))}) "
                        f"inside a word split text that, once joined, is flagged "
                        f"by {tripped}."
                    ),
                )
            )
            fid += 1
        return fid

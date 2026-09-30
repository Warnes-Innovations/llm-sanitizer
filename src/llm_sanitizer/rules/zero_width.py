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

import bisect
import itertools
import re
from collections import Counter

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, deadline_exceeded, register_rule
from llm_sanitizer.rules._rescan import scan_deobfuscated

# Zero-width and invisible Unicode characters, defined by codepoint so the
# source stays pure-ASCII and each entry is unambiguous (the characters are, by
# definition, invisible and unsafe to embed literally).
# THREE CLASSES of character, because they hide text in different ways.
#
# ZERO-WIDTH: renders as nothing. Removed in every view. Built from Unicode's
# Default_Ignorable_Code_Point property and the whole Cf (format) category,
# plus C0/C1 controls — a hand-remembered list missed U+2066, U+061C, U+180B,
# U+17B4, U+2065, U+FFF0.. and the C0 controls, each of which hid a split
# keyword (0.7.2 review, passes 2 and 3). The Cf part is checked against the
# running interpreter's unicodedata by
# tests/test_splitters.py::test_every_format_character_is_a_splitter.
#
# SPACE-LIKE: renders as a blank gap (Hangul fillers, blank Braille, U+FFFD
# standing in for an undecodable byte). Could be a hidden SPACE or glue inside a
# word, so one view removes it and another reads it as a space.
#
# LINE-ENDING characters other than LF / CRLF (VT, FF, FS/GS/RS, NEL, U+2028,
# U+2029, a bare CR): `splitlines` cuts a word in two at them. Between two word
# characters they are treated like SPACE-LIKE (removed in one view, a space in
# the other); elsewhere they are left alone as real line breaks.
#
# Removing or spacing any of these is harmless on its own: the rule fires only
# when a view trips a rule the original text did not.
_DEFAULT_IGNORABLE_RANGES = [
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
]
_FORMAT_RANGES = [
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD),
    (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001), (0xE0020, 0xE007F),
]
_CONTROL_RANGES = [
    # C0/C1 controls that neither are ordinary whitespace (TAB, LF, CR) nor end
    # a line (those are the LINE-ENDING class).
    (0x0000, 0x0008), (0x000E, 0x001B), (0x001F, 0x001F),
    (0x007F, 0x0084), (0x0086, 0x009F),
    (0x1D159, 0x1D159),  # MUSICAL SYMBOL NULL NOTEHEAD — renders as nothing
]
_SPACE_LIKE_CODEPOINTS = [0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800]
_FFFD = 0xFFFD
_LINE_ENDING = "\x0b\x0c\x1c\x1d\x1e\x85  "


def _expand(ranges: list[tuple[int, int]]) -> set[int]:
    return {cp for lo, hi in ranges for cp in range(lo, hi + 1)}


_ZERO_WIDTH_SET = (
    _expand(_DEFAULT_IGNORABLE_RANGES) | _expand(_FORMAT_RANGES) | _expand(_CONTROL_RANGES)
) - set(_SPACE_LIKE_CODEPOINTS) - {_FFFD}
#: Every character this rule treats as a possible splitter.
_ZERO_WIDTH_CODEPOINTS = sorted(_ZERO_WIDTH_SET | set(_SPACE_LIKE_CODEPOINTS) | {_FFFD})
_ZERO_WIDTH_CHARS = [chr(cp) for cp in _ZERO_WIDTH_CODEPOINTS]


def _char_class(codepoints: set[int] | list[int]) -> str:
    """A regex character-class BODY for *codepoints*, as ranges. Listing 4,000+
    code points one by one (the whole E0000 plane among them) made the run
    pattern ~50x slower than the same set written as ranges."""
    cps = sorted(set(codepoints))
    parts: list[str] = []
    i = 0
    while i < len(cps):
        j = i
        while j + 1 < len(cps) and cps[j + 1] == cps[j] + 1:
            j += 1
        lo, hi = re.escape(chr(cps[i])), re.escape(chr(cps[j]))
        parts.append(lo if i == j else f"{lo}-{hi}")
        i = j + 1
    return "".join(parts)


_ZW = _char_class(_ZERO_WIDTH_SET)
_SP = _char_class(_SPACE_LIKE_CODEPOINTS)
_SEP = re.escape(_LINE_ENDING)
_RUN = re.compile(f"(?:[{_ZW}{_SP}\\ufffd{_SEP}]|\\r(?!\\n))+")
_LINE_END_IN_RUN = re.compile(f"[{_SEP}]|\\r")

# Each character belongs to ONE class, and each class gets its own role in a
# reading: REMOVED (glue inside a word) or a SPACE (a hidden word separator).
# Every combination of roles over the classes actually present is read, so a
# character of one class inside words with another class between them is found
# (0.7.2 review, pass 4: two global readings gave every class the same role at
# once). Two characters of the SAME class in both roles in one text are not
# separated by any reading — a documented limitation.
_ZW_CLASS, _SP_CLASS, _FFFD_CLASS, _SEP_CLASS = "zero-width", "gap", "replacement", "line-end"
_MAX_READINGS = 16


def _class_of(ch: str) -> str:
    cp = ord(ch)
    if cp == _FFFD:
        return _FFFD_CLASS
    if cp in _SPACE_LIKE_CODEPOINTS:
        return _SP_CLASS
    if ch in _LINE_ENDING or ch == "\r":
        return _SEP_CLASS
    return _ZW_CLASS


def _line_starts(text: str) -> list[int]:
    starts, offset = [], 0
    for piece in text.splitlines(keepends=True):
        starts.append(offset)
        offset += len(piece)
    return starts or [0]


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
        runs = [m for m in _RUN.finditer(content) if self._is_splitter(content, m)]
        if not runs:
            return []
        run_classes = [frozenset(_class_of(c) for c in m.group(0)) for m in runs]

        # REGIONS: the LF-delimited lines holding a run, merged when adjacent.
        # Found with one newline index and bisect — an rfind per run was
        # quadratic on a long single line (0.7.2 review, pass 4).
        newlines = [m.start() for m in re.finditer("\n", content)]
        regions: list[list[int]] = []
        for m in runs:
            k = bisect.bisect_left(newlines, m.start())
            a = newlines[k - 1] + 1 if k else 0
            k2 = bisect.bisect_left(newlines, m.end())
            b = newlines[k2] + 1 if k2 < len(newlines) else len(content)
            if regions and a <= regions[-1][1]:
                regions[-1][1] = max(regions[-1][1], b)
            else:
                regions.append([a, b])

        present = sorted(set().union(*run_classes))
        readings: list[dict[str, bool]] = []
        for bits in itertools.product((False, True), repeat=len(present)):
            readings.append(dict(zip(present, bits)))  # True = read as a space
        readings = readings[:_MAX_READINGS]

        seen_texts: set[str] = set()
        newly_by_region: dict[int, dict[str, Finding]] = {}
        spaced_runs_by_region: dict[int, set[int]] = {}
        baselines: dict[int, Counter[str]] = {}
        for roles in readings:
            if deadline_exceeded():
                return []
            text, region_starts = self._view(content, regions, runs, run_classes, roles)
            if text in seen_texts:
                continue
            seen_texts.add(text)
            found = scan_deobfuscated(text, source, linear=True)
            if not found:
                continue
            view_lines = _line_starts(text)
            per_region: dict[int, list[Finding]] = {}
            for f in found:
                line = min(max(f.location.line - 1, 0), len(view_lines) - 1)
                idx = bisect.bisect_right(region_starts, view_lines[line]) - 1
                per_region.setdefault(max(idx, 0), []).append(f)
            for idx, fs in per_region.items():
                if deadline_exceeded():
                    return []
                if idx not in baselines:
                    a, b = regions[idx]
                    baselines[idx] = Counter(
                        f.rule for f in scan_deobfuscated(content[a:b], source, linear=True)
                    )
                counts = Counter(f.rule for f in fs)
                revealed_here = False
                for rule, n in counts.items():
                    # Each reading against the original on its own; summing
                    # readings double-counted (review pass 3).
                    if n > baselines[idx].get(rule, 0):
                        revealed_here = True
                        worst = max((f for f in fs if f.rule == rule), key=lambda f: f.risk.value)
                        prev = newly_by_region.setdefault(idx, {}).get(rule)
                        if prev is None or worst.risk.value > prev.risk.value:
                            newly_by_region[idx][rule] = worst
                if revealed_here:
                    a, b = regions[idx]
                    spaced = spaced_runs_by_region.setdefault(idx, set())
                    for r, m in enumerate(runs):
                        if a <= m.start() < b and any(roles.get(c) for c in run_classes[r]):
                            spaced.add(r)

        return self._findings(content, regions, runs, newly_by_region, spaced_runs_by_region)

    # --- helpers ------------------------------------------------------------

    @staticmethod
    def _is_splitter(content: str, m: re.Match[str]) -> bool:
        """A run with a line-ending in it counts only BETWEEN word characters —
        elsewhere it is an ordinary line break."""
        if not _LINE_END_IN_RUN.search(m.group(0)):
            return True
        before = content[m.start() - 1] if m.start() else ""
        after = content[m.end()] if m.end() < len(content) else ""
        return bool(before and after and (before.isalnum() or before == "_")
                    and (after.isalnum() or after == "_"))

    def _view(
        self, content: str, regions: list[list[int]], runs: list[re.Match[str]],
        run_classes: list[frozenset[str]], roles: dict[str, bool],
    ) -> tuple[str, list[int]]:
        """The affected regions under one role assignment, joined by LF; and
        where each region starts in the view."""
        pieces: list[str] = []
        starts: list[int] = []
        offset = 0
        r = 0
        for a, b in regions:
            starts.append(offset)
            out: list[str] = []
            pos = a
            while r < len(runs) and runs[r].start() < b:
                m = runs[r]
                out.append(content[pos:m.start()])
                out.append(" " if any(roles.get(c) for c in run_classes[r]) else "")
                pos = m.end()
                r += 1
            out.append(content[pos:b])
            text = "".join(out)
            if not text.endswith("\n"):
                text += "\n"
            pieces.append(text)
            offset += len(text)
        return "".join(pieces), starts

    def _findings(
        self, content: str, regions: list[list[int]], runs: list[re.Match[str]],
        newly_by_region: dict[int, dict[str, Finding]],
        spaced_runs_by_region: dict[int, set[int]],
    ) -> list[Finding]:
        if not newly_by_region:
            return []
        lines = content.splitlines()
        starts = _line_starts(content)
        findings: list[Finding] = []
        fid = 1
        for idx, newly in sorted(newly_by_region.items()):
            a, b = regions[idx]
            risk = max((f.risk for f in newly.values()), key=lambda r: r.value)
            tripped = ", ".join(sorted(newly))
            spaced = spaced_runs_by_region.get(idx, set())
            for r, m in enumerate(runs):
                if not (a <= m.start() < b):
                    continue
                line_idx = bisect.bisect_right(starts, m.start()) - 1
                col = m.start() - starts[line_idx] + 1
                before, line_text, after = self._build_context(lines, min(line_idx, len(lines) - 1))
                chars = ", ".join(sorted({hex(ord(c)) for c in m.group(0)}))
                finding = self._make_finding(
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
                        f"Invisible or line-breaking characters ({chars}) split "
                        f"text that, once removed or read as spaces, is flagged "
                        f"by {tripped} — they are being used to evade keyword "
                        "detection."
                    ),
                )
                if r in spaced:
                    # Revealed read as a SPACE: redact it to a space, so the
                    # words are not glued into text nothing detects.
                    finding._redact_as = " "
                findings.append(finding)
                fid += 1
        return findings

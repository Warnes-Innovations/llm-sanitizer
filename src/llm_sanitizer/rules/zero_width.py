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
from llm_sanitizer.redactor import _finding_offset
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

        # REGIONS: the LF-delimited lines holding a run (a run crossing an LF
        # joins the lines it spans), each with the runs it holds and the
        # classes they carry. Adjacent lines are NOT merged: merging made one
        # region of a whole emoji-dense file, which then paid for every class
        # any one line held. Found with
        # one newline index and bisect — an rfind per run was quadratic on a
        # long single line (0.7.2 review, pass 4).
        newlines = [m.start() for m in re.finditer("\n", content)]
        regions: list[list[int]] = []
        region_runs: list[list[int]] = []
        for r, m in enumerate(runs):
            k = bisect.bisect_left(newlines, m.start())
            a = newlines[k - 1] + 1 if k else 0
            k2 = bisect.bisect_left(newlines, m.end())
            b = newlines[k2] + 1 if k2 < len(newlines) else len(content)
            if regions and a < regions[-1][1]:
                regions[-1][1] = max(regions[-1][1], b)
                region_runs[-1].append(r)
            else:
                regions.append([a, b])
                region_runs.append([r])
        region_classes = [
            tuple(sorted(set().union(*(run_classes[r] for r in rr)))) for rr in region_runs
        ]

        present = sorted(set().union(*run_classes))
        readings: list[dict[str, bool]] = []
        for bits in itertools.product((False, True), repeat=len(present)):
            readings.append(dict(zip(present, bits)))  # True = read as a space
        readings = readings[:_MAX_READINGS]

        # A region is read once per assignment of roles to the classes IT
        # holds, not once per global assignment: a line with only zero-width
        # characters is read twice however many other classes the text holds
        # elsewhere (0.7.2 review, pass 5: the product over every class present
        # in the text made clean text refuse at ~1.7 MB).
        read_keys: list[set[tuple[bool, ...]]] = [set() for _ in regions]
        spans: list[tuple[int, int, RiskLevel, str]] = []
        baselines: dict[int, Counter[str]] = {}
        for roles in readings:
            if deadline_exceeded():
                return []
            included: list[int] = []
            for idx, classes in enumerate(region_classes):
                key = tuple(roles[c] for c in classes)
                if key not in read_keys[idx]:
                    read_keys[idx].add(key)
                    included.append(idx)
            if not included:
                continue
            view = self._view(content, regions, region_runs, runs, run_classes, roles, included)
            found = scan_deobfuscated(view.text, source, linear=True)
            if not found:
                continue
            per_region: dict[int, list[tuple[Finding, int | None]]] = {}
            for f in found:
                off = _finding_offset(view.text, f) if f.location.line > 0 else None
                pos = off if off is not None else view.line_offset(f.location.line)
                k = bisect.bisect_right(view.region_starts, pos) - 1
                per_region.setdefault(included[max(k, 0)], []).append((f, off))
            for idx, fs in per_region.items():
                if deadline_exceeded():
                    return []
                if idx not in baselines:
                    a, b = regions[idx]
                    baselines[idx] = Counter(
                        f.rule for f in scan_deobfuscated(content[a:b], source, linear=True)
                    )
                counts = Counter(f.rule for f, _ in fs)
                for rule, n in counts.items():
                    # Each reading against the original on its own; summing
                    # readings double-counted (review pass 3).
                    if n <= baselines[idx].get(rule, 0):
                        continue
                    spans.extend(self._payload_spans(
                        content, view, regions[idx], runs, region_runs[idx],
                        [(f, off) for f, off in fs if f.rule == rule],
                    ))

        return self._findings(content, spans)

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

    @staticmethod
    def _view(
        content: str, regions: list[list[int]], region_runs: list[list[int]],
        runs: list[re.Match[str]], run_classes: list[frozenset[str]],
        roles: dict[str, bool], included: list[int],
    ) -> _View:
        """The *included* regions under one role assignment, joined by LF, with
        a map from every view position back to the original text."""
        view = _View()
        for idx in included:
            a, b = regions[idx]
            view.region_starts.append(view.length)
            pos = a
            for r in region_runs[idx]:
                m = runs[r]
                view.keep(content, pos, m.start())
                if any(roles.get(c) for c in run_classes[r]):
                    view.replace(" ", m.start(), m.end())
                pos = m.end()
            view.keep(content, pos, b)
            if not content[a:b].endswith("\n"):
                view.replace("\n", b, b)
        return view

    @staticmethod
    def _payload_spans(
        content: str, view: _View, region: list[int], runs: list[re.Match[str]],
        run_ids: list[int], candidates: list[tuple[Finding, int | None]],
    ) -> list[tuple[int, int, RiskLevel, str]]:
        """The ORIGINAL spans of the payload a reading revealed.

        Redaction removes the payload itself, splitters included, in one edit —
        never the splitters alone. Editing only the splitters (removing them,
        or reading them as spaces) left the words behind: glued, or re-spaced
        into text a second payload's reading had split (`ig nore al l`), and
        published it with status ok (0.7.2 review, pass 5). A candidate whose
        span holds no splitter is found in the original text too and is left
        to the rule that finds it there.
        """
        a, b = region
        run_starts = [runs[r].start() for r in run_ids]
        out: list[tuple[int, int, RiskLevel, str]] = []
        unplaced: list[Finding] = []
        for f, off in candidates:
            if off is None:
                unplaced.append(f)
                continue
            s, e = view.to_original(off, off + len(f.matched_raw))
            i = bisect.bisect_left(run_starts, s)
            if i < len(run_starts) and run_starts[i] < e:
                out.append((s, e, f.risk, f.rule))
        if not out:
            # The reading tripped the rule more often than the original did,
            # but no finding could be placed over a splitter: remove the whole
            # region rather than guess which part carried the payload.
            worst = max((f for f, _ in candidates), key=lambda f: f.risk.value)
            out.append((a, b, worst.risk, worst.rule))
        return out

    def _findings(
        self, content: str, spans: list[tuple[int, int, RiskLevel, str]],
    ) -> list[Finding]:
        if not spans:
            return []
        # Merge overlapping spans into one edit each, so no redaction of one
        # payload is dropped for overlapping another.
        spans.sort(key=lambda t: t[0])
        merged: list[tuple[int, int, RiskLevel, set[str]]] = []
        for s, e, risk, rule in spans:
            if merged and s < merged[-1][1]:
                ls, le, lrisk, lrules = merged[-1]
                merged[-1] = (ls, max(le, e), max(lrisk, risk, key=lambda r: r.value), lrules | {rule})
            else:
                merged.append((s, e, risk, {rule}))
        lines = content.splitlines()
        starts = _line_starts(content)
        findings: list[Finding] = []
        for fid, (s, e, risk, rules) in enumerate(merged, start=1):
            span = content[s:e]
            line_idx = bisect.bisect_right(starts, s) - 1
            col = s - starts[line_idx] + 1
            before, line_text, after = self._build_context(lines, min(line_idx, len(lines) - 1))
            chars = ", ".join(sorted(
                {hex(ord(c)) for m in _RUN.finditer(span) for c in m.group(0)}
            ))
            findings.append(self._make_finding(
                finding_id=fid,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                risk=risk,
                line_no=line_idx + 1,
                col=col,
                end_col=col + len(span),
                matched=repr(span),
                matched_raw=span,
                before=before,
                line_text=line_text,
                after=after,
                explanation=(
                    f"Invisible or line-breaking characters ({chars}) split "
                    f"text that, once removed or read as spaces, is flagged "
                    f"by {', '.join(sorted(rules))} — they are being used to "
                    "evade keyword detection."
                ),
            ))
        return findings


class _View:
    """A de-obfuscated reading of some regions, and the map back to the
    original. Each non-empty piece of the view is either KEPT (maps character
    for character) or a REPLACEMENT (a space for a run, or a synthetic line
    end), which maps as a whole to the original span it stands for. Runs read
    as removed have no piece; a span over them covers them implicitly."""

    def __init__(self) -> None:
        self._parts: list[str] = []
        self.length = 0
        self.region_starts: list[int] = []
        self._view_starts: list[int] = []
        self._orig: list[tuple[int, int, bool]] = []  # (orig start, orig end, kept)
        self._text: str | None = None

    def keep(self, content: str, a: int, b: int) -> None:
        if b > a:
            self._add(content[a:b], a, b, True)

    def replace(self, text: str, a: int, b: int) -> None:
        self._add(text, a, b, False)

    def _add(self, text: str, a: int, b: int, kept: bool) -> None:
        self._parts.append(text)
        self._view_starts.append(self.length)
        self._orig.append((a, b, kept))
        self.length += len(text)
        self._text = None

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = "".join(self._parts)
        return self._text

    def line_offset(self, line: int) -> int:
        """View offset of 1-based *line* (splitlines numbering); 0 if unknown."""
        if line <= 0:
            return 0
        starts = _line_starts(self.text)
        return starts[min(line, len(starts)) - 1]

    def to_original(self, s: int, e: int) -> tuple[int, int]:
        """The original span a view span [s, e) stands for."""
        i = bisect.bisect_right(self._view_starts, s) - 1
        a, b, kept = self._orig[i]
        start = a + (s - self._view_starts[i]) if kept else a
        j = bisect.bisect_right(self._view_starts, max(e - 1, s)) - 1
        a, b, kept = self._orig[j]
        end = a + (max(e - 1, s) - self._view_starts[j]) + 1 if kept else b
        return start, max(end, start)

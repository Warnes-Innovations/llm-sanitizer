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


def _context(ln: int, nonblank: list[int], n: int) -> list[int]:
    """Line *ln*, its neighbours, and the nearest line of TEXT on each side
    past any blank lines: a directive opened two lines up, past a blank line,
    was out of a plain ±1 window (review pass 8). The blank lines themselves
    are not read; _view joins lines with only blank lines between them.
    *nonblank* is the sorted list of non-blank line indices."""
    out = [x for x in (ln - 1, ln, ln + 1) if 0 <= x < n]
    k = bisect.bisect_left(nonblank, ln)
    if k > 0:
        out.append(nonblank[k - 1])
    k2 = bisect.bisect_right(nonblank, ln)
    if k2 < len(nonblank):
        out.append(nonblank[k2])
    return out


def _lf_starts(text: str) -> list[int]:
    return [0, *(m.end() for m in re.finditer("\n", text))]


def _offset_in(
    text: str, finding: Finding, keep_starts: list[int], lf_starts: list[int],
) -> int | None:
    """Offset of *finding* in *text*, placed by its (line, column) under either
    line-numbering scheme (as redactor._finding_offset does) and verified
    against its matched text; None if neither verifies."""
    raw = finding.matched_raw
    line, col = finding.location.line - 1, finding.location.column - 1
    if not raw or line < 0 or col < 0:
        return None
    for starts in (keep_starts, lf_starts):
        if line < len(starts):
            start = starts[line] + col
            if text[start:start + len(raw)] == raw:
                return start
    return None


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

        # LINES (LF-delimited) are the unit. Runs never contain LF, so each run
        # lies in one line. Found with one newline index and bisect — an rfind
        # per run was quadratic on a long single line (0.7.2 review, pass 4).
        newlines = [m.start() for m in re.finditer("\n", content)]
        line_bounds = list(zip([0, *(n + 1 for n in newlines)], [*(n + 1 for n in newlines), len(content)]))
        if line_bounds and line_bounds[-1][0] == line_bounds[-1][1] and len(line_bounds) > 1:
            line_bounds.pop()
        # Non-blank lines, and for each line how many non-blank lines precede
        # it: two included lines with only blank lines between are one block.
        nonblank = [i for i, (a, b) in enumerate(line_bounds) if content[a:b].strip()]
        nonblank_upto = [0] * (len(line_bounds) + 1)
        for i, (a, b) in enumerate(line_bounds):
            nonblank_upto[i + 1] = nonblank_upto[i] + (1 if content[a:b].strip() else 0)
        line_runs: dict[int, list[int]] = {}
        for r, m in enumerate(runs):
            line_runs.setdefault(bisect.bisect_right(newlines, m.start() - 1), []).append(r)
        line_classes = {
            ln: tuple(sorted(set().union(*(run_classes[r] for r in rr))))
            for ln, rr in line_runs.items()
        }

        present = sorted(set().union(*run_classes))
        readings: list[dict[str, bool]] = []
        for bits in itertools.product((False, True), repeat=len(present)):
            readings.append(dict(zip(present, bits)))  # True = read as a space
        readings = readings[:_MAX_READINGS]

        # A line is read once per assignment of roles to the classes IT holds,
        # not once per global assignment (0.7.2 review, pass 5: the product
        # over every class in the text made clean text refuse at ~1.7 MB). Each
        # line read is joined by the lines either side of it, read under the
        # same roles, so a payload running across two lines is seen in every
        # combination of their classes (review pass 6: per-line reading alone
        # missed an HTML comment opened on one line and split on the next).
        read_keys: dict[int, set[tuple[bool, ...]]] = {ln: set() for ln in line_runs}
        spans: list[tuple[int, int, RiskLevel, str]] = []
        baselines: dict[tuple[int, int], Counter[str]] = {}
        for roles in readings:
            if deadline_exceeded():
                return []
            fresh: list[int] = []
            for ln, classes in line_classes.items():
                key = tuple(roles[c] for c in classes)
                if key not in read_keys[ln]:
                    read_keys[ln].add(key)
                    fresh.append(ln)
            if not fresh:
                continue
            lines = sorted({x for ln in fresh for x in _context(ln, nonblank, len(line_bounds))})
            view = self._view(content, line_bounds, line_runs, runs, run_classes, roles, lines,
                              nonblank_upto)
            found = scan_deobfuscated(view.text, source, linear=True)
            if not found:
                continue
            per_block: dict[int, list[tuple[Finding, int | None]]] = {}
            recheck: set[int] = set()
            for f in found:
                if deadline_exceeded():
                    return []
                off = view.offset_of(f)
                pos = off if off is not None else view.line_offset(f.location.line)
                k = view.block_at(pos)
                if off is not None and off + len(f.matched_raw) > view.block_end(k):
                    # A match running from one block into the next joins
                    # unrelated lines the view placed side by side (review
                    # pass 6: an `<!--` line and an `LLM:` line far apart were
                    # flagged, and a benign line deleted). Do NOT just drop it:
                    # a greedy match that starts in this block may hide a real
                    # one that ends inside it (review pass 7: a hidden
                    # three-line comment scanned clean). Re-scan the block on
                    # its own instead.
                    recheck.add(k)
                    continue
                per_block.setdefault(k, []).append((f, off))
            for k in sorted(recheck):
                if deadline_exceeded():
                    return []
                start, end = view.blocks[k][0], view.block_end(k)
                alone = view.text[start:end]
                keep, lf = _line_starts(alone), _lf_starts(alone)
                per_block[k] = [
                    (f, None if o is None else start + o)
                    for f in scan_deobfuscated(alone, source, linear=True)
                    for o in [_offset_in(alone, f, keep, lf)]
                ]
            for k, fs in per_block.items():
                if deadline_exceeded():
                    return []
                a, b = view.blocks[k][1], view.blocks[k][2]
                if (a, b) not in baselines:
                    # The same original lines, unread: a finding the reading
                    # did not add is not revealed.
                    baselines[(a, b)] = Counter(
                        f.rule for f in scan_deobfuscated(
                            content[a:b], source, linear=True,
                            exclude=frozenset({self.rule_id}),
                        )
                    )
                counts = Counter(f.rule for f, _ in fs)
                for rule, n in counts.items():
                    # Each reading against the original on its own; summing
                    # readings double-counted (review pass 3).
                    if n <= baselines[(a, b)].get(rule, 0):
                        continue
                    spans.extend(self._payload_spans(
                        view, runs, [(f, off) for f, off in fs if f.rule == rule],
                    ))

        return self._findings(content, spans)

    # --- helpers ------------------------------------------------------------

    @staticmethod
    def _is_splitter(content: str, m: re.Match[str]) -> bool:
        """A run with a line-ending in it counts only BETWEEN two non-space
        characters — beside whitespace or at a line's edge it is an ordinary
        line break. Word characters on both sides was too narrow: U+2028
        between `the` and `.env` split a payload (0.7.2 review, pass 5 F4)."""
        if not _LINE_END_IN_RUN.search(m.group(0)):
            return True
        before = content[m.start() - 1] if m.start() else ""
        after = content[m.end()] if m.end() < len(content) else ""
        return bool(before and after and not before.isspace() and not after.isspace())

    @staticmethod
    def _view(
        content: str, line_bounds: list[tuple[int, int]], line_runs: dict[int, list[int]],
        runs: list[re.Match[str]], run_classes: list[frozenset[str]],
        roles: dict[str, bool], lines: list[int], nonblank_upto: list[int],
    ) -> _View:
        """The given *lines* under one role assignment, with a map from every
        view position back to the original text. Consecutive lines form one
        BLOCK; blocks are separated in the view by a blank line."""
        view = _View()
        prev = -2
        for ln in lines:
            a, b = line_bounds[ln]
            # Only blank lines between this and the previous included line:
            # the same block, the blank lines left out of the reading.
            gap_blank = prev >= 0 and nonblank_upto[ln] == nonblank_upto[prev + 1]
            if ln != prev + 1 and not gap_blank:
                if prev >= 0:
                    view.replace("\n", view.last_end, view.last_end)
                view.start_block(a)
            pos = a
            for r in line_runs.get(ln, ()):
                m = runs[r]
                view.keep(content, pos, m.start())
                if any(roles.get(c) for c in run_classes[r]):
                    view.replace(" ", m.start(), m.end())
                pos = m.end()
            view.keep(content, pos, b)
            if not content[a:b].endswith("\n"):
                view.replace("\n", b, b)
            view.end_block(b)
            prev = ln
        return view

    @staticmethod
    def _payload_spans(
        view: _View, runs: list[re.Match[str]], candidates: list[tuple[Finding, int | None]],
    ) -> list[tuple[int, int, RiskLevel, str]]:
        """The ORIGINAL spans of the payload a reading revealed.

        Redaction removes the payload itself, splitters included, in one edit —
        never the splitters alone. Editing only the splitters (removing them,
        or reading them as spaces) left the words behind: glued, or re-spaced
        into text a second payload's reading had split (`ig nore al l`), and
        published it with status ok (0.7.2 review, pass 5). A candidate whose
        span holds no splitter is found in the original text too and is left
        to the rule that finds it there.

        A candidate never runs from one block into the next: detect() drops
        those, because blocks adjacent in the view need not be adjacent in the
        original, and such a span deleted every line between them (review
        pass 6: 40 benign paragraphs between a directive and a soft hyphen).
        """
        run_starts = [m.start() for m in runs]
        out: list[tuple[int, int, RiskLevel, str]] = []
        for f, off in candidates:
            if off is None:
                continue
            s, e = view.to_original(off, off + len(f.matched_raw))
            i = bisect.bisect_left(run_starts, s)
            if i < len(run_starts) and run_starts[i] < e:
                out.append((s, e, f.risk, f.rule))
        if not out:
            # The reading tripped the rule more often than the original did,
            # but no finding could be placed over a splitter: remove the block
            # it was found in rather than guess which part carried the payload.
            f, off = max(candidates, key=lambda c: c[0].risk.value)
            k = view.block_at(off if off is not None else view.line_offset(f.location.line))
            out.append((view.blocks[k][1], view.blocks[k][2], f.risk, f.rule))
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
        self._view_starts: list[int] = []
        self._orig: list[tuple[int, int, bool]] = []  # (orig start, orig end, kept)
        self._text: str | None = None
        #: (view start, original start, original end) per block of lines.
        self.blocks: list[tuple[int, int, int]] = []
        self.last_end = 0
        self._block_starts: list[int] | None = None
        self._keep_starts: list[int] | None = None
        self._lf_starts: list[int] | None = None

    def start_block(self, orig_start: int) -> None:
        self.blocks.append((self.length, orig_start, orig_start))

    def end_block(self, orig_end: int) -> None:
        v, a, _ = self.blocks[-1]
        self.blocks[-1] = (v, a, orig_end)
        self.last_end = orig_end

    def block_at(self, pos: int) -> int:
        """Index of the block holding view position *pos*."""
        if self._block_starts is None:
            self._block_starts = [v for v, _, _ in self.blocks]
        return max(bisect.bisect_right(self._block_starts, pos) - 1, 0)

    def block_end(self, k: int) -> int:
        """View offset where block *k* ends (the next block's start)."""
        return self.blocks[k + 1][0] if k + 1 < len(self.blocks) else self.length

    def offset_of(self, finding: Finding) -> int | None:
        """View offset of *finding*, placed by its (line, column) and verified
        against its matched text — the same two line-numbering schemes as
        redactor._finding_offset, but on line tables built ONCE per view.
        Calling _finding_offset per finding re-split the whole view each time:
        280 s on a 1.5 MB file against a 60 s deadline (review pass 6)."""
        if self._keep_starts is None:
            self._keep_starts = _line_starts(self.text)
        if self._lf_starts is None:
            self._lf_starts = _lf_starts(self.text)
        return _offset_in(self.text, finding, self._keep_starts, self._lf_starts)

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
        if self._keep_starts is None:
            self._keep_starts = _line_starts(self.text)
        starts = self._keep_starts
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

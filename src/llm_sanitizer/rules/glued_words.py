# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule: Glued Words.

A phrase written with its word breaks removed — ``ignoreallpreviousinstructions``,
``IgnoreAllPreviousInstructions`` — is still read without effort by a language
model, but no word-based rule matches it. The same text arrives from the
zero-width rule's "splitters removed" reading when invisible characters were
used both inside words and between them, so this is also what closes that case:
no assignment of roles to the invisible characters is needed once the glued
reading can be split back into words.

Like every obfuscation rule this is transport, not threat: the glued run is
split into words and the line is re-scanned with the full ruleset
(:func:`scan_deobfuscated`). It fires only when the split line trips a rule the
original line did not.

The split uses a vocabulary derived at first use from the detection rules
themselves (the words in their patterns and lexicons) and from the semantic
classifier's word features, so it cannot drift from what the rules look for.
Only a run holding at least one TRIGGER word (a word from a rule pattern or an
intent lexicon) is split: ordinary long words ("understanding",
"international") are left alone, which keeps the re-scan off ordinary prose.
"""

from __future__ import annotations

import functools
import importlib
import json
import pkgutil
import re
from collections import Counter
from pathlib import Path
from typing import Any

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

#: A run of letters long enough to hold two glued words.
_RUN = re.compile(r"[A-Za-z]{7,}")
_WORD = re.compile(r"[a-z]{2,}")
_ESCAPE = re.compile(r"\\[A-Za-z]")
#: Longest vocabulary word considered when splitting.
_MAX_WORD = 24
#: At most this share of a run may be letters the vocabulary does not cover.
_MAX_UNKNOWN_SHARE = 0.5
#: A run longer than this is split in blocks of this size, at half this stride,
#: so a glued phrase of up to half this length lies whole inside one block. The
#: word split is quadratic-ish in run length; a 4 MB run of one letter took 20 s
#: before blocks.
_BLOCK = 512


def _words_in(value: Any) -> set[str]:
    """Lower-case words (2+ letters) in a string, pattern, or collection of them.
    Regex escapes (``\\s``, ``\\b``) are dropped first, so ``\\bAI`` gives ``ai``."""
    if isinstance(value, re.Pattern):
        value = value.pattern
    if isinstance(value, str):
        return set(_WORD.findall(_ESCAPE.sub(" ", value).lower()))
    if isinstance(value, (list, tuple, set, frozenset)):
        out: set[str] = set()
        for v in value:
            out |= _words_in(v)
        return out
    return set()


@functools.cache
def _vocabulary() -> tuple[frozenset[str], frozenset[str]]:
    """(trigger words, all words). Built once, from the code — never listed here."""
    import llm_sanitizer.rules as rules_pkg
    from llm_sanitizer.semantic import features

    triggers: set[str] = set()
    for mod in pkgutil.iter_modules(rules_pkg.__path__):
        if mod.name.startswith("_") or mod.name == "glued_words":
            continue
        module = importlib.import_module(f"llm_sanitizer.rules.{mod.name}")
        for name, value in vars(module).items():
            if name.startswith("__"):
                continue
            triggers |= _words_in(value)
    lexicon_words: set[str] = set()
    for name, value in vars(features).items():
        if name.isupper() or name.startswith("_") and name[1:].isupper():
            lexicon_words |= _words_in(value)
    triggers |= lexicon_words - set(getattr(features, "_STOPWORDS", ()))

    words = set(triggers) | lexicon_words
    model = json.loads((Path(features.__file__).parent / "model.json").read_text())
    for key in model.get("weights", {}):
        if key.startswith("w:") and key[2:].isalpha():
            words.add(key[2:])
    # Plurals: patterns spell "instructions?" and lexicons list one form.
    words |= {w + "s" for w in words}
    triggers |= {w + "s" for w in triggers}
    # "a" and "i" are the only one-letter words ("uploadafile").
    return frozenset(triggers), frozenset({w for w in words if len(w) >= 2} | {"a", "i"})


@functools.cache
def _trigger_prefixes() -> dict[str, tuple[str, ...]]:
    """Trigger words of 4+ letters, keyed by their first four letters. A set
    lookup per position: an alternation regex over the same words took ~9 s on
    a 4 MB run, this ~0.6 s."""
    triggers, _ = _vocabulary()
    out: dict[str, list[str]] = {}
    for w in sorted((w for w in triggers if len(w) >= 4), key=len, reverse=True):
        out.setdefault(w[:4], []).append(w)
    return {k: tuple(v) for k, v in out.items()}


def _trigger_hits(low: str) -> list[int]:
    """Start offsets of trigger words in lower-cased *low*."""
    prefixes = _trigger_prefixes()
    hits: list[int] = []
    for i in range(len(low) - 3):
        cands = prefixes.get(low[i:i + 4])
        if cands and any(low.startswith(w, i) for w in cands):
            hits.append(i)
    return hits


@functools.lru_cache(maxsize=65536)
def _split(run: str) -> str | None:
    """*run* split into vocabulary words, or None when it is not a glued phrase:
    fewer than two words, no trigger word, or too much it cannot cover."""
    triggers, words = _vocabulary()
    low = run.lower()
    n = len(low)
    # best[i] = (unknown letters, pieces) for low[:i]; back[i] = start of last piece
    inf = (n + 1, n + 1)
    best: list[tuple[int, int]] = [(0, 0)] + [inf] * n
    back = [0] * (n + 1)
    known = [False] * (n + 1)
    for i in range(1, n + 1):
        unk, npieces = best[i - 1]
        best[i], back[i], known[i] = (unk + 1, npieces + 1), i - 1, False
        for j in range(max(0, i - _MAX_WORD), i):
            if low[j:i] in words:
                cand = (best[j][0], best[j][1] + 1)
                if cand < best[i]:
                    best[i], back[i], known[i] = cand, j, True
    pieces: list[tuple[str, bool]] = []
    i = n
    while i > 0:
        j = back[i]
        pieces.append((run[j:i], known[i]))
        i = j
    pieces.reverse()
    # Adjacent unknown letters are one chunk, not one word per letter.
    merged: list[tuple[str, bool]] = []
    for text, is_word in pieces:
        if merged and not is_word and not merged[-1][1]:
            merged[-1] = (merged[-1][0] + text, False)
        else:
            merged.append((text, is_word))
    # Letters the vocabulary does not cover at either END are left as they
    # are and not counted: a phrase glued between two blobs
    # ("qqqq...ignoreall...zzzz") is judged on the phrase.
    lo, hi = 0, len(merged)
    while lo < hi and not merged[lo][1]:
        lo += 1
    while hi > lo and not merged[hi - 1][1]:
        hi -= 1
    middle = merged[lo:hi]
    covered = sum(len(t) for t, _ in middle)
    unknown = sum(len(t) for t, is_word in middle if not is_word)
    if not middle or unknown > covered * _MAX_UNKNOWN_SHARE:
        return None
    found = [t.lower() for t, is_word in middle if is_word]
    # Cost controls, not detection: the re-scan decides. Each keeps ordinary
    # long words ("documentation" -> "document at i on") from being split and
    # re-scanned. A trigger must be a real content word (4+ letters, not
    # "at"/"on"); an uncovered chunk shorter than 4 letters is a sign the
    # vocabulary is forcing a split; short average pieces are fragments.
    if len(middle) < 2 or not any(len(w) >= 4 and w in triggers for w in found):
        return None
    if any(not is_word and len(t) < 4 for t, is_word in middle):
        return None
    if covered / len(middle) < 3.5:
        return None
    return " ".join(t for t, _ in merged)


def _split_short(run: str) -> str | None:
    if len(run) > _BLOCK or not _trigger_hits(run.lower()):
        return None
    return _split(run)


def _readings(line: str) -> list[str]:
    """The line with each short glued run split into words (if any changed),
    plus, for each LONG run, a split of the window around every trigger word
    on its own."""
    out: list[str] = []
    new = _RUN.sub(lambda m: _split_short(m.group(0)) or m.group(0), line)
    if new != line:
        out.append(new)
    half = _BLOCK // 2
    for m in _RUN.finditer(line):
        run = m.group(0)
        if len(run) <= _BLOCK:
            continue
        covered_to = -1
        for hit in _trigger_hits(run.lower()):
            if hit < covered_to - half // 2:
                continue  # already well inside the previous window
            if deadline_exceeded():
                return out
            start = max(0, hit - half)
            window = run[start:start + _BLOCK]
            covered_to = start + _BLOCK
            split = _split(window)
            if split:
                out.append(split)
    return out


@register_rule
class GluedWordsRule(BaseRule):
    rule_id = "glued_words"
    rule_name = "Glued Words"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects a phrase written with its word breaks removed "
        "(`ignoreallprevious...`) — flagged only when splitting it back into "
        "words reveals content another rule flags."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        lines = content.splitlines()
        changed: list[int] = []
        rebuilt: list[str] = []
        for idx, line in enumerate(lines):
            if deadline_exceeded():
                return []
            if not _RUN.search(line):
                continue
            for reading in _readings(line):
                changed.append(idx)
                rebuilt.append(reading)
        if not changed:
            return []
        # One re-scan of every rebuilt line together (linear in the input),
        # then a baseline only for the lines that tripped something.
        found = scan_deobfuscated("\n".join(rebuilt) + "\n", source, linear=True)
        by_line: dict[int, list[Finding]] = {}
        for f in found:
            k = f.location.line - 1
            if 0 <= k < len(changed):
                by_line.setdefault(k, []).append(f)
        findings: list[Finding] = []
        flagged: set[int] = set()
        baselines: dict[int, Counter[str]] = {}
        for k, fs in sorted(by_line.items()):
            if deadline_exceeded():
                return []
            idx = changed[k]
            if idx in flagged:
                continue
            line = lines[idx]
            if idx not in baselines:
                baselines[idx] = Counter(
                    f.rule for f in scan_deobfuscated(line, source, linear=True)
                )
            baseline = baselines[idx]
            counts = Counter(f.rule for f in fs)
            newly = [f for f in fs if counts[f.rule] > baseline.get(f.rule, 0)]
            if not newly:
                continue
            flagged.add(idx)
            risk = max((f.risk for f in newly), key=lambda r: r.value)
            tripped = ", ".join(sorted({f.rule_name for f in newly}))
            before, line_text, after = self._build_context(lines, idx)
            findings.append(self._make_finding(
                finding_id=len(findings) + 1,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                risk=risk,
                line_no=idx + 1,
                col=1,
                end_col=len(line) + 1,
                matched=line[:80] + ("..." if len(line) > 80 else ""),
                matched_raw=line,
                before=before,
                line_text=line_text,
                after=after,
                explanation=(
                    f"Glued words: split back into words, the line reads "
                    f"{rebuilt[k][:80]!r}, which is flagged by {tripped}."
                ),
            ))
        return findings

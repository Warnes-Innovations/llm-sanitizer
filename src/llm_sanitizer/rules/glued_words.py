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
    # The classifier's training sentences: ordinary words a payload is written
    # with that no rule pattern names ("password", "email").
    from llm_sanitizer.semantic import corpus

    for name, value in vars(corpus).items():
        if not name.startswith("__"):
            words |= _words_in(value)
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
    """Trigger words of 3+ letters, keyed by their first three letters. A set
    lookup per position: an alternation regex over the same words took ~9 s on
    a 4 MB run, this ~0.6 s."""
    triggers, _ = _vocabulary()
    out: dict[str, list[str]] = {}
    for w in sorted((w for w in triggers if len(w) >= 3), key=len, reverse=True):
        out.setdefault(w[:3], []).append(w)
    return {k: tuple(v) for k, v in out.items()}


def _trigger_hits(low: str) -> list[int]:
    """Start offsets of trigger words in lower-cased *low*."""
    prefixes = _trigger_prefixes()
    hits: list[int] = []
    for i in range(len(low) - 2):
        cands = prefixes.get(low[i:i + 3])
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
    # Cost controls, not detection: the re-scan decides, so these only keep
    # ordinary long words ("straightforward" -> "str ai ght forward") from
    # being split and re-scanned. Each was tightened once and then loosened
    # again when it hid a real payload (review pass 7), so read the case
    # before changing one:
    #  - some trigger word must be among the pieces;
    #  - an uncovered chunk under 4 letters inside the phrase ("ur", "teh")
    #    is allowed only when two or more distinct 4+ letter triggers vouch
    #    for the split ("ignoreallurpreviousinstructions");
    #  - a phrase whose triggers are all short ("youarenowdan") must be fully
    #    covered, in three pieces or more.
    #  - pieces average 3+ letters ("obf us cat i on" is fragments), and a
    #    phrase with an uncovered END trimmed off keeps 3+ pieces ("read in|g").
    long_triggers = {w for w in found if len(w) >= 4 and w in triggers}
    if len(middle) < 2 or not any(w in triggers for w in found):
        return None
    if covered / len(middle) < 3.0 or (len(middle) < 3 and (lo > 0 or hi < len(merged))):
        return None
    short_unknown = any(not is_word and len(t) < 4 for t, is_word in middle)
    if not long_triggers:
        if unknown or len(middle) < 3:
            return None
    elif short_unknown and len(long_triggers) < 2:
        return None
    return " ".join(t for t, _ in merged)


def _worth_splitting(low: str) -> bool:
    """A trigger word of 4+ letters in *low*, or three distinct short ones
    ("youarenowdan"). One short trigger ("all", "get") is in too many
    ordinary words to be worth a split and a re-scan."""
    short: set[str] = set()
    prefixes = _trigger_prefixes()
    for i in _trigger_hits(low):
        for w in prefixes[low[i:i + 3]]:
            if low.startswith(w, i):
                if len(w) >= 4:
                    return True
                short.add(w)
    return len(short) >= 3


def _split_short(run: str) -> str | None:
    # A short all-capitals run is an acronym, not a glued phrase: splitting
    # `OPENSSH` turned `BEGIN OPENSSH PRIVATE KEY` into an exfiltration phrase
    # (review pass 7). A glued payload in capitals is longer than 8 letters.
    if run.isupper() and len(run) <= 8:
        return None
    if len(run) > _BLOCK or not _worth_splitting(run.lower()):
        return None
    return _split(run)


#: Words joined by single separators or digits (`ignore_all.previous-1rules`).
#: A repeated separator is char_split's; a single one between words is also
#: what snake_case and dotted names look like, so it is read as a space only
#: in a token that holds a trigger word.
_JOINED = re.compile(r"(?<![A-Za-z])[A-Za-z]++(?:[._\-0-9]++[A-Za-z]++)+")
_JOINER = re.compile(r"[._\-0-9]+")


#: A lower-to-upper change inside a run: CamelCase, an identifier's shape.
_CAMEL = re.compile(r"[a-z][A-Z]")
_CAMEL_PART = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")

_IDENT_EDGE = frozenset("_./-")


#: A name-like token: letters, optionally joined by `_ . -` or digits.
_IDTOK = re.compile(r"(?<![A-Za-z])[A-Za-z]++(?:[._\-0-9]++[A-Za-z]++)*")


def _ident_token(tok: str, line: str, a: int, b: int) -> str:
    """*tok* (at line[a:b]) read as words: CamelCase split at its capitals,
    a letter run inside a name or path split as a glued run, and — for a
    phrase-like join of three or more parts, two of them trigger words
    (`ignore_all_previous`) — its separators read as spaces."""
    triggers, _ = _vocabulary()
    parts = _JOINER.split(tok)
    seps = _JOINER.findall(tok)
    phrase = len(parts) >= 3 and len(
        {p.lower() for p in parts if len(p) >= 4 and p.lower() in triggers}) >= 2
    in_name = len(parts) > 1 or (a > 0 and line[a - 1] in _IDENT_EDGE) or (
        b < len(line) and line[b] in _IDENT_EDGE)
    out: list[str] = []
    for i, p in enumerate(parts):
        if _CAMEL.search(p) and _worth_splitting(p.lower()):
            p = " ".join((_split_short(x) or x) if len(x) >= 7 else x for x in _CAMEL_PART.findall(p))
        elif in_name and len(p) >= 7:
            p = _split_short(p) or p
        out.append(p)
        if i < len(seps):
            out.append(" " if phrase else seps[i])
    return "".join(out)


def _ident_reading(line: str) -> tuple[str, list[tuple[int, int]]]:
    """*line* with each name-like token read as words, and where each
    rewritten token lies in the result."""
    out: list[str] = []
    spans: list[tuple[int, int]] = []
    pos = size = 0
    for m in _IDTOK.finditer(line):
        tok = m.group(0)
        new = _ident_token(tok, line, m.start(), m.end())
        out.append(line[pos:m.start()])
        size += m.start() - pos
        if new != tok:
            spans.append((size, size + len(new)))
        out.append(new)
        size += len(new)
        pos = m.end()
    out.append(line[pos:])
    return "".join(out), spans


def _plain(m: re.Match[str]) -> str:
    run = m.group(0)
    text, a, b = m.string, m.start(), m.end()
    if _CAMEL.search(run) or (a > 0 and text[a - 1] in _IDENT_EDGE) or (
            b < len(text) and text[b] in _IDENT_EDGE):
        return run
    return _split_short(run) or run


def _readings(line: str) -> list[tuple[str, list[tuple[int, int]] | None]]:
    """Readings of *line*. The second item is None for a PLAIN reading, and
    for an IDENTIFIER-shaped reading the spans of the rewritten tokens:

    - plain glued runs (no CamelCase, not inside a name or path) split;
    - name-like tokens read as words (see _ident_token);
    - for each LONG run, the window around every trigger word, split.
    """
    out: list[tuple[str, list[tuple[int, int]] | None]] = []
    plain = _RUN.sub(_plain, line)
    if plain != line:
        out.append((plain, None))
    ident, spans = _ident_reading(line)
    if spans and ident != plain:
        out.append((ident, spans))
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
                out.append((split, None))
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
        spans_of: list[list[tuple[int, int]] | None] = []
        for idx, line in enumerate(lines):
            if deadline_exceeded():
                return []
            if not _RUN.search(line) and not _JOINED.search(line):
                continue
            for reading, spans in _readings(line):
                changed.append(idx)
                rebuilt.append(reading)
                spans_of.append(spans)
        if not changed:
            return []
        # One re-scan of every rebuilt line together (linear in the input),
        # then a baseline only for the lines that tripped something.
        found = scan_deobfuscated("\n".join(rebuilt) + "\n", source, linear=True)
        by_line: dict[int, list[Finding]] = {}
        for f in found:
            k = f.location.line - 1
            if 0 <= k < len(changed):
                spans = spans_of[k]
                if spans is not None:
                    # In an identifier reading a finding counts only inside
                    # ONE rewritten token: a payload hidden as a name is all
                    # in the name, while code around a name ("return
                    # auth_user.access_token") reads as a phrase by accident.
                    # That alone took ordinary library code from 77 flagged
                    # lines to 2 (review pass 7); exempting whole rules on top
                    # removed no more and lost CamelCase payloads.
                    a = f.location.column - 1
                    z = a + len(f.matched_raw)
                    if not any(s <= a and z <= e for s, e in spans):
                        continue
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
                    f.rule for f in scan_deobfuscated(
                        line, source, linear=True, exclude=frozenset({self.rule_id}))
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

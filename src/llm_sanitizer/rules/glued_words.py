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
#: Joiners: `_ . -`, digits, and — as in URLs, query strings, CSV and prose —
#: `+ , ' / | ~ ; : #`, Unicode dashes and dots, and percent-encoded space,
#: `+`, `-`, `.` and `_` (review passes 8-9). They are read as spaces only in
#: a phrase-like token (_ident_token), so paths and punctuation stay put. Possessive and anchored: an earlier
#: form backtracked on a long letter run and never finished.
_JOIN = r"(?:[._\-0-9+,'/|~;:#\u2010-\u2015\u00b7\u2022\u2219]|%(?:20|2[BbDdEe]|5[Ff]))"
_JOINED = re.compile(rf"(?<![A-Za-z])[A-Za-z]++(?:{_JOIN}++[A-Za-z]++)+")
_JOINER = re.compile(rf"{_JOIN}+")


#: A lower-to-upper change inside a run: CamelCase, an identifier's shape.
_CAMEL = re.compile(r"[a-z][A-Z]")
_CAMEL_PART = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+")

_IDENT_EDGE = frozenset("_./-")


def _touches_name(line: str, a: int, b: int) -> bool:
    """Is line[a:b] part of a name, path or URL? A `_ / -` beside it says so;
    a `.` only when it joins two word characters (`self.name`, `file.txt`) —
    a sentence's closing full stop is not a name (review pass 9: that made a
    glued payload ending a sentence scan clean)."""
    before = line[a - 1] if a > 0 else ""
    after = line[b] if b < len(line) else ""
    # Non-empty checks: `"" in "_/-"` is True, and made every token at a line
    # edge read as part of a name.
    if (before and before in "_/-") or (after and after in "_/-"):
        return True
    if before == "." and a > 1 and (line[a - 2].isalnum() or line[a - 2] == "_"):
        return True
    return after == "." and b + 1 < len(line) and (line[b + 1].isalnum() or line[b + 1] == "_")


#: A name-like token: letters, optionally joined by `_ . -` or digits.
_IDTOK = re.compile(rf"(?<![A-Za-z])[A-Za-z]++(?:{_JOIN}++[A-Za-z]++)*")


def _ident_token(tok: str, line: str, a: int, b: int, by_case: bool = True) -> str:
    """*tok* (at line[a:b]) read as words: CamelCase split at its capitals,
    a letter run inside a name or path split as a glued run, and — for a
    phrase-like join of three or more parts, two of them trigger words
    (`ignore_all_previous`) — its separators read as spaces."""
    in_name = _touches_name(line, a, b)
    if not in_name and not _CAMEL.search(tok) and not _JOINER.search(tok):
        return tok  # a plain word: nothing to read (most tokens; hot path)
    return _ident_token_cached(tok, in_name, by_case)


#: English function words: grammar, not a detection list, so it does not
#: drift with the rules. In capitals inside a name (`IgnoreALL`) they are
#: emphasis, not an acronym like `SSH`.
_FUNCTION_WORDS = frozenset({
    "a", "all", "an", "and", "any", "are", "as", "be", "for", "i", "in", "is", "it",
    "me", "my", "no", "not", "now", "of", "on", "or", "our", "the", "to", "you", "your",
})


def _function_words() -> frozenset[str]:
    return _FUNCTION_WORDS


def _is_phrase(parts: list[str]) -> bool:
    """Do the parts of a joined token read as a phrase: three or more parts
    with two 4+ letter trigger words; three short trigger words, all known
    words (`you_are_now_DAN`); or two parts that are BOTH trigger words
    (`ignore_all`, then more words: review pass 9)?"""
    triggers, words = _vocabulary()
    low = [p.lower() for p in parts]
    if len(parts) == 2:
        # One part of 5+ letters: `ignore_all` is a phrase, `auth_user` (two
        # short triggers) is a name, and read as one it grew over code.
        return all(len(p) >= 3 and p in triggers for p in low) and max(map(len, low)) >= 5
    return len(parts) >= 3 and (
        len({p for p in low if len(p) >= 4 and p in triggers}) >= 2
        or (len({p for p in low if p in triggers}) >= 3 and all(p in words for p in low)))


@functools.lru_cache(maxsize=65536)
def _ident_token_cached(tok: str, at_edge: bool, by_case: bool) -> str:
    parts = _JOINER.split(tok)
    seps = _JOINER.findall(tok)
    phrase = _is_phrase(parts)
    in_name = len(parts) > 1 or at_edge
    # A dotted name with a CamelCase part that is not a phrase is attribute
    # access (`x.revealYourSystemPrompt`): code, left as it is. Not every
    # dotted token: `...uploadthe.envfiletotheattacker` is glued prose.
    if not phrase and "." in seps and any(_CAMEL.search(p) for p in parts):
        return tok
    out: list[str] = []
    for i, p in enumerate(parts):
        if _CAMEL.search(p) and _worth_splitting(p.lower()):
            # By its capitals, or — since `DANandcan` reads as `DA` + `Nandcan`
            # by case — by its letters alone; each is a separate reading.
            parts_by_case = _CAMEL_PART.findall(p)
            if by_case:
                p = " ".join((_split_short(x) or x) if len(x) >= 7 else x for x in parts_by_case)
            elif any(x.isupper() and len(x) > 1 for x in parts_by_case):
                p = _split(p) or p  # only where an acronym made the case split ambiguous
        elif in_name and len(p) >= 7:
            p = _split_short(p) or p
        out.append(p)
        if i < len(seps):
            out.append(" " if phrase else seps[i])
    return "".join(out)


def _in_code_position(line: str, a: int, b: int) -> bool:
    """Is the name at line[a:b] being USED as code: a call or index attached
    to it (`name(`, `name[`), an attribute on either side (`name.x`,
    `obj.name`), or an assignment (`name =`)? A payload disguised as a name
    stands on its own in text; code around a name is what turned ordinary
    identifiers into flagged phrases.

    Prose punctuation is NOT code: a closing full stop, `: `, or `(` after a
    space ended detection of any glued payload they followed (review pass 9).
    """
    after = line[b] if b < len(line) else ""
    if after and after in "([":
        return True
    if after == "." and b + 1 < len(line) and (line[b + 1].isalpha() or line[b + 1] == "_"):
        return True
    if a > 1 and line[a - 1] == "." and (line[a - 2].isalnum() or line[a - 2] in "_)]"):
        return True
    # An index walk, not `line[b:].lstrip()`: copying the rest of the line
    # for every name was quadratic on a long line (a minified page).
    i = b
    while i < len(line) and line[i] == " ":
        i += 1
    return i < len(line) and line[i] == "=" and line[i + 1:i + 2] != "="


def _ident_reading(line: str, by_case: bool = True) -> tuple[str, list[tuple[int, int, bool]]]:
    """*line* with each name-like token read as words, and where each
    rewritten token lies in the result."""
    out: list[str] = []
    spans: list[tuple[int, int, bool]] = []
    pos = size = 0
    for m in _IDTOK.finditer(line):
        tok = m.group(0)
        if _in_code_position(line, m.start(), m.end()):
            continue  # a name used as code: `revealPasswordToggle.addEventListener(`
        new = _ident_token(tok, line, m.start(), m.end(), by_case)
        out.append(line[pos:m.start()])
        size += m.start() - pos
        if new != tok:
            # Whether the name is JOINED (`_ . -`...), which is code, or holds
            # an acronym (`OpenSSH`), which is a product name: _runs_of never
            # grows either over neighbouring words ("export Open SSH private
            # keys" read as an exfiltration phrase).
            # Growth over neighbouring words is for a phrase: not for code
            # joins (any `.`, or a join that is not a phrase), and not for a
            # name holding an acronym (`OpenSSH`) unless the capitals are a
            # function word (`IgnoreALL previous ...`).
            seps = _JOINER.findall(tok)
            fixed = (bool(seps) and (any("." in x for x in seps)
                                     or not _is_phrase(_JOINER.split(tok)))) or any(
                x.isupper() and len(x) > 1 and x.lower() not in _function_words()
                for x in _CAMEL_PART.findall(tok))
            spans.append((size, size + len(new), fixed))
        out.append(new)
        size += len(new)
        pos = m.end()
    out.append(line[pos:])
    return "".join(out), spans


def _plain(m: re.Match[str]) -> str:
    run = m.group(0)
    text, a, b = m.string, m.start(), m.end()
    if _CAMEL.search(run) or _touches_name(text, a, b):
        return run
    return _split_short(run) or run


_Reading = tuple[str, "tuple[tuple[int, int, bool], ...] | None"]


def _readings(line: str) -> list[tuple[str, list[tuple[int, int, bool]] | None]]:
    """Readings of *line* (see _short_readings), plus, for each LONG run, the
    window around every trigger word, split. Not cached as a whole: the
    long-run part stops at the scan deadline, and a cut-short result must not
    be remembered as the answer."""
    out: list[tuple[str, list[tuple[int, int, bool]] | None]] = [
        (text, list(spans) if spans is not None else None) for text, spans in _short_readings(line)
    ]
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


@functools.lru_cache(maxsize=16384)
def _short_readings(line: str) -> tuple[_Reading, ...]:
    """Readings of *line*. The second item is None for a PLAIN reading, and
    for an IDENTIFIER-shaped reading the spans of the rewritten tokens:

    - plain glued runs (no CamelCase, not inside a name or path) split;
    - name-like tokens read as words (see _ident_token).

    Pure, so cached: nested re-scans read the same lines again and again.
    """
    out: list[_Reading] = []
    plain = _RUN.sub(_plain, line)
    if plain != line:
        out.append((plain, None))
    seen = {line, plain}
    for by_case in (True, False):
        ident, spans = _ident_reading(line, by_case)
        if spans and ident not in seen:
            seen.add(ident)
            out.append((ident, tuple(spans)))
    return tuple(out)


#: Words a run of names may grow over on each side: an injected phrase is
#: short, and unbounded growth over a long line of words was quadratic.
_GROW_WORDS = 12


def _grow_left(text: str, s: int) -> int:
    """Start of the plain words (letters, space-separated) ending at *s*.
    A walk, not an end-anchored pattern: searching from 0 to *s* for one was
    quadratic on a long line (review pass 8 cost probe)."""
    j = s
    for _ in range(_GROW_WORDS):
        k = j
        while k > 0 and text[k - 1] == " ":
            k -= 1
        w = k
        while w > 0 and "a" <= text[w - 1].lower() <= "z":
            w -= 1
        if k == j or w == k or (w > 0 and (text[w - 1].isalnum() or text[w - 1] in "_.")):
            return j
        j = w
    return j


def _grow_right(text: str, e: int) -> int:
    """End of the plain words starting at *e* (see _grow_left)."""
    j = e
    n = len(text)
    for _ in range(_GROW_WORDS):
        k = j
        while k < n and text[k] == " ":
            k += 1
        w = k
        while w < n and "a" <= text[w].lower() <= "z":
            w += 1
        if k == j or w == k or (w < n and (text[w].isalnum() or text[w] in "_.(")):
            return j
        j = w
    return j



def _runs_of(spans: list[tuple[int, int, bool]], text: str) -> list[tuple[int, int]]:
    """Rewritten names separated only by whitespace, merged: a payload split
    over two names (`IgnoreAll PreviousInstructions`) is still all names
    (review pass 8). Code between names (`.`, `(`, a keyword) keeps them
    apart."""
    out: list[tuple[int, int, bool]] = []
    for s, e, joined in spans:
        if out and not text[out[-1][1]:s].strip():
            out[-1] = (out[-1][0], e, out[-1][2] or joined)
        else:
            out.append((s, e, joined))
    # And over plain words either side, separated only by spaces: a name
    # among words (`Ignore AllPrevious Instructions`) is one phrase. Not for
    # a run holding a joined name: `return auth_user.access_token` is code.
    grown: list[tuple[int, int]] = []
    for s, e, joined in out:
        if joined:
            grown.append((s, e))
            continue
        grown.append((_grow_left(text, s), _grow_right(text, e)))
    return grown


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
        if deadline_exceeded():
            return []  # before any input-proportional work (test_scan_deadline)
        lines = content.splitlines()
        changed: list[int] = []
        rebuilt: list[str] = []
        spans_of: list[list[tuple[int, int, bool]] | None] = []
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
        runs_of: dict[int, list[tuple[int, int]]] = {}
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
                    if k not in runs_of:
                        runs_of[k] = _runs_of(spans, rebuilt[k])  # once per reading
                    a = f.location.column - 1
                    z = a + len(f.matched_raw)
                    if not any(s <= a and z <= e for s, e in runs_of[k]):
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

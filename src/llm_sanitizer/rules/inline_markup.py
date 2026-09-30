# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule: Inline Markup Inside Words.

An HTML tag, comment or character reference inside a word vanishes when the
text is rendered — by a browser, and by every Markdown renderer that passes
inline HTML through: ``ig<b></b>nore``, ``ig&shy;nore``, ``ig&#x200B;nore``,
``ig<!---->nore`` and ``ig<span hidden>q</span>nore`` all display as
``ignore``. The raw markup never matches a word rule (0.7.2 review, pass 6;
0.7.1 behaves the same).

Like every obfuscation rule this is transport, not threat: each paragraph
holding such markup is read the way it renders and re-scanned with the full
ruleset (:func:`scan_deobfuscated`), so a decoded soft hyphen or zero-width
space is then handled by the zero-width rule. It fires only when that reading
trips a rule the raw paragraph did not. The markup itself is still scanned raw
by every other rule; this adds a reading, it removes nothing.

Rendering uses the standard library's HTML parser, not a hand-written pattern:
a pattern missed references with no closing `;`, quoted attributes holding
`>`, and tags or comments running over a line break (review pass 7). The
parser handles those the way a browser does.
"""

from __future__ import annotations

import bisect
import functools
import html
import re
from collections import Counter
from html.parser import HTMLParser

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

#: A character reference inside a data run, joined to letters on both sides.
#: Linear: the reference can only extend over letters, digits and `;`.
_REF_IN_WORD = re.compile(r"[0-9A-Za-z]&#?[0-9A-Za-z]{1,64};?(?=[0-9A-Za-z])")

#: Elements after which a browser starts a new line or block: a space in the
#: rendered reading, so words either side are not glued by the rendering.
_BREAKS = frozenset({
    "br", "p", "div", "li", "ul", "ol", "tr", "td", "th", "table", "section",
    "article", "header", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "hr",
    "blockquote", "pre",
})
#: Elements whose content is never rendered as text.
_NOT_RENDERED = frozenset({"script", "style", "template", "noscript", "noembed", "head", "title"})
_VOID = frozenset({"br", "hr", "img", "wbr", "input", "meta", "link", "area",
                   "base", "col", "embed", "source", "track"})
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)"
    r"|font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])",
    re.IGNORECASE,
)
_CSS_ESCAPE = re.compile(r"\\([0-9a-fA-F]{1,6})\s?|\\(.)")


def _css_unescape(style: str) -> str:
    """`dis\\70 lay:none` is `display:none` to a browser."""
    return _CSS_ESCAPE.sub(
        lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2), style)


#: Markdown inline syntax directly between two word characters that renders to
#: nothing between them: code spans, `*` emphasis, `~~` strike, empty links and
#: images. Not `_` or `\\`: CommonMark renders those literally inside a word,
#: and snake_case is everywhere. Bounded, so it cannot backtrack far.
_MD_IN_WORD = re.compile(
    r"(?<=[0-9A-Za-z])!?\[\]\([^)\s]{0,200}\)(?=[0-9A-Za-z])"
)
#: Emphasis, code and strike markers as a matched PAIR around letters inside a
#: word (`ig**n**ore`, `` ig`n`ore ``). An unpaired `**` is exponentiation in
#: code (`x**0.5`), and reading it as markup flagged ordinary Python.
_MD_PAIR_IN_WORD = re.compile(r"(?<=[A-Za-z])(\*{1,3}|`{1,3}|~~)([A-Za-z]{1,40})\1(?=[A-Za-z])")
#: `</>` between two word characters: markup a browser drops, joining them.
_EMPTY_END_IN_WORD = re.compile(r"[0-9A-Za-z](?:</>)+[0-9A-Za-z]")
#: A Markdown link with text inside a word renders as its text: `ig[n](x)ore`.
_MD_LINK_IN_WORD = re.compile(r"(?<=[0-9A-Za-z])\[([0-9A-Za-z]{1,50})\]\([^)\s]{0,200}\)(?=[0-9A-Za-z])")


class _Renderer(HTMLParser):
    """One pass of the standard library's tokenizer (linear in the input)
    that yields both the text as rendered — tags and comments dropped,
    character references decoded, the text of hidden elements left out — and
    whether any markup token sat directly between two word characters.

    Do not replace this with a pattern over the raw text: a pattern for
    "markup between word characters" backtracks, and `a<` or `a<!--`
    repeated a few thousand times took seconds, growing with the square of
    the input (review pass 8)."""

    def __init__(self, raw: str, drop_styled: bool = False) -> None:
        super().__init__(convert_charrefs=False)
        self.raw = raw
        #: Treat any element with a class, id or style as hidden: hiding done
        #: in a stylesheet cannot be resolved here, so one reading assumes it.
        self.drop_styled = drop_styled
        self.styled = False
        self._starts = [0, *(m.end() for m in re.finditer("\n", raw))]
        self.parts: list[str] = []
        self._hidden: list[str] = []
        self.in_word = False
        self._markup_from: int | None = None  # start of a run of markup tokens
        self._refs = 0  # character references in the current run

    def _here(self) -> int:
        line, col = self.getpos()
        return self._starts[line - 1] + col

    def _markup(self) -> None:
        if self._markup_from is None:
            self._markup_from = self._here()

    def _text(self) -> None:
        # A run of markup ends where text resumes: it joined two words if
        # word characters sit on both sides of it.
        if self._markup_from is not None:
            a, b = self._markup_from, self._here()
            if a > 0 and b < len(self.raw) and self.raw[a - 1].isalnum() and self.raw[b].isalnum():
                self.in_word = True
            # A word written wholly as references (`&#105;&#103;...`) has no
            # plain letter beside it.
            if self._refs >= 2:
                self.in_word = True
            self._markup_from = None
            self._refs = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._markup()
        # A hidden element breaks nothing: `ig<div hidden></div>nore` renders
        # as one word (review pass 9).
        if tag in _BREAKS and not self._hidden and not self._opens_hidden(tag, attrs):
            self.parts.append(" ")
        if tag in _VOID:
            return
        style = _css_unescape(" ".join(v or "" for k, v in attrs if k == "style"))
        has_style = any(k in ("class", "id", "style") for k, _ in attrs)
        self.styled = self.styled or has_style
        if (self._hidden or tag in _NOT_RENDERED or any(k == "hidden" for k, _ in attrs)
                or _HIDDEN_STYLE.search(style) or (self.drop_styled and has_style)):
            self._hidden.append(tag)

    def _opens_hidden(self, tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        style = _css_unescape(" ".join(v or "" for k, v in attrs if k == "style"))
        has_style = any(k in ("class", "id", "style") for k, _ in attrs)
        return (tag in _NOT_RENDERED or any(k == "hidden" for k, _ in attrs)
                or bool(_HIDDEN_STYLE.search(style)) or (self.drop_styled and has_style))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID:
            # A browser ignores the `/` on a non-void element: `<span hidden/>`
            # OPENS a hidden span (review pass 8).
            self.handle_starttag(tag, attrs)
            return
        self._markup()
        if tag in _BREAKS:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        self._markup()
        if tag in _BREAKS and not self._hidden:
            self.parts.append(" ")
        # Close up to the matching open element, as a browser does. Popping
        # only an exact top-of-stack match left a mis-nested hidden element
        # (`<span hidden><i>z</span>`) hiding the rest of the paragraph.
        if tag in self._hidden:
            while self._hidden and self._hidden.pop() != tag:
                pass

    def handle_comment(self, data: str) -> None:
        self._markup()

    def handle_decl(self, decl: str) -> None:
        self._markup()

    def unknown_decl(self, data: str) -> None:
        self._markup()

    def handle_pi(self, data: str) -> None:
        self._markup()

    def _ref_touches_word(self, start: int, length: int) -> None:
        # A reference decodes to a character: touching a word character on
        # EITHER side it is part of that word (`&#105;gnore` at a line start
        # has nothing before it).
        end = start + length
        if (start > 0 and self.raw[start - 1].isalnum()) or (
                end < len(self.raw) and self.raw[end].isalnum()):
            self.in_word = True

    def handle_charref(self, name: str) -> None:
        start = self._here()
        semi = 1 if start + 2 + len(name) < len(self.raw) and self.raw[start + 2 + len(name)] == ";" else 0
        self._ref_touches_word(start, 2 + len(name) + semi)
        self._markup()
        self._refs += 1
        if not self._hidden:
            self.parts.append(f"&#{name};")

    def handle_entityref(self, name: str) -> None:
        # Re-encoded exactly as written: with no `;` the tokenizer hands over
        # the reference AND the letters after it (`&shynore`), and adding a
        # `;` changed how html.unescape decodes it.
        start = self._here()
        at = start + 1 + len(name)
        semi = ";" if at < len(self.raw) and self.raw[at] == ";" else ""
        if not semi and start > 0 and self.raw[start - 1].isalnum():
            # The letters after an unterminated reference are part of the
            # token, so the "word on both sides" test below cannot see them.
            self.in_word = True
        self._ref_touches_word(start, 1 + len(name) + len(semi))
        self._markup()
        self._refs += 1
        if not self._hidden:
            self.parts.append(f"&{name}{semi}")

    def handle_data(self, data: str) -> None:
        if self._hidden:
            # Hidden text is not text to the reader: it continues a run of
            # markup, so `ig<span hidden>!</span>nore` joins a word.
            self._markup()
            return
        self._text()
        if _REF_IN_WORD.search(data):
            self.in_word = True
        self.parts.append(data)


def _render(raw: str, drop_styled: bool = False) -> tuple[str, bool, bool]:
    """(the text as rendered, whether markup joined two words, whether any
    element carried a class, id or style)."""
    # `</>` is dropped by a browser's tokenizer; html.parser keeps it as text.
    # The renderer holds the SAME text it is fed: its positions index into it.
    joined = bool(_EMPTY_END_IN_WORD.search(raw))
    raw = raw.replace("</>", "")
    r = _Renderer(raw, drop_styled)
    r.feed(raw)
    r.close()
    r._text()  # close a run of markup that ends the paragraph
    r.in_word = r.in_word or joined
    # References left in data (no `;`, or not recognised by the tokenizer) are
    # decoded here, the way a browser does.
    return html.unescape("".join(r.parts)), r.in_word, r.styled


@functools.lru_cache(maxsize=4096)
def _readings(raw: str) -> tuple[str, ...]:
    """Rendered readings of one paragraph that differ from it: as HTML
    renders it; the same with styled elements' text dropped (stylesheet
    hiding cannot be resolved, so fail toward reading it as hidden); and
    with Markdown syntax inside words removed."""
    out: list[str] = []
    # Rendering is about TEXT a reader sees. A segment dense with control
    # characters is binary (a PDF font stream reaches this rule through the
    # rewrite check), and its "rendering" is noise that trips rules at random.
    controls = sum(1 for c in raw if c < " " and c not in "\t\n\r")
    if "\x00" in raw or controls * 20 > len(raw):
        return ()
    if "<" in raw or "&" in raw:
        rendered, in_word, styled = _render(raw)
        if in_word:
            out.append(rendered)
            if styled:
                out.append(_render(raw, drop_styled=True)[0])
    if _MD_IN_WORD.search(raw) or _MD_LINK_IN_WORD.search(raw) or _MD_PAIR_IN_WORD.search(raw):
        out.append(_MD_PAIR_IN_WORD.sub(r"\2", _MD_IN_WORD.sub("", _MD_LINK_IN_WORD.sub(r"\1", raw))))
    flat = " ".join(raw.split())
    return tuple(x for x in dict.fromkeys(" ".join(r.split()) for r in out) if x and x != flat)


def _paragraphs(lines: list[str]) -> list[tuple[int, int]]:
    """(first line, last line + 1) of each run of non-blank lines — joined
    with the next run while it ends inside an open comment or tag, so markup
    holding a blank line (`<!--\n\n-->`) stays one piece (review pass 8)."""
    out: list[tuple[int, int]] = []
    start = None
    for i, line in enumerate(lines):
        if line.strip():
            if start is None:
                start = i
        elif start is not None:
            out.append((start, i))
            start = None
    if start is not None:
        out.append((start, len(lines)))
    merged: list[tuple[int, int]] = []
    in_comment = in_tag = False
    for a, b in out:
        if (in_comment or in_tag) and merged:
            merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))
        # State carried chunk by chunk (re-reading the growing paragraph was
        # quadratic): the LAST opener or closer in this chunk decides.
        chunk = "\n".join(lines[a:b])
        lo, lc = chunk.rfind("<!--"), chunk.rfind("-->")
        if lo != lc:
            in_comment = lo > lc
        to, tc = chunk.rfind("<"), chunk.rfind(">")
        if to != tc:
            in_tag = to > tc
    return merged


#: A segment longer than this many lines is read in overlapping chunks: one
#: reading line per segment made a 200 KB paragraph one line, and work per
#: finding on it grew with its length (review pass 8 cost probe).
_CHUNK_LINES, _CHUNK_OVERLAP = 64, 4


class _BlockFinder(HTMLParser):
    """Offsets of block-level tags, as the tokenizer sees them. A pattern over
    the raw text also matched a `<p>` inside a comment or an attribute value
    and cut the paragraph there (review pass 9)."""

    def __init__(self, raw: str) -> None:
        super().__init__(convert_charrefs=False)
        self._starts = [0, *(m.end() for m in re.finditer("\n", raw))]
        self.raw = raw
        self.cuts: list[tuple[int, int]] = []
        self._hidden: list[str] = []

    def _tag(self, tag: str) -> None:
        # A HIDDEN block element breaks nothing, so it is no cut
        # (`ig<div hidden></div>nore` renders as one word).
        if tag in _BREAKS and not self._hidden:
            line, col = self.getpos()
            a = self._starts[line - 1] + col
            end = self.raw.find(">", a)
            self.cuts.append((a, end + 1 if end >= 0 else a))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        style = _css_unescape(" ".join(v or "" for k, v in attrs if k == "style"))
        hides = (tag in _NOT_RENDERED or any(k == "hidden" for k, _ in attrs)
                 or bool(_HIDDEN_STYLE.search(style)))
        if not hides:
            self._tag(tag)
        if tag not in _VOID and (self._hidden or hides):
            self._hidden.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in self._hidden:
            while self._hidden and self._hidden.pop() != tag:
                pass
            return
        self._tag(tag)


def _segments(content: str, a: int, b: int) -> list[tuple[int, int]]:
    """Absolute (start, end) of each block-delimited segment of content[a:b].
    A paragraph is judged, and redacted, one segment at a time — markup
    cannot join two words across a block-level tag, and judging a whole page
    deleted all of it for one hidden payload (passes 7-8) — with long
    segments cut into overlapping chunks of lines."""
    raw = content[a:b]
    if "<" not in raw:
        return _chunks(content, a, b)
    finder = _BlockFinder(raw)
    finder.feed(raw)
    finder.close()
    out: list[tuple[int, int]] = []
    pos = 0
    for s, e in finder.cuts:
        if s > pos:
            out.extend(_chunks(content, a + pos, a + s))
        pos = max(pos, e)
    if len(raw) > pos:
        out.extend(_chunks(content, a + pos, b))
    return out


def _chunks(content: str, a: int, b: int) -> list[tuple[int, int]]:
    """content[a:b] in chunks of about _CHUNK_LINES lines, overlapping, never
    ended inside an open comment or tag: a comment open across a cut was
    seen by neither chunk (review pass 9)."""
    starts = [a] + [a + m.end() for m in re.finditer("\n", content[a:b]) if a + m.end() < b]
    n = len(starts)
    if n <= _CHUNK_LINES:
        return [(a, b)]
    # ok[j]: a chunk may end before line j (nothing open at that point).
    ok = [True] * (n + 1)
    in_comment = in_tag = False
    for i, s0 in enumerate(starts):
        line = content[s0:starts[i + 1] if i + 1 < n else b]
        lo, lc = line.rfind("<!--"), line.rfind("-->")
        if lo != lc:
            in_comment = lo > lc
        to, tc = line.rfind("<"), line.rfind(">")
        if to != tc:
            in_tag = to > tc
        ok[i + 1] = not (in_comment or in_tag)
    out: list[tuple[int, int]] = []
    i = 0
    while i < n:
        j = min(i + _CHUNK_LINES, n)
        while j < n and not ok[j]:
            j += 1  # extend past an open comment or tag
        out.append((starts[i], starts[j] - 1 if j < n else b))
        if j >= n:
            break
        i = max(j - _CHUNK_OVERLAP, i + 1)
    return out


@register_rule
class InlineMarkupRule(BaseRule):
    rule_id = "inline_markup"
    rule_name = "Inline Markup Inside Words"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects HTML tags, comments or character references placed inside "
        "words so the raw text evades word rules while rendering normally — "
        "flagged only when the rendered reading reveals content another rule "
        "flags."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        if deadline_exceeded():
            return []  # before any input-proportional work (test_scan_deadline)
        # Gate on the characters, not on "a letter right before `<` or `&`":
        # a word written starting with a reference (`&#105;gnore`) has none,
        # and the tokenizer below decides whether markup joined words.
        if ("<" not in content and "&" not in content and not _MD_IN_WORD.search(content)
                and not _MD_LINK_IN_WORD.search(content) and not _MD_PAIR_IN_WORD.search(content)):
            return []
        lines = content.splitlines()
        starts = [0]
        for piece in content.splitlines(keepends=True):
            starts.append(starts[-1] + len(piece))
        units: list[tuple[int, int]] = []  # absolute (start, end) in content
        rebuilt: list[str] = []
        for a, b in _paragraphs(lines):
            if deadline_exceeded():
                return []
            p0 = starts[a]
            p1 = starts[b - 1] + len(lines[b - 1])
            for s0, s1 in _segments(content, p0, p1):
                # One line per reading: the rendering is judged as the reader
                # sees it, and a finding maps back to its segment.
                for shown in _readings(content[s0:s1]):
                    units.append((s0, s1))
                    rebuilt.append(shown)
        if not units:
            return []
        # One re-scan of every rendered segment together (linear in the
        # input), then a baseline only for the segments that tripped
        # something — scanned without this rule (see _rescan._excluded).
        found = scan_deobfuscated("\n".join(rebuilt) + "\n", source, linear=True)
        by_unit: dict[int, list[Finding]] = {}
        for f in found:
            k = f.location.line - 1
            if 0 <= k < len(units):
                by_unit.setdefault(k, []).append(f)
        findings: list[Finding] = []
        flagged: set[tuple[int, int]] = set()
        baselines: dict[tuple[int, int], Counter[str]] = {}
        for k, fs in sorted(by_unit.items()):
            if deadline_exceeded():
                return []
            unit = units[k]
            if unit in flagged:
                continue  # one finding per segment, whichever reading showed it
            raw = content[unit[0]:unit[1]]
            if unit not in baselines:
                # The segment FLATTENED like its readings: scanning it with its
                # line breaks scored differently (the classifier reads whole
                # sentences), and code joined into one line looked "revealed"
                # (review pass 9: ordinary Python flagged).
                baselines[unit] = Counter(f.rule for f in scan_deobfuscated(
                    " ".join(raw.split()) + "\n", source, linear=True,
                    exclude=frozenset({self.rule_id})))
            baseline = baselines[unit]
            counts = Counter(f.rule for f in fs)
            newly = [f for f in fs if counts[f.rule] > baseline.get(f.rule, 0)]
            if not newly:
                continue
            flagged.add(unit)
            risk = max((f.risk for f in newly), key=lambda r: r.value)
            tripped = ", ".join(sorted({f.rule_name for f in newly}))
            line_idx = bisect.bisect_right(starts, unit[0]) - 1
            col = unit[0] - starts[line_idx] + 1
            before, line_text, after = self._build_context(lines, line_idx)
            findings.append(self._make_finding(
                finding_id=len(findings) + 1,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                risk=risk,
                line_no=line_idx + 1,
                col=col,
                end_col=col + len(raw),
                matched=raw[:80] + ("..." if len(raw) > 80 else ""),
                matched_raw=raw,
                before=before,
                line_text=line_text,
                after=after,
                explanation=(
                    "Markup inside words: rendered, the text reads "
                    f"{rebuilt[k][:80]!r}, which is flagged by {tripped}."
                ),
            ))
        return findings

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

import html
import re
from collections import Counter
from html.parser import HTMLParser

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

#: Cheap prefilter: a word character directly before `<` or `&`. Only a
#: paragraph holding one is tokenised.
_NEAR = re.compile(r"[0-9A-Za-z][<&]")
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
_VOID = frozenset({"br", "hr", "img", "wbr", "input", "meta", "link", "area",
                   "base", "col", "embed", "source", "track"})
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE)


class _Renderer(HTMLParser):
    """One pass of the standard library's tokenizer (linear in the input)
    that yields both the text as rendered — tags and comments dropped,
    character references decoded, the text of hidden elements left out — and
    whether any markup token sat directly between two word characters.

    Do not replace this with a pattern over the raw text: a pattern for
    "markup between word characters" backtracks, and `a<` or `a<!--`
    repeated a few thousand times took seconds, growing with the square of
    the input (review pass 8)."""

    def __init__(self, raw: str) -> None:
        super().__init__(convert_charrefs=False)
        self.raw = raw
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
        if tag in _BREAKS:
            self.parts.append(" ")
        if tag in _VOID:
            return
        style = " ".join(v or "" for k, v in attrs if k == "style")
        if self._hidden or any(k == "hidden" for k, _ in attrs) or _HIDDEN_STYLE.search(style):
            self._hidden.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._markup()
        if tag in _BREAKS:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        self._markup()
        if tag in _BREAKS:
            self.parts.append(" ")
        if self._hidden and self._hidden[-1] == tag:
            self._hidden.pop()

    def handle_comment(self, data: str) -> None:
        self._markup()

    def handle_decl(self, decl: str) -> None:
        self._markup()

    def unknown_decl(self, data: str) -> None:
        self._markup()

    def handle_pi(self, data: str) -> None:
        self._markup()

    def handle_charref(self, name: str) -> None:
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
        self._markup()
        self._refs += 1
        if not self._hidden:
            self.parts.append(f"&{name}{semi}")

    def handle_data(self, data: str) -> None:
        self._text()
        if _REF_IN_WORD.search(data):
            self.in_word = True
        if not self._hidden:
            self.parts.append(data)


def _render(raw: str) -> tuple[str, bool]:
    """(the text as rendered, whether markup joined two words)."""
    r = _Renderer(raw)
    r.feed(raw)
    r.close()
    r._text()  # close a run of markup that ends the paragraph
    # References left in data (no `;`, or not recognised by the tokenizer) are
    # decoded here, the way a browser does.
    return html.unescape("".join(r.parts)), r.in_word


def _paragraphs(lines: list[str]) -> list[tuple[int, int]]:
    """(first line, last line + 1) of each run of non-blank lines."""
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
        if ("<" not in content and "&" not in content) or not _NEAR.search(content):
            return []
        lines = content.splitlines()
        blocks: list[tuple[int, int]] = []
        rebuilt: list[str] = []
        for a, b in _paragraphs(lines):
            if deadline_exceeded():
                return []
            raw = "\n".join(lines[a:b])
            if not _NEAR.search(raw):
                continue
            rendered, in_word = _render(raw)
            if not in_word:
                continue
            # One line per paragraph in the reading: the rendering is judged
            # as the reader sees it, and a finding maps back to its paragraph.
            shown = " ".join(rendered.split())
            if shown and shown != " ".join(raw.split()):
                blocks.append((a, b))
                rebuilt.append(shown)
        if not blocks:
            return []
        # One re-scan of every rendered paragraph together (linear in the
        # input), then a baseline only for the paragraphs that tripped
        # something — scanned without this rule (see _rescan._excluded).
        found = scan_deobfuscated("\n".join(rebuilt) + "\n", source, linear=True)
        by_block: dict[int, list[Finding]] = {}
        for f in found:
            k = f.location.line - 1
            if 0 <= k < len(blocks):
                by_block.setdefault(k, []).append(f)
        findings: list[Finding] = []
        for k, fs in sorted(by_block.items()):
            if deadline_exceeded():
                return []
            a, b = blocks[k]
            raw = "\n".join(lines[a:b])
            baseline = Counter(f.rule for f in scan_deobfuscated(
                raw + "\n", source, linear=True, exclude=frozenset({self.rule_id})))
            counts = Counter(f.rule for f in fs)
            newly = [f for f in fs if counts[f.rule] > baseline.get(f.rule, 0)]
            if not newly:
                continue
            risk = max((f.risk for f in newly), key=lambda r: r.value)
            tripped = ", ".join(sorted({f.rule_name for f in newly}))
            # The finding is the whole paragraph: redaction must also remove
            # markup that ran over a line break.
            before, line_text, after = self._build_context(lines, a)
            findings.append(self._make_finding(
                finding_id=len(findings) + 1,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                risk=risk,
                line_no=a + 1,
                col=1,
                end_col=len(raw) + 1,
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

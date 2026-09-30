# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule: Inline Markup Inside Words.

An HTML tag or character reference inside a word vanishes when the text is
rendered — by a browser, and by every Markdown renderer that passes inline
HTML through: ``ig<b></b>nore``, ``ig&shy;nore``, ``ig&#x200B;nore`` and
``ig<!---->nore`` all display as ``ignore``. The raw markup never matches a
word rule (0.7.2 review, pass 6; 0.7.1 behaves the same).

Like every obfuscation rule this is transport, not threat: the line is read
the way it renders — tags removed, character references decoded — and re-scanned
with the full ruleset (:func:`scan_deobfuscated`), so a decoded soft hyphen or
zero-width space is then handled by the zero-width rule. It fires only when
that reading trips a rule the raw line did not. The markup itself is still
scanned raw by every other rule; this adds a reading, it removes nothing.
"""

from __future__ import annotations

import html
import re
from collections import Counter

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

#: A tag, comment or character reference directly between two word characters,
#: possibly several in a row — the shapes that join a word when rendered.
_IN_WORD = re.compile(
    r"[0-9A-Za-z](?:<[^<>\n]{0,200}>|&#?[0-9A-Za-z]{1,32};)+[0-9A-Za-z]"
)
_TAG = re.compile(r"<[^<>\n]{0,200}>")


def _rendered(line: str) -> str:
    return html.unescape(_TAG.sub("", line))


@register_rule
class InlineMarkupRule(BaseRule):
    rule_id = "inline_markup"
    rule_name = "Inline Markup Inside Words"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects HTML tags or character references placed inside words so the "
        "raw text evades word rules while rendering normally — flagged only when "
        "the rendered reading reveals content another rule flags."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        lines = content.splitlines()
        changed: list[int] = []
        rebuilt: list[str] = []
        for idx, line in enumerate(lines):
            if deadline_exceeded():
                return []
            if ("<" in line or "&" in line) and _IN_WORD.search(line):
                new = _rendered(line)
                if new != line:
                    changed.append(idx)
                    rebuilt.append(new)
        if not changed:
            return []
        # One re-scan of every rendered line together (linear in the input),
        # then a baseline only for the lines that tripped something.
        found = scan_deobfuscated("\n".join(rebuilt) + "\n", source, linear=True)
        by_line: dict[int, list[Finding]] = {}
        for f in found:
            k = f.location.line - 1
            if 0 <= k < len(changed):
                by_line.setdefault(k, []).append(f)
        findings: list[Finding] = []
        for k, fs in sorted(by_line.items()):
            if deadline_exceeded():
                return []
            idx = changed[k]
            line = lines[idx]
            baseline = Counter(f.rule for f in scan_deobfuscated(line, source, linear=True))
            counts = Counter(f.rule for f in fs)
            newly = [f for f in fs if counts[f.rule] > baseline.get(f.rule, 0)]
            if not newly:
                continue
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
                    "Markup inside words: rendered, the line reads "
                    f"{rebuilt[k][:80]!r}, which is flagged by {tripped}."
                ),
            ))
        return findings

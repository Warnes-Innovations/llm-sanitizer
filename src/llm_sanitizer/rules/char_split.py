# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule: Character-Splitting Obfuscation.

Splitting a phrase with separators — ``i g n o r e   a l l`` (inter-character
spaces) or ``ignore___all___previous`` (multi-character separators between
words) — defeats word-based detection while remaining readable to a human. Like
base64 and homoglyph substitution this is *transport*, not a threat in itself:
it is only a problem if reconstructing the text reveals something a real rule
flags. So this rule reconstructs the split text and re-scans it with the full
ruleset (:func:`scan_deobfuscated`), flagging only when the *reconstructed* text
trips a rule. Ordinary prose and ``snake_case`` identifiers (single underscores)
reconstruct to text that trips nothing and stay clean.
"""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

# Separators an attacker uses to break up a word/phrase. Kept as a character-
# class body: '-' is last so it is a literal, '.', '*', '|' are literal inside
# '[...]'. \t is a real tab.
_SEP_CHARS = " \t_.·*|-"

# Signal 1: >=5 single alphanumeric chars each followed by a single separator
# ("i g n o r e", "i_g_n_o_r_e"). Single-char token runs are not natural text.
_INTERCHAR = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9A-Za-z][" + _SEP_CHARS + r"]){4,}[0-9A-Za-z](?![0-9A-Za-z])"
)
# Signal 2: a word char, a run of >=2 of the SAME separator, another word char
# ("ignore___all", "ignore...all", "a|||b"). A single underscore (snake_case) is
# intentionally NOT a signal, so legitimate identifiers are left alone.
#
# The repeated-SAME-separator requirement (\1+ rather than a bare {2,} over the
# whole class) is load-bearing for precision: with a mixed run allowed, the
# two-character sequence ". " — a period followed by a space, i.e. EVERY
# sentence boundary in ordinary prose — matched, so any document with normal
# punctuation "looked split", was reconstructed, and was re-scanned. Combined
# with base64's former willingness to "decode" long dictionary words, that
# recursed to the de-obfuscation depth cap and reported benign business prose as
# CRITICAL. Deliberately repeating one separator is the actual obfuscation
# pattern; mixed punctuation is just writing.
#
# Anchored on the separator run (single word chars either side, no greedy {2,}
# alnum quantifier) so it cannot backtrack quadratically on a long
# separator-free run; \1+ is a plain greedy repeat of one literal character.
_MULTISEP = re.compile(r"[0-9A-Za-z]([" + _SEP_CHARS + r"])\1+[0-9A-Za-z]")

# Tokenize into word / whitespace-run / punctuation-run pieces.
_TOKEN = re.compile(r"[0-9A-Za-z]+|\s+|[^0-9A-Za-z\s]+")


def _reconstruct(line: str) -> str:
    """Rebuild a split line into plain words.

    Single-character tokens are concatenated (an intra-word split); a separator
    run of length >=2 is a word boundary; multi-character tokens are words in
    their own right. Applied only to lines that already look split (see
    _looks_split), and gated by the re-scan so an over-eager reconstruction that
    happens to be benign is simply never reported.
    """
    words: list[str] = []
    current = ""
    for tok in _TOKEN.findall(line):
        if tok[0].isalnum():
            if len(tok) == 1:
                current += tok
            else:
                if current:
                    words.append(current)
                    current = ""
                words.append(tok)
        else:
            # A separator run of length >=2 ends the current reconstructed word;
            # a single separator between single-char tokens is dropped (it is the
            # splitter). Between multi-char words a single separator is a no-op
            # here because those words were already emitted individually.
            if len(tok) >= 2 and current:
                words.append(current)
                current = ""
    if current:
        words.append(current)
    return " ".join(words)


def _looks_split(line: str) -> bool:
    return bool(_INTERCHAR.search(line) or _MULTISEP.search(line))


@register_rule
class CharSplitRule(BaseRule):
    rule_id = "char_split"
    rule_name = "Character-Splitting Obfuscation"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects text split with inter-character spaces or repeated separators "
        "to evade word-based detection — flagged only when reconstructing the "
        "split text reveals content another rule flags, never on the splitting "
        "alone (so snake_case and ordinary prose stay clean)."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            if deadline_exceeded():
                break
            if not _looks_split(line):
                continue
            reconstructed = _reconstruct(line)
            if reconstructed == line or not reconstructed.strip():
                continue
            # Only credit findings the reconstruction REVEALS: diff against what
            # the raw line already trips, so an injection that fires on the raw
            # text is not double-reported here.
            baseline = {
                (f.rule, f.matched) for f in scan_deobfuscated(line, source)
            }
            sub_findings = [
                f
                for f in scan_deobfuscated(reconstructed, source)
                if (f.rule, f.matched) not in baseline
            ]
            if not sub_findings:
                continue
            risk = max((f.risk for f in sub_findings), key=lambda r: r.value)
            tripped = ", ".join(sorted({f.rule_name for f in sub_findings}))
            before, line_text, after = self._build_context(lines, line_idx)
            findings.append(
                self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=risk,
                    line_no=line_idx + 1,
                    col=1,
                    end_col=len(line) + 1,
                    matched=line[:80] + ("..." if len(line) > 80 else ""),
                    matched_raw=line,
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        "Character-splitting obfuscation: reconstructing the split "
                        f"text {reconstructed[:80]!r} reveals content flagged by "
                        f"{tripped}."
                    ),
                )
            )
            fid += 1

        return findings

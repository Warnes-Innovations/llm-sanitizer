# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 8: Base64-Encoded Content.

Base64 is an obfuscation layer, not a threat in itself: encoded content is only
a problem if what it *decodes to* is a problem. So this rule decodes each
base64 blob and re-scans the decoded text with the full detection ruleset
(:func:`scan_deobfuscated`), surfacing whatever the other rules find — an
injection hidden one (or a few) layers down, including nested base64. Innocent
base64 (a key, a hash, an encoded innocuous sentence) decodes to text that
trips nothing and is left clean.
"""

from __future__ import annotations

import base64
import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import deadline_exceeded, scan_deobfuscated

# Minimum length of a base64-looking run (non-padding chars) to bother decoding.
# Kept low (M10): "act as DAN" is only 14 non-pad base64 chars. The floor is
# precision-NEUTRAL — a blob is only ever reported if its DECODED text trips a
# real rule (scan_deobfuscated), so short random tokens (hashes, ids) decode to
# gibberish and stay clean. The floor exists only to skip trivially-short runs
# and bound decode attempts; total re-scan work is separately capped by the
# _rescan byte budget.
_MIN_B64_LENGTH = 12

_B64_PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{' + str(_MIN_B64_LENGTH) + r',}={0,2})(?![A-Za-z0-9+/=])'
)

# A whole line that is nothing but base64 (as MIME wraps it, ~76 chars/line).
# Used to reassemble a blob split across several lines (M11).
_B64_FULL_LINE = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')


def _looks_like_base64(s: str) -> bool:
    """Candidate gate: does this run plausibly encode bytes, or is it a word?

    ``_B64_PATTERN`` matches any run of >=12 base64-alphabet characters, which
    every ordinary >=12-letter English word satisfies ("microcontroller",
    "documentation", "transportation"). Requiring characters from at least TWO
    of {lowercase, uppercase, digit, ``+/``} rejects single-class dictionary
    words before any decode attempt, while genuine base64 of real bytes mixes
    classes with overwhelming probability (a 12-char run staying inside one
    class has probability ~(26/64)**12 ≈ 4e-6).

    This is a precision floor, not a security boundary: a payload deliberately
    crafted to encode as single-class base64 would be missed here, but it is
    still subject to the depth-capped ``chained_obfuscation`` backstop and to
    the other rules scanning the raw text.
    """
    body = s.rstrip("=")
    classes = (
        any(c.islower() for c in body)
        + any(c.isupper() for c in body)
        + any(c.isdigit() for c in body)
        + any(c in "+/" for c in body)
    )
    return classes >= 2


def _try_decode_base64(s: str) -> str | None:
    """Attempt to decode a base64 string. Return decoded text or None."""
    if not _looks_like_base64(s):
        return None
    # Pad if needed
    padded = s + "=" * ((-len(s)) % 4)
    try:
        decoded_bytes = base64.b64decode(padded)
        # UTF-8 ONLY — deliberately no latin-1 fallback. latin-1 decodes ANY
        # byte sequence without error, so it made essentially every candidate
        # "decode" to garbage that then recursed through scan_deobfuscated until
        # it hit the depth cap and emitted a fail-closed chained_obfuscation
        # CRITICAL — the false-positive cascade that made ordinary prose
        # unscannable. A genuine hidden-text payload is UTF-8; bytes that are
        # not valid UTF-8 are not recoverable text and must not be re-scanned.
        try:
            text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None
        # Must be mostly printable. Sample the first 64 KiB for the ratio so a
        # multi-MB decoded blob doesn't cost an O(n) per-char isprintable() pass
        # (the printable-ratio is representative from a prefix).
        sample = text[:65536]
        printable = sum(c.isprintable() for c in sample)
        if len(sample) > 0 and printable / len(sample) > 0.8:
            return text
    except Exception:
        # Intentional broad catch (CodeQL py/empty-except, reviewed): a blob that
        # isn't valid/decodable base64 is the common case, not an error — treat
        # any decode/parse failure as "not base64" and return None.
        pass
    return None


@register_rule
class Base64EncodedRule(BaseRule):
    rule_id = "base64_encoded"
    rule_name = "Base64-Encoded Content"
    category = "obfuscation"
    default_risk = RiskLevel.high
    description = (
        "Detects base64-encoded strings that decode to content the other "
        "detection rules flag. Decodes each blob and re-scans the decoded text "
        "with the full ruleset (recursively, for nested base64)."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            if deadline_exceeded():
                break
            for m in _B64_PATTERN.finditer(line):
                if deadline_exceeded():
                    break
                candidate = m.group(1)
                decoded = _try_decode_base64(candidate)
                if not decoded:
                    continue
                # Treat the decoded text as ordinary content and scan it. Only
                # a real finding from another rule makes this base64 suspicious.
                sub_findings = scan_deobfuscated(decoded, source)
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
                        col=m.start() + 1,
                        end_col=m.end() + 1,
                        matched=candidate[:80]
                        + ("..." if len(candidate) > 80 else ""),
                        matched_raw=candidate,
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            f"Base64 content decodes to text flagged by {tripped}: "
                            f"{decoded[:100]!r}"
                        ),
                    )
                )
                fid += 1

        # M11: reassemble base64 blobs wrapped across consecutive lines (MIME
        # style), which the per-line pass above cannot decode because each line
        # is only a fragment. Join runs of >=2 whole-base64 lines, decode, and
        # re-scan; report at the run's first line.
        run_start = 0
        run: list[str] = []

        def _flush_run(start: int, parts: list[str]) -> None:
            nonlocal fid
            if len(parts) < 2:
                return
            joined = "".join(parts)
            decoded = _try_decode_base64(joined)
            if not decoded:
                return
            sub_findings = scan_deobfuscated(decoded, source)
            if not sub_findings:
                return
            risk = max((f.risk for f in sub_findings), key=lambda r: r.value)
            tripped = ", ".join(sorted({f.rule_name for f in sub_findings}))
            before, line_text, after = self._build_context(lines, start)
            findings.append(
                self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=risk,
                    line_no=start + 1,
                    col=1,
                    end_col=len(lines[start]) + 1,
                    matched=joined[:80] + ("..." if len(joined) > 80 else ""),
                    matched_raw=joined,
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        f"Base64 content wrapped across {len(parts)} lines decodes "
                        f"to text flagged by {tripped}: {decoded[:100]!r}"
                    ),
                )
            )
            fid += 1

        for idx, line in enumerate(lines):
            if deadline_exceeded():
                run = []
                break
            if _B64_FULL_LINE.match(line.strip()):
                if not run:
                    run_start = idx
                run.append(line.strip())
            else:
                _flush_run(run_start, run)
                run = []
        _flush_run(run_start, run)

        return findings

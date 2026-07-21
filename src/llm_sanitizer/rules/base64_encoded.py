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
from llm_sanitizer.rules._rescan import scan_deobfuscated

# Minimum length to avoid false positives on short base64-looking tokens
_MIN_B64_LENGTH = 40

_B64_PATTERN = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{' + str(_MIN_B64_LENGTH) + r',}={0,2})(?![A-Za-z0-9+/=])'
)


def _try_decode_base64(s: str) -> str | None:
    """Attempt to decode a base64 string. Return decoded text or None."""
    # Pad if needed
    padded = s + "=" * ((-len(s)) % 4)
    try:
        decoded_bytes = base64.b64decode(padded)
        # Try UTF-8 first, then latin-1
        try:
            text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = decoded_bytes.decode("latin-1")
            except UnicodeDecodeError:
                return None
        # Must be mostly printable
        printable = sum(c.isprintable() for c in text)
        if len(text) > 0 and printable / len(text) > 0.8:
            return text
    except Exception:
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
            for m in _B64_PATTERN.finditer(line):
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

        return findings

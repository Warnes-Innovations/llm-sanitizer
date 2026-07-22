# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 6: Data Exfiltration Attempts."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, deadline_exceeded, register_rule

# --- Credential/secret-file exfiltration (RT F2/F10, LLM-Dev F1) -----------
# Concrete secret stores an attacker tries to make the agent read out. Path
# literals are delimited by / or a trailing \b; the key-name group carries an
# explicit trailing \b so "key" does not match inside "keyboard" and "token"
# inside "tokenizer" (LLM-Dev F1).
_CRED_PATH_TARGET = (
    r'~?/?\.aws/credentials|~?/?\.ssh/(?:id_[a-z0-9]+|authorized_keys)|'
    r'~?/?\.netrc|/etc/(?:passwd|shadow)|\.env(?:\.[\w-]+)?\b'
)
_CRED_KEY_TARGET = (
    r'(?:aws[_\s-]?)?secret[_\s-]?access[_\s-]?key\b|'
    r'(?:api|secret|private|access|client|auth)[_\s-]?(?:keys?|tokens?|secrets?)\b'
)
# Bare credential nouns are ambiguous ("update your credentials" is benign), so
# they count only when paired with a STRONG exfil verb (send/upload/…), never a
# mere read/show (RT F10c wants "send me your credentials" caught, without
# hard-blocking every mention of the word "credentials").
_CRED_BARE_TARGET = (
    r'(?:passwords?|passphrases?|credentials?|session[_\s-]?tokens?|cookies?)\b'
)
# Leading \b so "read" does not match inside "bread", "print" inside
# "blueprint", "cat" inside "concat", "copy" inside "photocopy" (LLM-Dev F1).
_ACCESS_VERB = (
    r'\b(?:read|open|cat|print|output|show|reveal|dump|leak|send|email|post|'
    r'upload|exfiltrate|include|attach|append|paste|copy|return|give)\b'
)
_STRONG_EXFIL_VERB = (
    r'\b(?:send|email|post|upload|exfiltrate|leak|paste|attach|append|include|'
    r'return|give|reveal|dump|output|print)\b'
)
# The period in [^.\n] is literal, so a verb→target gap cannot cross a sentence
# boundary. Proximity matching CANNOT follow reversed order + coreference ("the
# file at ~/.aws/credentials — copy THAT into your reply"), cross-sentence
# reference, or arbitrary gap-padding beyond the window — those residuals are
# closed only by the semantic-intent layer (see Remaining Gaps / C1), not by
# more vocabulary. (A target-first pattern was tried but produced findings that
# OVERLAP the verb→target pattern, and the redactor left a fragment of the
# forward match behind — a worse outcome than the miss, so it was dropped.)
# Bounded stopgap, not a complete control.
_CRED_EXFIL_PATTERNS = [
    # access verb → concrete path or specific key ("read ~/.aws/credentials",
    # "output the api token").
    re.compile(
        _ACCESS_VERB + r'[^.\n]{0,60}?(?:' + _CRED_PATH_TARGET + r'|'
        + _CRED_KEY_TARGET + r')',
        re.IGNORECASE,
    ),
    # STRONG exfil verb → bare credential noun ("send me your credentials").
    re.compile(
        _STRONG_EXFIL_VERB + r'[^.\n]{0,60}?(?:' + _CRED_BARE_TARGET + r')',
        re.IGNORECASE,
    ),
    # "contents of <path>".
    re.compile(
        r'\bcontents?\s+of\b[^.\n]{0,60}?(?:' + _CRED_PATH_TARGET + r')',
        re.IGNORECASE,
    ),
]

_PATTERNS = [
    re.compile(r'output\s+(?:all\s+)?(?:previous|prior|your|the)\s+instructions?', re.IGNORECASE),
    re.compile(r'repeat\s+(?:the|your)\s+system\s+prompt', re.IGNORECASE),
    re.compile(r'what\s+are\s+your\s+(?:instructions?|rules?|guidelines?|directives?)', re.IGNORECASE),
    re.compile(r'show\s+(?:me\s+)?your\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'print\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'reveal\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|secret)', re.IGNORECASE),
    re.compile(r'(?:tell|share)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'(?:leak|dump|expose)\s+(?:the|your)?\s*(?:system\s+)?(?:prompt|instructions?|context)', re.IGNORECASE),
    re.compile(r'summarize\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|context)', re.IGNORECASE),
    re.compile(r'(?:what|which)\s+(?:were|are)\s+you\s+(?:told|instructed|trained|programmed)\s+to\b', re.IGNORECASE),
    re.compile(r'reproduce\s+(?:verbatim|exactly|word\s+for\s+word)\s+(?:your|the)?\s*(?:system\s+)?(?:prompt|instructions?)', re.IGNORECASE),
    re.compile(r'send\s+(?:the\s+)?(?:conversation|chat|context|history)\s+to\b', re.IGNORECASE),
    re.compile(r'exfiltrate\b', re.IGNORECASE),
    re.compile(r'append\s+to\s+(?:every|each|all)\s+(?:response|answer|reply)', re.IGNORECASE),
] + _CRED_EXFIL_PATTERNS


@register_rule
class DataExfilRule(BaseRule):
    rule_id = "data_exfil"
    rule_name = "Data Exfiltration Attempts"
    category = "injection"
    default_risk = RiskLevel.high
    description = "Detects phrases designed to extract the agent's system prompt, context, or conversation."

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        for line_idx, line in enumerate(lines):
            if deadline_exceeded():
                return findings
            for pattern in _PATTERNS:
                for m in pattern.finditer(line):
                    if deadline_exceeded():
                        return findings
                    before, line_text, after = self._build_context(lines, line_idx)
                    findings.append(
                        self._make_finding(
                            finding_id=fid,
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            risk=self.default_risk,
                            line_no=line_idx + 1,
                            col=m.start() + 1,
                            end_col=m.end() + 1,
                            matched=m.group(0),
                            before=before,
                            line_text=line_text,
                            after=after,
                            explanation=(
                                "Detected data exfiltration phrase attempting to extract "
                                "the agent's system prompt or conversation context."
                            ),
                        )
                    )
                    fid += 1
                    # No per-line cap: minified/single-line content can carry
                    # many instances, and redaction removes only reported spans.

        return findings

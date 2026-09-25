# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 10: Agent-Specific Configuration Patterns."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import (
    BaseRule,
    deadline_exceeded,
    is_legitimate_file,
    line_number_at,
    newline_offsets,
    register_rule,
)

# Leading indentation, horizontal whitespace ONLY — never `\s*`.
#
# `\s*` here is a denial-of-service amplifier, not a style choice. Under
# MULTILINE the `^` (or an explicit `(?:^|\n)`) offers O(n) start positions;
# a greedy `\s*` at that position swallows every remaining whitespace
# character and then backtracks one at a time through the literal
# alternation that follows. On whitespace-only input that is O(n) work at
# each of O(n) starts — quadratic. 8 KB of blank CRLF lines took 7.7 s
# through `Scanner.scan`, and the blowup happens inside a single C-level
# `re.search` that never returns to Python, so `deadline_exceeded()` is
# never consulted and `max_scan_seconds` CANNOT interrupt it. A 1-second
# budget measured 6.4 s.
#
# `[^\S\n]` is "whitespace except newline". It costs nothing in coverage:
# under MULTILINE `^` already matches at the key's OWN line start, so any
# key a newline-crossing `\s*` could reach is still reached — and reached
# with the correct line number, which the old pattern got wrong whenever it
# started the match on an earlier blank line.
#
# Do NOT "simplify" this back to `\s*`.
_HSPACE = r'[^\S\n]*'

# Agent-SPECIFIC keys: strong signal on their own — they name an LLM/agent
# directly and rarely appear in ordinary config.
_AGENT_SPECIFIC_PATTERN = re.compile(
    r'^' + _HSPACE + r'["\']?(?:instructions?|system_prompt|agent_mode|ai_behavior|'
    r'agent_instructions?|ai_context|llm_config)["\']?\s*[:=]',
    re.IGNORECASE | re.MULTILINE,
)
# GENERIC LLM-adjacent keys that ALSO appear in ordinary ML/DevOps YAML
# (training configs, dataset descriptors). On their own these flooded MEDIUM
# false positives, so they are only flagged when an agent-SPECIFIC key also
# occurs in the same content (corroboration).
_GENERIC_KEY_PATTERN = re.compile(
    r'^' + _HSPACE + r'["\']?(?:model|temperature|tools|context_window|max_tokens|top_p|'
    r'stop_sequences?)["\']?\s*[:=]',
    re.IGNORECASE | re.MULTILINE,
)

# YAML frontmatter with agent keys (between --- delimiters)
_FRONTMATTER_PATTERN = re.compile(
    r'^---\s*\n(.*?)\n---',
    re.DOTALL | re.MULTILINE,
)

_AGENT_CONFIG_KEYS_IN_FRONTMATTER = re.compile(
    r'(?:^|\n)' + _HSPACE + r'["\']?(?:instructions?|system_prompt|agent_mode|ai_behavior|'
    r'tools|model|temperature)["\']?\s*:',
    re.IGNORECASE,
)


@register_rule
class AgentConfigRule(BaseRule):
    rule_id = "agent_config"
    rule_name = "Agent-Specific Configuration Patterns"
    category = "structural"
    default_risk = RiskLevel.medium
    description = (
        "Detects YAML/JSON/TOML structures with keys targeting AI agents, "
        "especially in unexpected file locations."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        # Consult the clock BEFORE the setup below, not only inside the match
        # loops. `splitlines`, `newline_offsets` and every `finditer` here scale
        # with the input, so a rule whose first deadline check is inside its
        # loop has already done all of that uninterruptibly — and that window is
        # exactly what a large or hostile input widens. Measured at ~367 ms on a
        # 5.28 MB single line before this returned anything (issue #56).
        if deadline_exceeded():
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        offsets = newline_offsets(content)
        fid = 1

        legitimate = is_legitimate_file(source)

        # Check for YAML frontmatter with agent keys
        for fm_match in _FRONTMATTER_PATTERN.finditer(content):
            # This loop had no deadline check at all, while the key loop below
            # did. Both iterate once per match over untrusted input.
            if deadline_exceeded():
                break
            fm_content = fm_match.group(1)
            if _AGENT_CONFIG_KEYS_IN_FRONTMATTER.search(fm_content):
                line_no = line_number_at(offsets, fm_match.start())
                risk = RiskLevel.info if legitimate else RiskLevel.medium
                before, line_text, after = self._build_context(lines, line_no)
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=risk,
                        line_no=line_no + 1,
                        col=1,
                        end_col=len(line_text) + 1,
                        matched=fm_match.group(0)[:200],
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            "Detected YAML frontmatter with AI agent configuration keys "
                            f"({'legitimate file' if legitimate else 'unexpected location'})."
                        ),
                    )
                )
                fid += 1

        # Check for individual agent configuration keys outside frontmatter.
        # Generic ML keys (model/temperature/…) only count when an agent-specific
        # key co-occurs, so ordinary training/dataset YAML is not flagged.
        if not legitimate:
            has_specific = _AGENT_SPECIFIC_PATTERN.search(content) is not None
            patterns = [_AGENT_SPECIFIC_PATTERN]
            if has_specific:
                patterns.append(_GENERIC_KEY_PATTERN)
            matches = sorted(
                (m for p in patterns for m in p.finditer(content)),
                key=lambda m: m.start(),
            )
            for m in matches:
                if deadline_exceeded():
                    break
                line_no = line_number_at(offsets, m.start())
                col = m.start() - (content.rfind("\n", 0, m.start()) + 1) + 1
                before, line_text, after = self._build_context(lines, line_no)
                findings.append(
                    self._make_finding(
                        finding_id=fid,
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        risk=RiskLevel.medium,
                        line_no=line_no + 1,
                        col=col,
                        end_col=col + len(m.group(0).rstrip()),
                        matched=m.group(0).strip()[:200],
                        before=before,
                        line_text=line_text,
                        after=after,
                        explanation=(
                            "Detected AI agent configuration key in an unexpected location. "
                            "This may indicate embedded agent instructions."
                        ),
                    )
                )
                fid += 1

        return findings

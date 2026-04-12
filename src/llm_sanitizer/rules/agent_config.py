# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 10: Agent-Specific Configuration Patterns."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, is_legitimate_file, register_rule

# YAML/JSON keys targeting AI agents
_AGENT_KEY_PATTERN = re.compile(
    r'^\s*["\']?(?:instructions?|system_prompt|agent_mode|ai_behavior|'
    r'model|temperature|tools|context_window|max_tokens|top_p|'
    r'stop_sequences?|agent_instructions?|ai_context|llm_config)["\']?\s*[:=]',
    re.IGNORECASE | re.MULTILINE,
)

# YAML frontmatter with agent keys (between --- delimiters)
_FRONTMATTER_PATTERN = re.compile(
    r'^---\s*\n(.*?)\n---',
    re.DOTALL | re.MULTILINE,
)

# Agent-specific config file patterns in unexpected locations
_AGENT_CONFIG_FILENAME_PATTERN = re.compile(
    r'(?:\.cursorrules|\.clinerules|\.windsurfrules|codex\.md|'
    r'AGENTS\.md|CLAUDE\.md|\.copilot-codegeneration-instructions\.md)',
    re.IGNORECASE,
)

_AGENT_CONFIG_KEYS_IN_FRONTMATTER = re.compile(
    r'(?:^|\n)\s*["\']?(?:instructions?|system_prompt|agent_mode|ai_behavior|'
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
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        legitimate = is_legitimate_file(source)

        # Check for YAML frontmatter with agent keys
        for fm_match in _FRONTMATTER_PATTERN.finditer(content):
            fm_content = fm_match.group(1)
            if _AGENT_CONFIG_KEYS_IN_FRONTMATTER.search(fm_content):
                line_no = content[: fm_match.start()].count("\n")
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

        # Check for individual agent configuration keys outside frontmatter
        if not legitimate:
            for m in _AGENT_KEY_PATTERN.finditer(content):
                line_no = content[: m.start()].count("\n")
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

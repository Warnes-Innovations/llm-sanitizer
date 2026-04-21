# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Detection rule registry and base class."""

from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod
from typing import ClassVar

from llm_sanitizer.models import Finding, RiskLevel

# ---------------------------------------------------------------------------
# Legitimate AI instruction file patterns
# ---------------------------------------------------------------------------

LEGITIMATE_FILE_PATTERNS: list[str] = [
    ".github/copilot-instructions.md",
    ".github/instructions/*.md",
    ".github/prompts/*.md",
    ".github/agents/*.md",
    "AGENTS.md",
    "**/AGENTS.md",
    ".cursorrules",
    ".cursor/rules/*.md",
    ".clinerules",
    ".claude/*",
    "CLAUDE.md",
    "**/CLAUDE.md",
    ".windsurfrules",
    "codex.md",
    "**/codex.md",
    ".copilot-codegeneration-instructions.md",
    "**/SKILL.md",
]


def is_legitimate_file(path: str) -> bool:
    """Return True if the given path matches a known legitimate AI instruction file."""
    # Normalise path separators
    normalised = path.replace("\\", "/").lstrip("./")
    for pattern in LEGITIMATE_FILE_PATTERNS:
        pat = pattern.lstrip("./")
        if fnmatch.fnmatch(normalised, pat):
            return True
        # Also try matching the basename for simple filenames
        basename = normalised.rsplit("/", 1)[-1]
        if "/" not in pat and fnmatch.fnmatch(basename, pat):
            return True
    return False


# ---------------------------------------------------------------------------
# Base rule
# ---------------------------------------------------------------------------


class BaseRule(ABC):
    """Abstract base class for all detection rules."""

    rule_id: ClassVar[str]
    rule_name: ClassVar[str]
    category: ClassVar[str]
    default_risk: ClassVar[RiskLevel]
    description: ClassVar[str] = ""

    @abstractmethod
    def detect(self, content: str, source: str = "") -> list[Finding]:
        """Run detection on *content* and return a list of Finding objects.

        Args:
            content: The text content to scan.
            source: Optional source path/URL for context.
        """

    # ------------------------------------------------------------------
    # Helpers shared by most rules
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(lines: list[str], line_idx: int, context_lines: int = 2) -> tuple[list[str], str, list[str]]:
        """Return (before_lines, matched_line, after_lines) for a line index."""
        before = lines[max(0, line_idx - context_lines): line_idx]
        matched_line = lines[line_idx] if line_idx < len(lines) else ""
        after = lines[line_idx + 1: line_idx + 1 + context_lines]
        return before, matched_line, after

    @staticmethod
    def _make_finding(
        *,
        finding_id: int,
        rule_id: str,
        rule_name: str,
        risk: RiskLevel,
        line_no: int,
        col: int,
        end_col: int,
        matched: str,
        matched_raw: str = "",
        before: list[str],
        line_text: str,
        after: list[str],
        explanation: str,
    ) -> Finding:
        from llm_sanitizer.models import FindingContext, Location

        return Finding(
            id=finding_id,
            rule=rule_id,
            rule_name=rule_name,
            risk=risk,
            location=Location(
                line=line_no,
                column=col,
                end_line=line_no,
                end_column=end_col,
            ),
            matched=matched,
            matched_raw=matched_raw,
            context=FindingContext(before=before, line=line_text, after=after),
            explanation=explanation,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_RULE_REGISTRY: dict[str, type[BaseRule]] = {}


def register_rule(cls: type[BaseRule]) -> type[BaseRule]:
    """Class decorator that registers a rule in the global registry."""
    _RULE_REGISTRY[cls.rule_id] = cls
    return cls


def get_all_rules() -> list[type[BaseRule]]:
    """Return all registered rule classes in a stable order."""
    # Import all rule modules to trigger registration
    from llm_sanitizer.rules import (  # noqa: F401
        agent_config,
        base64_encoded,
        comment_directive,
        data_exfil,
        hidden_content,
        homoglyph,
        instruction_override,
        role_play,
        system_prompt,
        zero_width,
    )
    return list(_RULE_REGISTRY.values())


def get_rule_by_id(rule_id: str) -> type[BaseRule] | None:
    """Return the rule class for a given rule ID, or None."""
    get_all_rules()  # ensure all modules are imported
    return _RULE_REGISTRY.get(rule_id)


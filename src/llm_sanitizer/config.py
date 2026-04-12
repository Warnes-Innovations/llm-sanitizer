# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Configuration loading and management (.llm-sanitizer.yml)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


_DEFAULT_RULES = [
    "instruction_override",
    "zero_width",
    "hidden_content",
    "role_play",
    "system_prompt",
    "data_exfil",
    "comment_directive",
    "base64_encoded",
    "homoglyph",
    "agent_config",
]


@dataclass
class RuleSettings:
    enabled: bool = True
    sensitivity: str | None = None  # Override global sensitivity if set


@dataclass
class PolicySettings:
    mode: str = "allow-known"  # "allow-known" | "allow-none" | "allow-all"
    agents: dict[str, str] = field(default_factory=lambda: {
        "copilot": "allow",
        "cursor": "allow",
        "claude": "allow",
        "cline": "allow",
    })
    custom_allow: list[str] = field(default_factory=list)
    custom_deny: list[str] = field(default_factory=list)


@dataclass
class OutputSettings:
    format: str = "markdown"  # "json" | "markdown" | "sarif"
    context_lines: int = 2


@dataclass
class SanitizerConfig:
    sensitivity: str = "medium"
    rules: dict[str, RuleSettings] = field(default_factory=dict)
    policy: PolicySettings = field(default_factory=PolicySettings)
    output: OutputSettings = field(default_factory=OutputSettings)

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Return True if the rule is enabled (default: True for all rules)."""
        return self.rules.get(rule_id, RuleSettings()).enabled

    def rule_sensitivity(self, rule_id: str) -> str:
        """Return the effective sensitivity for a rule."""
        rule_cfg = self.rules.get(rule_id, RuleSettings())
        return rule_cfg.sensitivity or self.sensitivity


def _parse_rules(raw: dict[str, Any]) -> dict[str, RuleSettings]:
    result: dict[str, RuleSettings] = {}
    for rule_id, cfg in raw.items():
        if isinstance(cfg, dict):
            result[rule_id] = RuleSettings(
                enabled=cfg.get("enabled", True),
                sensitivity=cfg.get("sensitivity"),
            )
        elif isinstance(cfg, bool):
            result[rule_id] = RuleSettings(enabled=cfg)
    return result


def load_config(path: str | Path | None = None) -> SanitizerConfig:
    """Load configuration from a .llm-sanitizer.yml file.

    If *path* is None, search the current directory and its parents for
    `.llm-sanitizer.yml`. Returns default config if no file is found.
    """
    cfg_path: Path | None = None

    if path is not None:
        cfg_path = Path(path)
    else:
        # Walk up from cwd looking for config file
        search = Path(os.getcwd())
        for candidate in [search, *search.parents]:
            p = candidate / ".llm-sanitizer.yml"
            if p.exists():
                cfg_path = p
                break

    if cfg_path is None or not cfg_path.exists():
        return SanitizerConfig()

    if not _YAML_AVAILABLE:
        # PyYAML not installed — return defaults silently
        return SanitizerConfig()

    with open(cfg_path) as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    sensitivity = raw.get("sensitivity", "medium")
    rules = _parse_rules(raw.get("rules", {}))

    policy_raw = raw.get("policy", {})
    policy = PolicySettings(
        mode=policy_raw.get("mode", "allow-known"),
        agents=policy_raw.get("agents", {
            "copilot": "allow", "cursor": "allow", "claude": "allow", "cline": "allow",
        }),
        custom_allow=policy_raw.get("custom_allow", []),
        custom_deny=policy_raw.get("custom_deny", []),
    )

    output_raw = raw.get("output", {})
    output = OutputSettings(
        format=output_raw.get("format", "markdown"),
        context_lines=output_raw.get("context_lines", 2),
    )

    return SanitizerConfig(
        sensitivity=sensitivity,
        rules=rules,
        policy=policy,
        output=output,
    )


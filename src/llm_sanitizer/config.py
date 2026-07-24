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


# Archive-handling limits. Defaults mirror the module-level constants in
# llm_sanitizer.scanner, which remain the ultimate fallback (used when a
# Scanner is built without a config, and by _is_archive_bomb's default args).
# Keeping the numbers here in sync with those constants means configuration is
# purely additive: nothing configured → identical behavior to before.
_DEFAULT_ARCHIVE_FORMATS = ["zip", "tar", "gz", "bz2", "xz", "7z", "rar"]


@dataclass
class ArchiveSettings:
    """Limits and enabled-format list for recursive archive extraction."""

    max_depth: int = 3  # max archive-in-archive nesting levels
    max_cumulative_bytes: int = 500 * 1024 * 1024  # across all nested levels
    max_entries: int = 1000  # per-archive entry-count cap
    max_uncompressed_bytes: int = 100 * 1024 * 1024  # per-archive size cap
    max_compression_ratio: int = 100  # zip-bomb ratio guard
    min_ratio_check_bytes: int = 10 * 1024 * 1024  # floor before ratio applies
    formats: list[str] = field(
        default_factory=lambda: list(_DEFAULT_ARCHIVE_FORMATS)
    )


# Governs a NON-archive binary that, under binary_mode="extract", is
# successfully processed but yields NO extractable text (markitdown returns ""
# or only whitespace). Does NOT govern extractor-unavailable (that fails fast)
# or extraction-error/corrupt (that is always CRITICAL).
_UNPROCESSABLE_BINARY_POLICIES = ("ignore", "scan-text", "fail")
_DEFAULT_UNPROCESSABLE_BINARY_POLICY = "fail"

# Maximum bytes of text content the scanner will process for a single unit (a
# file, an extracted archive member, or inline text). Larger input is not
# scanned; a CRITICAL input_too_large integrity finding is emitted instead
# (fail-closed) so an oversized/adversarial input cannot pin CPU. Configurable
# via the `max_scan_bytes` key.
_DEFAULT_MAX_SCAN_BYTES = 25 * 1024 * 1024

# Wall-clock deadline for scanning a single content unit. If exceeded, the
# scanner stops running further rules and emits a HIGH scan_timeout finding
# rather than pinning a thread indefinitely on a pathological input (committee
# M4). Generous by default so it only trips on genuinely adversarial content;
# configurable via the `max_scan_seconds` key (0 or negative disables it).
_DEFAULT_MAX_SCAN_SECONDS = 60.0


@dataclass
class SanitizerConfig:
    sensitivity: str = "medium"
    rules: dict[str, RuleSettings] = field(default_factory=dict)
    policy: PolicySettings = field(default_factory=PolicySettings)
    output: OutputSettings = field(default_factory=OutputSettings)
    archive: ArchiveSettings = field(default_factory=ArchiveSettings)
    # "fail" (default, fail-closed) | "scan-text" | "ignore" — see the constant
    # comment above. Governs only the "processed but empty" outcome.
    unprocessable_binary_policy: str = _DEFAULT_UNPROCESSABLE_BINARY_POLICY
    max_scan_bytes: int = _DEFAULT_MAX_SCAN_BYTES
    max_scan_seconds: float = _DEFAULT_MAX_SCAN_SECONDS

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

    archive = _parse_archive(raw.get("archive", {}))

    policy_value = raw.get(
        "unprocessable_binary_policy", _DEFAULT_UNPROCESSABLE_BINARY_POLICY
    )
    if policy_value not in _UNPROCESSABLE_BINARY_POLICIES:
        # Unknown value → fail closed rather than trust a typo'd opt-out.
        policy_value = _DEFAULT_UNPROCESSABLE_BINARY_POLICY

    max_scan_bytes = raw.get("max_scan_bytes", _DEFAULT_MAX_SCAN_BYTES)
    if not isinstance(max_scan_bytes, int) or max_scan_bytes <= 0:
        max_scan_bytes = _DEFAULT_MAX_SCAN_BYTES

    max_scan_seconds = raw.get("max_scan_seconds", _DEFAULT_MAX_SCAN_SECONDS)
    if not isinstance(max_scan_seconds, (int, float)) or isinstance(
        max_scan_seconds, bool
    ):
        max_scan_seconds = _DEFAULT_MAX_SCAN_SECONDS

    return SanitizerConfig(
        sensitivity=sensitivity,
        rules=rules,
        policy=policy,
        output=output,
        archive=archive,
        unprocessable_binary_policy=policy_value,
        max_scan_bytes=max_scan_bytes,
        max_scan_seconds=float(max_scan_seconds),
    )


def _parse_archive(raw: dict[str, Any]) -> ArchiveSettings:
    """Build ArchiveSettings from a config mapping, falling back to the dataclass
    defaults (which mirror the scanner's module-level constants) for any key the
    config omits."""
    defaults = ArchiveSettings()
    formats = raw.get("formats", defaults.formats)
    if not isinstance(formats, list):
        formats = defaults.formats
    return ArchiveSettings(
        max_depth=raw.get("max_depth", defaults.max_depth),
        max_cumulative_bytes=raw.get(
            "max_cumulative_bytes", defaults.max_cumulative_bytes
        ),
        max_entries=raw.get("max_entries", defaults.max_entries),
        max_uncompressed_bytes=raw.get(
            "max_uncompressed_bytes", defaults.max_uncompressed_bytes
        ),
        max_compression_ratio=raw.get(
            "max_compression_ratio", defaults.max_compression_ratio
        ),
        min_ratio_check_bytes=raw.get(
            "min_ratio_check_bytes", defaults.min_ratio_check_bytes
        ),
        formats=[str(f) for f in formats],
    )


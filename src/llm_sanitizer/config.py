# Copyright (C) 2026 Gregory R. Warnes
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
except ImportError:  # pragma: no cover - pyyaml is a declared dependency
    _YAML_AVAILABLE = False


class ConfigError(RuntimeError):
    """A config file exists and could not be honoured.

    Deliberately NOT recoverable-by-default. Every caller that wants to keep going
    without a config can simply not have one; the case this guards is "there is a
    config, and we cannot apply it", where continuing means reporting one policy while
    enforcing another.
    """


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


#: Valid sensitivity levels; mirrors scanner._SENSITIVITY_RISK_MAP (checked by
#: tests/test_review_round6.py::test_config_sensitivities_match_scanner).
_SENSITIVITIES = ("low", "medium", "high")


def _parse_rules(raw: dict[str, Any]) -> dict[str, RuleSettings]:
    result: dict[str, RuleSettings] = {}
    for rule_id, cfg in raw.items():
        if isinstance(cfg, dict):
            enabled = cfg.get("enabled", True)
            if not isinstance(enabled, bool):
                raise ConfigError(f"rules.{rule_id}.enabled must be true or false, not {enabled!r}")
            result[rule_id] = RuleSettings(enabled=enabled, sensitivity=cfg.get("sensitivity"))
        elif isinstance(cfg, bool):
            result[rule_id] = RuleSettings(enabled=cfg)
        else:
            # Silently skipping `zero_width: 5` left the rule at its default
            # while the operator believed it configured (review pass 6).
            raise ConfigError(
                f"rules.{rule_id} must be true, false or a mapping, not {cfg!r}"
            )
    return result


def load_config(path: str | Path | None = None) -> SanitizerConfig:
    """Load configuration from a .llm-sanitizer.yml file.

    If *path* is None, search the current directory and its parents for
    `.llm-sanitizer.yml`. Returns default config if no file is found.
    """
    cfg_path: Path | None = None

    if path is not None:
        cfg_path = Path(path)
        if not os.path.lexists(cfg_path):
            # A NAMED config that is missing is an error, never "use defaults":
            # the caller asked for a policy and would silently get another.
            raise ConfigError(f"{cfg_path} does not exist; refusing to fall back to defaults.")
    else:
        # Walk up from cwd looking for config file. `lexists`, not `exists`: a
        # DANGLING symlink named .llm-sanitizer.yml is not "no config here" —
        # skipping it silently used a parent's (or the default) policy instead
        # (0.7.2 review, pass 3). It is found here and refused below.
        search = Path(os.getcwd())
        for candidate in [search, *search.parents]:
            p = candidate / ".llm-sanitizer.yml"
            if os.path.lexists(p):
                cfg_path = p
                break

    if cfg_path is None:
        return SanitizerConfig()

    if not _YAML_AVAILABLE:
        # WAS: "PyYAML not installed — return defaults silently". It is now a hard error,
        # and `pyyaml` is a declared dependency so this branch should be unreachable.
        #
        # THE FAIL-OPEN. We have just established that a config file EXISTS. Returning
        # defaults there tells the caller the policy is in force while running a
        # different policy — and `list_rules` documents itself as reporting "what
        # actually runs", so the tool would confidently report rules the operator
        # disabled as active, and vice versa.
        #
        # Verified 2026-07-31 against v0.5.1: `pyyaml` was NOT declared, and in the
        # environment consumers actually use — `uvx --from git+...@v0.5.1`, which is what
        # bastion's INV-7 wiring creates — `import yaml` failed. So every
        # `.llm-sanitizer.yml` in that deployment was inert, silently.
        #
        # It is also LATENT, which is the worse half: pyyaml arriving transitively would
        # make every checked-in `enabled: false` become live AT ONCE, with no event
        # marking the change. Failing closed here means that transition can only ever go
        # from "loud error" to "working", never from "silently ignored" to "suddenly
        # enforcing something different".
        raise ConfigError(
            f"{cfg_path} exists but PyYAML is not installed, so it cannot be read. "
            "Refusing to continue with default rules: that would report a policy as "
            "in force while running a different one. Install PyYAML "
            "(`pip install pyyaml`), or remove the config file to accept the defaults "
            "deliberately."
        )

    # A FIFO named .llm-sanitizer.yml blocked every command forever (0.7.2):
    # refuse anything that is not a regular file, like any other bad config.
    if not Path(cfg_path).is_file():
        raise ConfigError(
            f"{cfg_path} is not a regular file (FIFO, socket, device or directory); "
            "refusing to read it as configuration."
        )
    # Every way the file can fail to be a config — unreadable, not UTF-8, not
    # YAML, not a mapping — is a ConfigError, so the CLI reports it (exit 2)
    # rather than crashing with a traceback (0.7.2 review, pass 4). Still
    # fail-closed: nothing here falls back to defaults.
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{cfg_path} could not be read as YAML: {exc}") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ConfigError(
            f"{cfg_path} must be a YAML mapping of settings, not a {type(loaded).__name__}"
        )
    raw: dict[str, Any] = loaded

    # Each section must have the shape the code below indexes into, or the
    # loader crashes with a traceback (`rules: 5`) instead of refusing the
    # config (0.7.2 review, pass 5).
    for section in ("rules", "policy", "output", "archive"):
        value = raw.get(section, {})
        if not isinstance(value, dict):
            raise ConfigError(
                f"{cfg_path}: `{section}` must be a mapping, not a {type(value).__name__}"
            )
    # A key this version does not read is an error, not ignored: a misspelt
    # or invented setting (`policy: {fail_on: ...}`) left the operator
    # believing a control was configured (review pass 7).
    for where, value, known in (
        ("", raw, _KNOWN_TOP_LEVEL),
        ("policy.", raw.get("policy", {}), _KNOWN_POLICY),
        ("output.", raw.get("output", {}), _KNOWN_OUTPUT),
        ("archive.", raw.get("archive", {}), _KNOWN_ARCHIVE),
    ):
        unknown = sorted(str(k) for k in value if k not in known)
        if unknown:
            raise ConfigError(
                f"{cfg_path}: unknown setting(s) {', '.join(where + k for k in unknown)}; "
                f"known: {', '.join(sorted(known))}"
            )
    sensitivity = raw.get("sensitivity", "medium")
    if sensitivity not in _SENSITIVITIES:
        # An unknown level is not "medium": the operator asked for something
        # this version does not provide.
        raise ConfigError(
            f"{cfg_path}: sensitivity {sensitivity!r} is not one of "
            f"{', '.join(_SENSITIVITIES)}"
        )
    rules = _parse_rules(raw.get("rules", {}))
    for rule_id, rule_cfg in rules.items():
        if rule_cfg.sensitivity is not None and rule_cfg.sensitivity not in _SENSITIVITIES:
            raise ConfigError(
                f"{cfg_path}: rules.{rule_id}.sensitivity {rule_cfg.sensitivity!r} "
                f"is not one of {', '.join(_SENSITIVITIES)}"
            )

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

    # A limit that is not a number is an error, not the default: the operator
    # asked for a limit this file does not express (review pass 6).
    max_scan_bytes = raw.get("max_scan_bytes", _DEFAULT_MAX_SCAN_BYTES)
    if isinstance(max_scan_bytes, bool) or not isinstance(max_scan_bytes, int) or max_scan_bytes <= 0:
        raise ConfigError(
            f"{cfg_path}: max_scan_bytes must be a positive integer, not {max_scan_bytes!r}"
        )

    max_scan_seconds = raw.get("max_scan_seconds", _DEFAULT_MAX_SCAN_SECONDS)
    if not isinstance(max_scan_seconds, (int, float)) or isinstance(
        max_scan_seconds, bool
    ):
        raise ConfigError(
            f"{cfg_path}: max_scan_seconds must be a number, not {max_scan_seconds!r}"
        )

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


#: Every key this version reads, per section. `llm` is reserved: the design
#: spec's example config carries it, and rejecting it would break a config
#: copied from there.
_KNOWN_TOP_LEVEL = frozenset({
    "sensitivity", "rules", "policy", "output", "archive",
    "unprocessable_binary_policy", "max_scan_bytes", "max_scan_seconds", "llm",
})
_KNOWN_POLICY = frozenset({"mode", "agents", "custom_allow", "custom_deny"})
_KNOWN_OUTPUT = frozenset({"format", "context_lines"})
_KNOWN_ARCHIVE = frozenset({
    "formats", "max_depth", "max_cumulative_bytes", "max_entries",
    "max_uncompressed_bytes", "max_compression_ratio", "min_ratio_check_bytes",
})
_ARCHIVE_INTS = _KNOWN_ARCHIVE - {"formats"}


def _parse_archive(raw: dict[str, Any]) -> ArchiveSettings:
    """Build ArchiveSettings from a config mapping, falling back to the dataclass
    defaults (which mirror the scanner's module-level constants) for any key the
    config omits."""
    defaults = ArchiveSettings()
    for key in _ARCHIVE_INTS & raw.keys():
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ConfigError(f"archive.{key} must be a non-negative number, not {value!r}")
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


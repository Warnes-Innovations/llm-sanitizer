# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Core scanner engine — rule registry, content parsing, finding accumulation."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from llm_sanitizer.config import SanitizerConfig, load_config
from llm_sanitizer.models import (
    DirScanResult,
    Finding,
    RiskLevel,
    ScanResult,
    SummaryStats,
)
from llm_sanitizer.rules import BaseRule, get_all_rules, is_legitimate_file

# Map sensitivity strings to minimum risk level to include in results
_SENSITIVITY_RISK_MAP: dict[str, RiskLevel] = {
    "low": RiskLevel.high,      # low sensitivity → only critical/high
    "medium": RiskLevel.medium, # medium → medium and above
    "high": RiskLevel.info,     # high → all including info/low
}

# Directories excluded from directory scans — VCS metadata and dependency
# caches are not source content. ".git" in particular can hold gigabytes of
# binary packed objects; scanning them means read_text(errors="replace")
# force-decodes arbitrary binary data as UTF-8, and statistically some byte
# sequences will decode to valid-looking high-codepoint Unicode — triggering
# character-pattern rules (homoglyph, zero_width) with no security meaning.
_EXCLUDED_DIR_NAMES = frozenset([
    ".git", ".svn", ".hg", "__pycache__", "node_modules", ".venv", "venv",
])


def iter_scannable_files(root: Path, glob_pattern: str = "**/*") -> list[Path]:
    """Recursively collect files under root for directory scan/redact
    operations, pruning excluded directories (see _EXCLUDED_DIR_NAMES) during
    the walk itself — not just filtering afterward, since .git can be large
    enough that even walking into it before discarding results is wasteful."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIR_NAMES]
        for name in filenames:
            files.append(Path(dirpath) / name)

    if glob_pattern != "**/*":
        files = [p for p in files if fnmatch.fnmatch(p.name, glob_pattern.lstrip("**/"))]
    return files


def _build_summary(findings: list[Finding]) -> SummaryStats:
    by_risk: dict[str, int] = {level.name: 0 for level in RiskLevel}
    rules_triggered: set[str] = set()
    max_risk: RiskLevel | None = None

    for f in findings:
        by_risk[f.risk.name] += 1
        rules_triggered.add(f.rule)
        if max_risk is None or f.risk > max_risk:
            max_risk = f.risk

    return SummaryStats(
        total_findings=len(findings),
        by_risk=by_risk,
        max_risk=max_risk,
        rules_triggered=sorted(rules_triggered),
    )


class Scanner:
    """Orchestrates detection rules and accumulates findings."""

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        self._config = config or load_config()
        self._rules: list[BaseRule] = [
            cls() for cls in get_all_rules()
            if self._config.is_rule_enabled(cls.rule_id)
        ]

    @property
    def rules(self) -> list[BaseRule]:
        return self._rules

    def scan(
        self,
        content: str,
        source: str = "<inline>",
        sensitivity: str = "medium",
    ) -> ScanResult:
        """Scan *content* and return a ScanResult.

        Args:
            content: Text to scan.
            source: Source path/URL for context and legitimate-file classification.
            sensitivity: "low" | "medium" | "high"
        """
        min_risk = _SENSITIVITY_RISK_MAP.get(sensitivity, RiskLevel.medium)
        findings: list[Finding] = []

        # Check if this is a legitimate file and add an info-level finding if so
        if is_legitimate_file(source):
            from llm_sanitizer.models import FindingContext, Location
            findings.append(
                Finding(
                    id=0,
                    rule="agent_config",
                    rule_name="Legitimate AI Instruction File",
                    risk=RiskLevel.info,
                    location=Location(line=0, column=0, end_line=0, end_column=0),
                    matched=source,
                    context=FindingContext(),
                    explanation=(
                        f"This file ({source}) is a known legitimate AI instruction file. "
                        "Its purpose is to provide AI agent instructions."
                    ),
                )
            )

        # Run all enabled rules
        finding_id = len(findings) + 1
        for rule in self._rules:
            rule_findings = rule.detect(content, source)
            for f in rule_findings:
                # Re-number finding IDs sequentially across all rules
                findings.append(f.model_copy(update={"id": finding_id}))
                finding_id += 1

        # Filter by sensitivity threshold
        filtered = [f for f in findings if f.risk >= min_risk]

        # Re-number after filtering
        for i, f in enumerate(filtered, start=1):
            filtered[i - 1] = f.model_copy(update={"id": i})

        return ScanResult(
            source=source,
            sensitivity=sensitivity,
            summary=_build_summary(filtered),
            findings=filtered,
        )

    def scan_dir(
        self,
        path: str,
        glob_pattern: str = "**/*",
        sensitivity: str = "medium",
    ) -> DirScanResult:
        """Recursively scan a directory and return aggregated results."""
        root = Path(path)
        results: list[ScanResult] = []

        files = iter_scannable_files(root, glob_pattern)

        for file_path in sorted(files):
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                result = self.scan(content, source=str(file_path), sensitivity=sensitivity)
                results.append(result)
            except OSError:
                continue

        all_findings = [f for r in results for f in r.findings]
        max_risk: RiskLevel | None = None
        for f in all_findings:
            if max_risk is None or f.risk > max_risk:
                max_risk = f.risk

        return DirScanResult(
            source=path,
            sensitivity=sensitivity,
            files_scanned=len(results),
            total_findings=len(all_findings),
            max_risk=max_risk,
            results=results,
        )


def scan_text(
    content: str,
    source: str = "<inline>",
    sensitivity: str = "medium",
    config: SanitizerConfig | None = None,
) -> ScanResult:
    """Convenience function: scan text content and return ScanResult."""
    return Scanner(config).scan(content, source=source, sensitivity=sensitivity)


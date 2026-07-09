# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Core scanner engine — rule registry, content parsing, finding accumulation."""

from __future__ import annotations

import fnmatch
import os
import zipfile
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


# Bytes sniffed from the head of each file to classify it as binary. Matches
# the heuristic git and most other tools use (presence of a NUL byte), rather
# than an extension allowlist/denylist — classifying by content instead of
# name means renaming a file can't change how it's handled, closing off an
# evasion in both directions: a malicious text file renamed to a benign-
# looking extension (e.g. .png) to dodge scanning, or a document renamed
# *away* from its real extension to dodge markitdown text extraction.
_BINARY_SNIFF_BYTES = 8000


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return False


# markitdown's ZipConverter extracts every entry of a .zip (recursively, for
# nested archives) with no size, entry-count, or compression-ratio limit of
# its own. Since binary_mode="extract" is our default and this pipeline
# routinely scans untrusted, attacker-supplied content, a small crafted zip
# (classic zip-bomb: one entry with an extreme compression ratio, or many
# entries) would be read fully into memory the moment it's scanned. These
# are the same three heuristics general-purpose zip-bomb detectors use;
# checking them from the archive's central directory (infolist()) is cheap
# and doesn't require decompressing anything.
_ARCHIVE_MAX_ENTRIES = 1000
_ARCHIVE_MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB
_ARCHIVE_MAX_COMPRESSION_RATIO = 100
# Highly-compressible legitimate content (e.g. the repetitive XML inside a
# small DOCX/PPTX) can trivially exceed the ratio threshold above while
# expanding to a few KB — harmless. Only apply the ratio check once an
# entry's *uncompressed* size is itself large enough to matter; small
# entries can't produce a memory bomb regardless of ratio, and genuinely
# oversized entries are still caught by this floor combined with the ratio.
_ARCHIVE_MIN_RATIO_CHECK_BYTES = 10 * 1024 * 1024  # 10 MB
# Nested zip bombs (zip-of-zips) defense: limit recursion depth and
# cumulative uncompressed size across all nested levels.
_ARCHIVE_MAX_NESTING_DEPTH = 3
_ARCHIVE_MAX_CUMULATIVE_BYTES = 500 * 1024 * 1024  # 500 MB across all layers


def _looks_like_zip(name: str, data: bytes | None = None) -> bool:
    """Heuristic: does this entry look like it might be a zip file?"""
    if name.lower().endswith(".zip"):
        return True
    if data and len(data) >= 4 and data[:2] == b"PK":
        return True
    return False


def _is_archive_bomb(path: Path, depth: int = 0, cumulative_size: int = 0) -> bool:
    """Cheaply inspect a zip's central directory (no decompression) for the
    hallmarks of a zip bomb, including nested (zip-of-zips) variants.
    Returns False for anything that isn't a valid zip — malformed/non-zip
    binaries are left to their normal extract/skip handling rather than
    being judged here.

    depth: current recursion level (0 for the top-level call)
    cumulative_size: sum of uncompressed sizes across all nested levels so far
    """
    if depth > _ARCHIVE_MAX_NESTING_DEPTH:
        return True  # Too deeply nested
    if cumulative_size > _ARCHIVE_MAX_CUMULATIVE_BYTES:
        return True  # Cumulative size exceeded across all levels

    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > _ARCHIVE_MAX_ENTRIES:
                return True
            total_size = sum(i.file_size for i in infos)
            if total_size > _ARCHIVE_MAX_UNCOMPRESSED_BYTES:
                return True
            if cumulative_size + total_size > _ARCHIVE_MAX_CUMULATIVE_BYTES:
                return True
            for i in infos:
                if (
                    i.file_size > _ARCHIVE_MIN_RATIO_CHECK_BYTES
                    and i.compress_size > 0
                    and i.file_size / i.compress_size > _ARCHIVE_MAX_COMPRESSION_RATIO
                ):
                    return True
                # Check for nested zips: if this entry looks like a zip,
                # recursively inspect it (without decompressing the whole thing)
                if _looks_like_zip(i.filename):
                    try:
                        # Read just the first 4 bytes to peek for zip magic bytes
                        head = zf.read(i.filename, 4)
                        if _looks_like_zip(i.filename, head):
                            # This entry might be a nested zip; write it to a
                            # temp location and recursively check.
                            import tempfile
                            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                                tmp.write(zf.read(i.filename))
                                tmp_path = tmp.name
                            try:
                                if _is_archive_bomb(
                                    Path(tmp_path),
                                    depth=depth + 1,
                                    cumulative_size=cumulative_size + total_size,
                                ):
                                    return True
                            finally:
                                Path(tmp_path).unlink(missing_ok=True)
                    except (OSError, RuntimeError):
                        # If we can't read/decompress the nested entry, treat
                        # as potential bomb (fail-open for safety).
                        continue
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def read_scannable_content(path: Path, binary_mode: str = "extract") -> str | None:
    """Read *path* for scanning, honoring *binary_mode* for content sniffed
    as binary (see _is_binary). Text files are always read as text.

    binary_mode:
        "extract" (default) — run binary content through markitdown to pull
            out any embedded text (PDF, DOCX, PPTX, XLSX, ODT, and whatever
            else markitdown supports); if extraction fails or isn't available,
            fall back to scanning the raw bytes as UTF-8 text (errors="replace")
            rather than silently skipping the file. This may produce spurious
            findings on raw binary garbage (e.g. PNG image data), but ensures
            injection payloads hidden inside unextractable binaries are not
            silently missed.
        "text" — force raw bytes to be decoded as UTF-8 (errors="replace")
            regardless of binary content. An explicit opt-in for scanning a
            suspected extension-swapped file as literal text.
        "skip" — never attempt to read binary content; always returns None.

    Returns None when the file should be excluded from the scan entirely.
    """
    if not _is_binary(path):
        return path.read_text(encoding="utf-8", errors="replace")

    if binary_mode == "text":
        return path.read_text(encoding="utf-8", errors="replace")
    if binary_mode == "extract":
        if _is_archive_bomb(path):
            return None
        try:
            from llm_sanitizer.readers.binary_reader import read_binary
            return read_binary(str(path))
        except (ImportError, RuntimeError):
            # Extraction not available or failed; fall back to raw-text
            # scanning so we don't silently drop potentially malicious content.
            return path.read_text(encoding="utf-8", errors="replace")
    return None  # binary_mode == "skip", or any unrecognized value


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
        binary_mode: str = "extract",
    ) -> DirScanResult:
        """Recursively scan a directory and return aggregated results.

        binary_mode controls how files sniffed as binary are handled — see
        read_scannable_content for the "extract"/"text"/"skip" semantics.
        """
        root = Path(path)
        results: list[ScanResult] = []
        files_skipped_binary = 0

        files = iter_scannable_files(root, glob_pattern)

        for file_path in sorted(files):
            try:
                content = read_scannable_content(file_path, binary_mode=binary_mode)
            except OSError:
                continue
            if content is None:
                files_skipped_binary += 1
                continue
            result = self.scan(content, source=str(file_path), sensitivity=sensitivity)
            results.append(result)

        all_findings = [f for r in results for f in r.findings]
        max_risk: RiskLevel | None = None
        for f in all_findings:
            if max_risk is None or f.risk > max_risk:
                max_risk = f.risk

        return DirScanResult(
            source=path,
            sensitivity=sensitivity,
            files_scanned=len(results),
            files_skipped_binary=files_skipped_binary,
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


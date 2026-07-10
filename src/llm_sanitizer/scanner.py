# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Core scanner engine — rule registry, content parsing, finding accumulation."""

from __future__ import annotations

import fnmatch
import os
import tempfile
import zipfile
from pathlib import Path

from llm_sanitizer.config import ArchiveSettings, SanitizerConfig, load_config
from llm_sanitizer.models import (
    DirScanResult,
    Finding,
    RiskLevel,
    ScanResult,
    SummaryStats,
)
from llm_sanitizer.readers.archive_reader import (
    ArchiveError,
    ArchiveToolUnavailable,
    archive_type_from_extension,
    detect_archive_type,
    is_zip_based_document,
    iter_archive_members,
)
from llm_sanitizer.readers.integrity_checks import (
    detect_type_mismatch,
    validate_structure,
)
from llm_sanitizer.rules import BaseRule, get_all_rules, is_legitimate_file
from llm_sanitizer.rules.integrity import (
    ARCHIVE_UNSUPPORTED,
    CORRUPT_FILE,
    TYPE_MISMATCH,
    UNSCANNABLE_BINARY,
    make_integrity_finding,
)

# Map sensitivity strings to minimum risk level to include in results
_SENSITIVITY_RISK_MAP: dict[str, RiskLevel] = {
    "low": RiskLevel.high,      # low sensitivity → only critical/high
    "medium": RiskLevel.medium, # medium → medium and above
    "high": RiskLevel.info,     # high → all including info/low
}


class ExtractorUnavailableError(RuntimeError):
    """A required extractor/backend for content present in the scan is not
    installed. This is a systemic coverage gap, not a per-file decision, so it
    fails the whole run FAST — loudly — rather than silently degrading (raw-text
    fallback, skipping, or a per-file finding).

    Raised for: markitdown missing when a binary needs extraction, or an
    archive backend (py7zr/libarchive-c) missing for an archive format actually
    present in the scan. Carries an actionable install hint in ``.hint`` (also
    the exception message). Subclasses RuntimeError so existing CLI/MCP handlers
    that catch RuntimeError surface it as an error rather than crashing.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.hint = message


class _ExtractionFailedError(Exception):
    """Internal signal: markitdown ran but failed on this specific file (it is
    corrupt/unreadable). Distinct from ExtractorUnavailableError (backend
    missing). Routed by the scanner into a CRITICAL per-file finding; never
    escapes the scanner."""


def _extract_binary_text(path: Path) -> str:
    """Run markitdown extraction on *path*, translating its failure modes into
    the scanner's typed signals: ExtractorUnavailableError (markitdown absent →
    fail fast) vs _ExtractionFailedError (markitdown ran but failed → CRITICAL
    finding). Returns the extracted text (possibly empty) on success."""
    from llm_sanitizer.readers.binary_reader import read_binary

    try:
        return read_binary(str(path))
    except ImportError as exc:
        raise ExtractorUnavailableError(str(exc)) from exc
    except RuntimeError as exc:
        raise _ExtractionFailedError(str(exc)) from exc

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


def _is_archive_bomb(
    path: Path,
    depth: int = 0,
    cumulative_size: int = 0,
    settings: ArchiveSettings | None = None,
) -> bool:
    """Cheaply inspect a zip's central directory (no decompression) for the
    hallmarks of a zip bomb, including nested (zip-of-zips) variants.
    Returns False for anything that isn't a valid zip — malformed/non-zip
    binaries are left to their normal extract/skip handling rather than
    being judged here.

    depth: current recursion level (0 for the top-level call)
    cumulative_size: sum of uncompressed sizes across all nested levels so far
    settings: configured limits; falls back to the module-level constants (the
        ultimate defaults) when None, so a Scanner built without a config, and
        direct callers, behave exactly as before.
    """
    max_depth = settings.max_depth if settings else _ARCHIVE_MAX_NESTING_DEPTH
    max_cumulative = (
        settings.max_cumulative_bytes if settings else _ARCHIVE_MAX_CUMULATIVE_BYTES
    )
    max_entries = settings.max_entries if settings else _ARCHIVE_MAX_ENTRIES
    max_uncompressed = (
        settings.max_uncompressed_bytes if settings else _ARCHIVE_MAX_UNCOMPRESSED_BYTES
    )
    max_ratio = (
        settings.max_compression_ratio if settings else _ARCHIVE_MAX_COMPRESSION_RATIO
    )
    min_ratio_bytes = (
        settings.min_ratio_check_bytes if settings else _ARCHIVE_MIN_RATIO_CHECK_BYTES
    )

    if depth > max_depth:
        return True  # Too deeply nested
    if cumulative_size > max_cumulative:
        return True  # Cumulative size exceeded across all levels

    try:
        if not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                return True
            total_size = sum(i.file_size for i in infos)
            if total_size > max_uncompressed:
                return True
            if cumulative_size + total_size > max_cumulative:
                return True
            for i in infos:
                if (
                    i.file_size > min_ratio_bytes
                    and i.compress_size > 0
                    and i.file_size / i.compress_size > max_ratio
                ):
                    return True
                # Check for nested zips: if this entry looks like a zip,
                # recursively inspect it (without decompressing the whole thing)
                if _looks_like_zip(i.filename):
                    try:
                        # Peek at just the first 4 bytes to check for the zip
                        # magic ("PK") without decompressing the whole entry.
                        # (ZipFile.read's 2nd positional arg is the password,
                        # not a length — so open the member stream and read 4.)
                        with zf.open(i.filename) as _entry:
                            head = _entry.read(4)
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
                                    settings=settings,
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
        "extract" (default) — run binary content through markitdown to pull out
            any embedded text (PDF, DOCX, PPTX, XLSX, ODT, …). This text-oriented
            reader NEVER raw-text-falls-back on compressed/binary bytes (that
            produced spurious findings on binary garbage and never saw an
            archive's real contents). Instead:
              * markitdown absent → raises ExtractorUnavailableError (fail fast).
              * markitdown ran but failed on this file (corrupt) → returns None
                here (the scan path, Scanner.scan_file, detects this separately
                and emits a CRITICAL finding; redact copies the original
                through unchanged).
              * recognized archives → None (expanded by Scanner.scan_file).
        "text" — force raw bytes to be decoded as UTF-8 (errors="replace")
            regardless of binary content. An explicit opt-in for scanning a
            suspected extension-swapped file as literal text.
        "skip" — never attempt to read binary content; always returns None.

    Returns None when the file should be excluded from this text-oriented read.
    Raises ExtractorUnavailableError when markitdown is required but not
    installed (fail fast — a systemic coverage gap, not a per-file decision).
    """
    if not _is_binary(path):
        return path.read_text(encoding="utf-8", errors="replace")

    if binary_mode == "text":
        return path.read_text(encoding="utf-8", errors="replace")
    if binary_mode == "extract":
        if _is_archive_bomb(path):
            return None
        # Recognized archives (zip/tar/gz/bz2/xz/7z/rar) are expanded and
        # recursively scanned by Scanner.scan_file, not here. ZIP-based
        # *documents* (.docx/.odt/…) are not archives-to-expand and still flow
        # to markitdown below.
        atype = detect_archive_type(path)
        if atype is not None and not (
            atype == "zip" and is_zip_based_document(path)
        ):
            return None
        try:
            return _extract_binary_text(path)
        except _ExtractionFailedError:
            # markitdown ran but failed on this file. This text-oriented reader
            # cannot emit a finding, so it reports "no scannable content"; the
            # scan path (Scanner.scan_file) surfaces a CRITICAL finding for the
            # same file, and redact paths copy the original through unchanged.
            return None
        # ExtractorUnavailableError intentionally propagates (fail fast).
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
        self._archive_settings = self._config.archive
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

    def scan_file(
        self,
        path: str | Path,
        source: str | None = None,
        sensitivity: str = "medium",
        binary_mode: str = "extract",
    ) -> ScanResult | None:
        """Scan a single file, expanding recognized archives in place and
        applying content-integrity checks.

        Under ``binary_mode="extract"`` the file is classified by content, not
        extension. It may yield a ScanResult whose findings include, in addition
        to ordinary rule hits:

          * CRITICAL ``type_mismatch`` — the declared type (extension) does not
            match the content (a disguised archive, a .png that's really an
            executable, a text-named file whose bytes are binary, …);
          * CRITICAL ``corrupt_file`` — a recognized archive/PDF/Office document
            that fails a bounded structural check;
          * CRITICAL ``unscannable_binary`` — a non-archive binary whose
            extraction failed, or (under ``unprocessable_binary_policy="fail"``)
            produced no text;
          * findings from recursively scanning each member of a valid archive.

        Raises ExtractorUnavailableError (fail fast, halting the run) when a
        binary needs markitdown and it's absent, or an archive format present in
        the scan needs an uninstalled backend.

        Returns None when the file is skipped from scanning (a non-archive binary
        excluded by ``binary_mode`` / the "ignore" policy), so directory scans
        can count it as files_skipped_binary.
        """
        p = Path(path)
        src = source if source is not None else str(p)

        if binary_mode == "extract" and self._should_handle_as_archive(p):
            findings = self._scan_node(p, src, sensitivity, depth=0, cumulative=0)
            return self._result_from_findings(src, sensitivity, findings)

        outcome = self._scan_nonarchive(p, src, sensitivity, binary_mode)
        if outcome is None:
            return None
        return self._result_from_findings(src, sensitivity, outcome)

    def _should_handle_as_archive(self, path: Path) -> bool:
        """True when *path* should go through archive handling rather than the
        normal text/binary-extract path. A true-archive extension always
        qualifies (so a mismatch can be flagged even if the content is benign
        text); archive *content* qualifies too, except for ZIP-based documents
        (.docx/.odt/…), which are handled by markitdown."""
        if archive_type_from_extension(path) is not None:
            return True
        magic = detect_archive_type(path)
        if magic is None:
            return False
        if magic == "zip" and is_zip_based_document(path):
            return False
        return True

    def _scan_node(
        self,
        path: Path,
        source: str,
        sensitivity: str,
        depth: int,
        cumulative: int,
    ) -> list[Finding]:
        """Recursively classify and scan *path* (an archive, a member extracted
        from one, or a plain file), returning the flat list of findings.

        Handles, at every nesting level: extension/content type mismatch,
        disguised archives, corrupt archives, unsupported/uninstalled formats,
        bomb guards (depth + cumulative size), and normal member scanning.
        """
        settings = self._archive_settings
        ext_type = archive_type_from_extension(path)
        magic = detect_archive_type(path)

        # --- Not an archive at all → normal (non-archive) handling -------
        if ext_type is None and magic is None:
            return self._scan_nonarchive(path, source, sensitivity, "extract") or []

        # --- Archive content but no archive extension --------------------
        if ext_type is None and magic is not None:
            if magic == "zip" and is_zip_based_document(path):
                return self._scan_nonarchive(path, source, sensitivity, "extract") or []
            # A file whose bytes are an archive but whose name hides that fact
            # is a classic evasion — surface it loudly rather than expand it.
            return [
                make_integrity_finding(
                    TYPE_MISMATCH,
                    source,
                    f"File content is a '{magic}' archive but its name has no "
                    "archive extension — content is disguised. Not expanded.",
                )
            ]

        # --- Archive extension but content isn't a recognized archive ----
        if magic is None:
            return [
                make_integrity_finding(
                    TYPE_MISMATCH,
                    source,
                    f"File has a '{ext_type}' archive extension but its content "
                    "is not a recognized archive of any supported type "
                    "(corrupt, truncated, or type-swapped). Not expanded.",
                )
            ]

        # --- Extension and content disagree about the archive type -------
        if ext_type != magic:
            return [
                make_integrity_finding(
                    TYPE_MISMATCH,
                    source,
                    f"File extension implies a '{ext_type}' archive but its "
                    f"content is a '{magic}' archive — type mismatch. "
                    "Not expanded.",
                )
            ]

        # --- Bomb guard (same defense as the pre-extract zip-bomb check) --
        if _is_archive_bomb(path, depth=depth, settings=settings):
            return []  # silently skipped, matching the existing bomb defense

        # --- Format disabled by configuration ----------------------------
        if magic not in settings.formats:
            return [
                make_integrity_finding(
                    ARCHIVE_UNSUPPORTED,
                    source,
                    f"Archive format '{magic}' is disabled by configuration "
                    "(archive.formats). Not expanded.",
                )
            ]

        # --- Too deeply nested → bomb guard ------------------------------
        if depth >= settings.max_depth:
            return []  # silently stop recursing, matching the bomb defense

        # --- Expand and recursively scan members -------------------------
        return self._extract_and_scan(
            path, source, magic, sensitivity, depth, cumulative
        )

    def _scan_nonarchive(
        self, path: Path, source: str, sensitivity: str, binary_mode: str
    ) -> list[Finding] | None:
        """Scan a non-archive file. Returns its findings, or None to signal the
        file was skipped (counted as files_skipped_binary by directory scans).

        Under ``binary_mode="extract"`` this applies the two content-integrity
        tiers before ordinary scanning:
          * Tier 1 — extension-vs-content type mismatch → CRITICAL type_mismatch.
          * Tier 2 — bounded PDF/Office structural validation → CRITICAL
            corrupt_file.
        Both are fail-closed short-circuits: a file that fails them is not
        extracted/scanned further. ``"text"``/``"skip"`` are explicit overrides
        that bypass these content-based checks.
        """
        if binary_mode == "extract":
            mismatch = detect_type_mismatch(path)
            if mismatch is not None:
                return [make_integrity_finding(TYPE_MISMATCH, source, mismatch)]
            corrupt = validate_structure(
                path,
                max_entries=self._archive_settings.max_entries,
                max_bytes=self._archive_settings.max_uncompressed_bytes,
            )
            if corrupt is not None:
                return [make_integrity_finding(CORRUPT_FILE, source, corrupt)]
        return self._scan_plain(path, source, sensitivity, binary_mode)

    def _scan_plain(
        self, path: Path, source: str, sensitivity: str, binary_mode: str
    ) -> list[Finding] | None:
        """Read and scan a non-archive file's content. Returns findings, or None
        to signal a skip. Applies the unprocessable-binary policy and emits the
        CRITICAL unscannable_binary finding for a failed/empty extraction.

        Lets ExtractorUnavailableError propagate (fail fast) — never caught."""
        # Text content is always scanned as text, regardless of binary_mode.
        # An OSError here (e.g. a missing file) propagates: directory scans
        # catch it per-file (skip), and the CLI/MCP surface it as an error —
        # a single-file scan of a nonexistent path must fail, not silently skip.
        if not _is_binary(path):
            content = path.read_text(encoding="utf-8", errors="replace")
            return self.scan(content, source=source, sensitivity=sensitivity).findings

        if binary_mode == "text":
            content = path.read_text(encoding="utf-8", errors="replace")
            return self.scan(content, source=source, sensitivity=sensitivity).findings
        if binary_mode == "skip":
            return None
        # binary_mode == "extract"
        if _is_archive_bomb(path):
            return None
        try:
            text = _extract_binary_text(path)
        except _ExtractionFailedError as exc:
            # markitdown ran but failed on this file → fail closed.
            return [
                make_integrity_finding(
                    UNSCANNABLE_BINARY,
                    source,
                    f"Binary extraction failed (corrupt or unreadable): {exc}",
                )
            ]
        if not text.strip():
            # Processed but no extractable text → governed by policy (Part A).
            policy = self._config.unprocessable_binary_policy
            if policy == "ignore":
                return None  # explicit fail-open opt-out (counted as skipped)
            if policy == "scan-text":
                raw = path.read_text(encoding="utf-8", errors="replace")
                return self.scan(raw, source=source, sensitivity=sensitivity).findings
            # "fail" (default) — fail closed.
            return [
                make_integrity_finding(
                    UNSCANNABLE_BINARY,
                    source,
                    "Binary was processed but yielded no extractable text; it "
                    "cannot be scanned (unprocessable_binary_policy='fail').",
                )
            ]
        return self.scan(text, source=source, sensitivity=sensitivity).findings

    def _extract_and_scan(
        self,
        path: Path,
        source: str,
        archive_type: str,
        sensitivity: str,
        depth: int,
        cumulative: int,
    ) -> list[Finding]:
        settings = self._archive_settings
        try:
            members = iter_archive_members(
                path,
                archive_type,
                max_total_bytes=settings.max_uncompressed_bytes,
                max_entries=settings.max_entries,
            )
            findings: list[Finding] = []
            running = cumulative
            for name, data in members:
                running += len(data)
                if running > settings.max_cumulative_bytes:
                    break  # cumulative bomb guard across nested levels
                member_source = f"{source}::{name}"
                with tempfile.NamedTemporaryFile(
                    suffix="_" + Path(name).name, delete=False
                ) as tmp:
                    tmp.write(data)
                    tmp_path = Path(tmp.name)
                try:
                    findings.extend(
                        self._scan_node(
                            tmp_path,
                            member_source,
                            sensitivity,
                            depth=depth + 1,
                            cumulative=running,
                        )
                    )
                finally:
                    tmp_path.unlink(missing_ok=True)
            return findings
        except ArchiveToolUnavailable as exc:
            # A format actually present in the scan needs a backend that isn't
            # installed → systemic coverage gap → fail fast (Part B), NOT a
            # per-file finding. (Format-disabled-by-config is handled earlier as
            # a CRITICAL archive_unsupported finding; corrupt archives below.)
            raise ExtractorUnavailableError(str(exc)) from exc
        except ArchiveError as exc:
            return [make_integrity_finding(CORRUPT_FILE, source, str(exc))]

    def _result_from_findings(
        self, source: str, sensitivity: str, findings: list[Finding]
    ) -> ScanResult:
        """Build a ScanResult from pre-computed findings (from archive
        expansion), applying the sensitivity threshold and re-numbering IDs the
        same way :meth:`scan` does."""
        min_risk = _SENSITIVITY_RISK_MAP.get(sensitivity, RiskLevel.medium)
        filtered = [f for f in findings if f.risk >= min_risk]
        renumbered = [
            f.model_copy(update={"id": i}) for i, f in enumerate(filtered, start=1)
        ]
        return ScanResult(
            source=source,
            sensitivity=sensitivity,
            summary=_build_summary(renumbered),
            findings=renumbered,
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
        Recognized archives are expanded and their members scanned recursively
        (see scan_file).
        """
        root = Path(path)
        results: list[ScanResult] = []
        files_skipped_binary = 0

        files = iter_scannable_files(root, glob_pattern)

        for file_path in sorted(files):
            try:
                result = self.scan_file(
                    file_path, sensitivity=sensitivity, binary_mode=binary_mode
                )
            except OSError:
                continue
            if result is None:
                files_skipped_binary += 1
                continue
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


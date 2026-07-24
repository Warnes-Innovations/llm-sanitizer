# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Human-friendly CLI for llm-sanitizer."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-sanitize",
        description="Detect, classify, and redact embedded LLM agent instructions.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    scan_parser = subparsers.add_parser("scan", help="Scan file, URL, directory, or stdin")
    scan_parser.add_argument("target", help="File path, URL, directory, or '-' for stdin")
    scan_parser.add_argument("--glob", default="**/*", help="File pattern for directory scans")
    scan_parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Detection sensitivity (default: medium)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    scan_parser.add_argument(
        "--min-risk",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
        help="Minimum risk level to report (default: info)",
    )
    scan_parser.add_argument(
        "--exit-code-threshold",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Exit non-zero if any finding meets or exceeds this level",
    )
    scan_parser.add_argument(
        "--binary-mode",
        choices=["skip", "extract", "text"],
        default="extract",
        help=(
            "How to handle content sniffed as binary, by content not "
            "extension (default: extract). extract: pull embedded text via "
            "markitdown, and expand recognized archives (zip/tar/gz/7z/rar/…) "
            "to recursively scan their members. text: force raw bytes to be "
            "scanned as literal UTF-8 text — use when a file's extension is "
            "suspected of being swapped to evade extraction/skipping. skip: "
            "exclude binary files from the scan entirely."
        ),
    )
    scan_parser.add_argument(
        "--unprocessable-binary-policy",
        choices=["ignore", "scan-text", "fail"],
        default=None,
        help=(
            "How to handle a NON-archive binary that is processed but yields no "
            "extractable text (default: fail). fail: emit a CRITICAL "
            "unscannable_binary finding (fail closed). scan-text: scan the raw "
            "bytes as text for injection patterns. ignore: skip it (counted as "
            "skipped). Does not affect extractor-unavailable (always fails the "
            "run) or corrupt files (always CRITICAL)."
        ),
    )
    _add_archive_args(scan_parser)

    # --- redact ---
    redact_parser = subparsers.add_parser("redact", help="Redact file, URL, directory, or stdin")
    redact_parser.add_argument("target", help="File path, URL, directory, or '-' for stdin")
    redact_parser.add_argument("-o", "--output", required=True, help="Output path (file or directory)")
    redact_parser.add_argument(
        "--mode",
        choices=["strip", "comment", "highlight"],
        default="strip",
        help="Redaction mode (default: strip)",
    )
    redact_parser.add_argument("--glob", default="**/*", help="File pattern for directory redaction")
    redact_parser.add_argument(
        "--sensitivity",
        choices=["low", "medium", "high"],
        default="medium",
        help=(
            "Detection sensitivity (default: medium). Use the same value as "
            "the scan so redaction removes everything the scan reported."
        ),
    )
    redact_parser.add_argument(
        "--affected-only",
        action="store_true",
        help="Only output files that had findings (directory mode)",
    )
    redact_parser.add_argument(
        "--binary-mode",
        choices=["skip", "extract", "text"],
        default="extract",
        help=(
            "How to handle content sniffed as binary, by content not "
            "extension (default: extract). extract: scan embedded text via "
            "markitdown, but always copy the original binary through "
            "unchanged (redacted extracted text can't be written back into "
            "e.g. a PDF). text: force raw bytes to be scanned *and "
            "redacted* as literal text — only safe for files you already "
            "know aren't genuinely binary. skip: copy binary files through "
            "unscanned."
        ),
    )

    # --- list-rules ---
    rules_parser = subparsers.add_parser("list-rules", help="List active detection rules")
    rules_parser.add_argument("--category", default=None, help="Filter rules by category")

    # --- merge ---
    merge_parser = subparsers.add_parser(
        "merge",
        help="Assemble a directory-level report from cached per-file scan JSON, without re-scanning",
    )
    merge_parser.add_argument(
        "--manifest",
        default="-",
        help=(
            "Path to a manifest of JSON_PATH<TAB>CURRENT_PATH lines, one "
            "per previously-scanned file — JSON_PATH is a saved `scan "
            "--format json` result, CURRENT_PATH is the path it should be "
            "reported under (default: read manifest from stdin)"
        ),
    )
    merge_parser.add_argument(
        "--source",
        default="<merged>",
        help="Value to report as the aggregate source/root path (default: '<merged>')",
    )
    merge_parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    merge_parser.add_argument(
        "--exit-code-threshold",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Exit non-zero if any finding meets or exceeds this level",
    )
    merge_parser.add_argument(
        "--skipped-binary",
        type=int,
        default=0,
        help="Count to report as files_skipped_binary (the caller's own count; not derived from the manifest)",
    )

    return parser


def _add_archive_args(parser: argparse.ArgumentParser) -> None:
    """Add archive-handling override flags. These override the corresponding
    keys from any loaded config file; unset flags leave the config (or its
    built-in defaults) untouched."""
    parser.add_argument(
        "--archive-max-depth",
        type=int,
        default=None,
        metavar="N",
        help="Max archive-in-archive nesting depth to expand (default: 3)",
    )
    parser.add_argument(
        "--archive-max-bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help=(
            "Max cumulative uncompressed bytes across all nested archive "
            "levels before extraction stops (default: 524288000 = 500MB)"
        ),
    )
    parser.add_argument(
        "--archive-formats",
        default=None,
        metavar="LIST",
        help=(
            "Comma-separated list of archive formats to expand "
            "(zip,tar,gz,bz2,xz,7z,rar). Formats omitted here are reported as "
            "unsupported (CRITICAL) rather than expanded. Default: all."
        ),
    )
    parser.add_argument(
        "--max-scan-bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help=(
            "Max bytes of text a single unit (file, extracted member, or inline "
            "content) may be scanned. Larger input is refused with a CRITICAL "
            "input_too_large finding (default: 26214400 = 25MB)"
        ),
    )


def _config_with_archive_overrides(args: argparse.Namespace) -> object:
    """Load config and apply any --archive-* / --unprocessable-binary-policy /
    --max-scan-bytes CLI overrides on top of it."""
    from llm_sanitizer.config import load_config

    config = load_config()
    if getattr(args, "archive_max_depth", None) is not None:
        config.archive.max_depth = args.archive_max_depth
    if getattr(args, "archive_max_bytes", None) is not None:
        config.archive.max_cumulative_bytes = args.archive_max_bytes
    if getattr(args, "archive_formats", None) is not None:
        config.archive.formats = [
            f.strip() for f in args.archive_formats.split(",") if f.strip()
        ]
    if getattr(args, "unprocessable_binary_policy", None) is not None:
        config.unprocessable_binary_policy = args.unprocessable_binary_policy
    if getattr(args, "max_scan_bytes", None) is not None:
        config.max_scan_bytes = args.max_scan_bytes
    return config


def _get_version() -> str:
    from llm_sanitizer import __version__

    return __version__


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _read_content(target: str, binary_mode: str = "extract") -> tuple[str | None, str]:
    """Read content from target (file/URL/stdin). Returns (content, source_label).
    content is None when target is a file sniffed as binary and binary_mode
    excludes it from scanning (see llm_sanitizer.scanner.read_scannable_content)."""
    if target == "-":
        from llm_sanitizer.readers.text_reader import read_text
        return read_text("-"), "<stdin>"
    if _is_url(target):
        from llm_sanitizer.readers.url_reader import read_url
        return read_url(target), target
    from llm_sanitizer.readers import read_file
    return read_file(target, binary_mode=binary_mode), target


def _filter_by_min_risk(result: object, min_risk_str: str) -> object:
    """Post-filter findings by min_risk if needed."""
    from llm_sanitizer.models import RiskLevel, ScanResult
    if not isinstance(result, ScanResult):
        return result
    min_risk = RiskLevel.from_str(min_risk_str)
    filtered = [f for f in result.findings if f.risk >= min_risk]
    from llm_sanitizer.scanner import _build_summary
    return result.model_copy(update={
        "findings": filtered,
        "summary": _build_summary(filtered),
    })


def main() -> None:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "redact":
        _cmd_redact(args)
    elif args.command == "list-rules":
        _cmd_list_rules(args)
    elif args.command == "merge":
        _cmd_merge(args)
    else:
        parser.print_help()
        sys.exit(2)


def _cmd_scan(args: argparse.Namespace) -> None:
    from llm_sanitizer.config import SanitizerConfig
    from llm_sanitizer.formatters import format_output
    from llm_sanitizer.models import DirScanResult, RiskLevel, ScanResult
    from llm_sanitizer.scanner import ExtractorUnavailableError, Scanner

    config = _config_with_archive_overrides(args)
    assert isinstance(config, SanitizerConfig)
    scanner = Scanner(config)
    target: str = args.target
    binary_mode: str = args.binary_mode

    try:
        if Path(target).is_dir():
            result = scanner.scan_dir(
                target, glob_pattern=args.glob, sensitivity=args.sensitivity, binary_mode=binary_mode
            )
        elif target != "-" and not _is_url(target):
            # Local file: use the archive-aware path so recognized archives are
            # expanded and their members recursively scanned.
            file_result = scanner.scan_file(
                target, sensitivity=args.sensitivity, binary_mode=binary_mode
            )
            if file_result is None:
                print(
                    f"[llm-sanitize] Skipped: no scannable text content "
                    f"(binary file, binary_mode={binary_mode!r}): {target}",
                    file=sys.stderr,
                )
                sys.exit(3)
            result = _filter_by_min_risk(file_result, args.min_risk)  # type: ignore[assignment]
        else:
            content, source = _read_content(target, binary_mode=binary_mode)
            if content is None:
                print(
                    f"[llm-sanitize] Skipped: no scannable text content "
                    f"(binary file, binary_mode={binary_mode!r}): {target}",
                    file=sys.stderr,
                )
                sys.exit(3)
            result = scanner.scan(  # type: ignore[assignment]
                content, source=source, sensitivity=args.sensitivity
            )
            result = _filter_by_min_risk(result, args.min_risk)  # type: ignore[assignment]
    except ExtractorUnavailableError as exc:
        # A required extractor/backend is missing for content in this scan.
        # Fail fast and loud — do not degrade or partially report.
        print(
            f"[llm-sanitize] Extractor unavailable — cannot complete scan: {exc.hint}",
            file=sys.stderr,
        )
        sys.exit(2)
    except (OSError, RuntimeError) as exc:
        print(f"[llm-sanitize] Error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(format_output(result, fmt=args.format))

    # Exit code logic. Both ScanResult and DirScanResult expose .summary.max_risk
    # (DirScanResult is a SIBLING type, not a subclass) — a directory scan must
    # gate the exit code too, or `scan <dir> --exit-code-threshold` fails open and
    # a directory full of injections exits 0 (committee round-2 HIGH).
    if args.exit_code_threshold and isinstance(result, (ScanResult, DirScanResult)):
        threshold = RiskLevel.from_str(args.exit_code_threshold)
        if result.summary.max_risk is not None and result.summary.max_risk >= threshold:
            sys.exit(1)


def _cmd_redact(args: argparse.Namespace) -> None:
    from llm_sanitizer.redactor import redact_content
    from llm_sanitizer.scanner import ExtractorUnavailableError, Scanner

    scanner = Scanner()
    target: str = args.target
    output: str = args.output
    binary_mode: str = args.binary_mode
    sensitivity: str = args.sensitivity

    try:
        if Path(target).is_dir():
            _redact_dir(
                scanner, target, output, args.mode, args.glob,
                args.affected_only, binary_mode, sensitivity,
            )
        else:
            from llm_sanitizer.scanner import _is_binary

            content, source = _read_content(target, binary_mode=binary_mode)
            if content is None:
                print(
                    f"[llm-sanitize] Skipped: no scannable text content "
                    f"(binary file, binary_mode={binary_mode!r}): {target}",
                    file=sys.stderr,
                )
                sys.exit(3)
            # Iterate scan/redact to a stable state — a single pass can
            # expose new findings (stripping zero-width characters reveals
            # the text underneath; removing one span on a minified line
            # uncovers the next).
            redacted, scan_result = redact_content(
                content, mode=args.mode, source=source, sensitivity=sensitivity
            )
            if output == "-":
                print(redacted, end="")
            else:
                is_binary_content = (
                    binary_mode != "text"
                    and target != "-"
                    and not _is_url(target)
                    and _is_binary(Path(target))
                )
                if is_binary_content:
                    # A binary file's *extracted* text can be scanned for
                    # findings, but a redacted version of that extracted text
                    # can't be written back into the original binary format —
                    # so binary files are copied through unmodified rather
                    # than replaced with mangled text (mirrors
                    # _redact_dir/redact_dir's handling of the same case).
                    shutil.copy2(target, output)
                else:
                    Path(output).write_text(redacted, encoding="utf-8")
                findings_count = scan_result.summary.total_findings
                print(f"[llm-sanitize] Redacted {findings_count} finding(s) → {output}")
    except ExtractorUnavailableError as exc:
        print(
            f"[llm-sanitize] Extractor unavailable — cannot complete redact: {exc.hint}",
            file=sys.stderr,
        )
        sys.exit(2)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[llm-sanitize] Error: {exc}", file=sys.stderr)
        sys.exit(2)


def _redact_dir(
    scanner: object,
    src: str,
    dst: str,
    mode: str,
    glob_pattern: str,
    affected_only: bool,
    binary_mode: str = "extract",
    sensitivity: str = "medium",
) -> None:
    from llm_sanitizer.redactor import redact_content
    from llm_sanitizer.scanner import Scanner, _is_binary, iter_scannable_files, read_scannable_content

    assert isinstance(scanner, Scanner)
    src_path = Path(src)
    dst_path = Path(dst)
    dst_path.mkdir(parents=True, exist_ok=True)
    files_written: list[str] = []

    files = iter_scannable_files(src_path, glob_pattern)

    for file_path in sorted(files):
        rel = file_path.relative_to(src_path)
        out_path = dst_path / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # A binary file's *extracted* text can be scanned for findings,
            # but a redacted version of that extracted text can't be written
            # back into the original binary format — so binary files with
            # findings are still copied through unmodified rather than
            # replaced with mangled text (mirrors server.py's redact_dir).
            is_binary_content = binary_mode != "text" and _is_binary(file_path)
            content = read_scannable_content(file_path, binary_mode=binary_mode)
            if content is None:
                # Never scanned (binary_mode="skip", or "extract" with
                # extraction unavailable/failed) — still copy the original
                # through so it isn't silently dropped from what's meant to
                # be a drop-in replacement directory (matches the documented
                # --binary-mode behavior for both "skip" and "extract").
                if not affected_only:
                    shutil.copy2(file_path, out_path)
                    files_written.append(str(out_path))
                continue
            # Iterate scan/redact per file to a stable state (see
            # _cmd_redact's single-file path for rationale).
            redacted, scan_result = redact_content(
                content, mode=mode, source=str(file_path), sensitivity=sensitivity
            )
            if scan_result.findings:
                if is_binary_content:
                    shutil.copy2(file_path, out_path)
                else:
                    out_path.write_text(redacted, encoding="utf-8")
                files_written.append(str(out_path))
            elif not affected_only:
                shutil.copy2(file_path, out_path)
                files_written.append(str(out_path))
        except OSError:
            continue

    print(
        json.dumps(
            {"status": "ok", "source": src, "output_dir": dst, "files_written": files_written},
            indent=2,
        )
    )


def _cmd_merge(args: argparse.Namespace) -> None:
    """Assemble a DirScanResult from previously-saved per-file `scan --format
    json` results, without re-scanning any content. Built for callers (like
    audit-agents.sh) that already cache a full ScanResult per file (keyed by
    content hash) and only need a combined report — the alternative, a fresh
    `scan <dir>` call, silently discards that cache and re-reads/re-scans
    every file a second time.

    Manifest lines are JSON_PATH<TAB>CURRENT_PATH. JSON_PATH points at a
    saved ScanResult; CURRENT_PATH is the path it should be reported under.
    The two differ whenever the cache is keyed by content hash rather than
    path (a cache hit's saved `source` field reflects whichever path was
    scanned *first* under that hash, not necessarily the current file) — so
    each loaded result's `source` is overridden to CURRENT_PATH before it's
    included in the report.
    """
    from llm_sanitizer.formatters import format_output
    from llm_sanitizer.models import DirScanResult, RiskLevel, ScanResult

    if args.manifest == "-":
        manifest_text = sys.stdin.read()
    else:
        try:
            manifest_text = Path(args.manifest).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[llm-sanitize] Error: {exc}", file=sys.stderr)
            sys.exit(2)

    results: list[ScanResult] = []
    sensitivities: set[str] = set()
    for lineno, line in enumerate(manifest_text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            print(
                f"[llm-sanitize] Error: manifest line {lineno} is not "
                f"JSON_PATH<TAB>CURRENT_PATH: {line!r}",
                file=sys.stderr,
            )
            sys.exit(2)
        json_path, current_path = parts
        try:
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
            # `scan --format json` renders risk levels as human-readable
            # names (via model_dump_json_friendly) rather than the raw
            # IntEnum values plain model_validate() expects — the cache this
            # command reads is exactly that saved --format json output, so
            # convert the names back before validating.
            summary = data.get("summary") or {}
            if isinstance(summary.get("max_risk"), str):
                summary["max_risk"] = RiskLevel.from_str(summary["max_risk"])
            for finding in data.get("findings", []):
                if isinstance(finding.get("risk"), str):
                    finding["risk"] = RiskLevel.from_str(finding["risk"])
            result = ScanResult.model_validate(data)
        except (OSError, ValueError, KeyError) as exc:
            print(
                f"[llm-sanitize] Error: could not load {json_path!r} (manifest line {lineno}): {exc}",
                file=sys.stderr,
            )
            sys.exit(2)
        sensitivities.add(result.sensitivity)
        results.append(result.model_copy(update={"source": current_path}))

    from llm_sanitizer.scanner import _build_summary

    all_findings = [f for r in results for f in r.findings]
    summary = _build_summary(all_findings)
    max_risk = summary.max_risk

    # Manifest entries can legitimately have been scanned under different
    # --sensitivity settings (a cache accumulated across runs) — report that
    # honestly rather than silently reporting whichever entry happened to be
    # processed last.
    sensitivity = sensitivities.pop() if len(sensitivities) == 1 else "mixed"

    dir_result = DirScanResult(
        source=args.source,
        sensitivity=sensitivity,
        files_scanned=len(results),
        files_skipped_binary=args.skipped_binary,
        summary=summary,
        total_findings=summary.total_findings,
        max_risk=summary.max_risk,
        results=results,
    )

    print(format_output(dir_result, fmt=args.format))

    if args.exit_code_threshold:
        threshold = RiskLevel.from_str(args.exit_code_threshold)
        if max_risk is not None and max_risk >= threshold:
            sys.exit(1)


def _cmd_list_rules(args: argparse.Namespace) -> None:
    from llm_sanitizer.rules import get_all_rules

    rules = get_all_rules()
    if args.category:
        rules = [r for r in rules if r.category == args.category]

    output = [
        {
            "id": r.rule_id,
            "name": r.rule_name,
            "category": r.category,
            "default_risk": r.default_risk.name,
            "description": r.description,
        }
        for r in rules
    ]
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()


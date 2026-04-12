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
        "--affected-only",
        action="store_true",
        help="Only output files that had findings (directory mode)",
    )

    # --- list-rules ---
    rules_parser = subparsers.add_parser("list-rules", help="List active detection rules")
    rules_parser.add_argument("--category", default=None, help="Filter rules by category")

    return parser


def _get_version() -> str:
    from llm_sanitizer import __version__

    return __version__


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _read_content(target: str) -> tuple[str, str]:
    """Read content from target (file/URL/stdin). Returns (content, source_label)."""
    if target == "-":
        from llm_sanitizer.readers.text_reader import read_text
        return read_text("-"), "<stdin>"
    if _is_url(target):
        from llm_sanitizer.readers.url_reader import read_url
        return read_url(target), target
    from llm_sanitizer.readers import read_file
    return read_file(target), target


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
    else:
        parser.print_help()
        sys.exit(2)


def _cmd_scan(args: argparse.Namespace) -> None:
    from llm_sanitizer.formatters import format_output
    from llm_sanitizer.models import RiskLevel, ScanResult
    from llm_sanitizer.scanner import Scanner

    scanner = Scanner()
    target: str = args.target

    try:
        if Path(target).is_dir():
            result = scanner.scan_dir(target, glob_pattern=args.glob, sensitivity=args.sensitivity)
        else:
            content, source = _read_content(target)
            result = scanner.scan(content, source=source, sensitivity=args.sensitivity)
            result = _filter_by_min_risk(result, args.min_risk)  # type: ignore[assignment]
    except (OSError, RuntimeError) as exc:
        print(f"[llm-sanitize] Error: {exc}", file=sys.stderr)
        sys.exit(2)

    print(format_output(result, fmt=args.format))

    # Exit code logic
    if args.exit_code_threshold and isinstance(result, ScanResult):
        threshold = RiskLevel.from_str(args.exit_code_threshold)
        if result.summary.max_risk is not None and result.summary.max_risk >= threshold:
            sys.exit(1)


def _cmd_redact(args: argparse.Namespace) -> None:
    from llm_sanitizer.redactor import redact
    from llm_sanitizer.scanner import Scanner

    scanner = Scanner()
    target: str = args.target
    output: str = args.output

    try:
        if Path(target).is_dir():
            _redact_dir(scanner, target, output, args.mode, args.glob, args.affected_only)
        else:
            content, source = _read_content(target)
            scan_result = scanner.scan(content, source=source)
            redacted = redact(content, scan_result, mode=args.mode)
            if output == "-":
                print(redacted, end="")
            else:
                Path(output).write_text(redacted, encoding="utf-8")
                findings_count = scan_result.summary.total_findings
                print(f"[llm-sanitize] Redacted {findings_count} finding(s) → {output}")
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
) -> None:
    import fnmatch
    from llm_sanitizer.redactor import redact
    from llm_sanitizer.scanner import Scanner

    assert isinstance(scanner, Scanner)
    src_path = Path(src)
    dst_path = Path(dst)
    dst_path.mkdir(parents=True, exist_ok=True)
    files_written: list[str] = []

    files = [p for p in src_path.rglob("*") if p.is_file()]
    if glob_pattern != "**/*":
        files = [p for p in files if fnmatch.fnmatch(p.name, glob_pattern.lstrip("**/"))]

    for file_path in sorted(files):
        rel = file_path.relative_to(src_path)
        out_path = dst_path / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            scan_result = scanner.scan(content, source=str(file_path))
            if scan_result.findings:
                out_path.write_text(redact(content, scan_result, mode=mode), encoding="utf-8")
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


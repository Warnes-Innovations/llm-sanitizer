# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Human-friendly CLI for llm-sanitizer."""

from __future__ import annotations

import argparse
import sys


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
    print(f"[llm-sanitize] scan not yet implemented (target={args.target})", file=sys.stderr)
    sys.exit(2)


def _cmd_redact(args: argparse.Namespace) -> None:
    print(f"[llm-sanitize] redact not yet implemented (target={args.target})", file=sys.stderr)
    sys.exit(2)


def _cmd_list_rules(args: argparse.Namespace) -> None:
    print("[llm-sanitize] list-rules not yet implemented", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()

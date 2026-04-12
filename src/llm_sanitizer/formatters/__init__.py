# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Output format registry."""

from __future__ import annotations

from llm_sanitizer.models import DirScanResult, ScanResult


def format_output(
    result: ScanResult | DirScanResult,
    fmt: str = "markdown",
) -> str:
    """Format a scan result using the requested output format.

    Args:
        result: A ScanResult or DirScanResult to format.
        fmt: "json" | "markdown" | "sarif"
    """
    if fmt == "json":
        from llm_sanitizer.formatters.json_format import format_json
        return format_json(result)
    elif fmt == "sarif":
        from llm_sanitizer.formatters.sarif_format import format_sarif
        return format_sarif(result)
    else:
        from llm_sanitizer.formatters.markdown_format import format_markdown
        return format_markdown(result)


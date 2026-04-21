# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Redaction engine — produce cleaned content from scan findings."""

from __future__ import annotations

from llm_sanitizer.models import Finding, ScanResult


def _strip_finding(content: str, finding: Finding) -> str:
    """Remove the matched text from content."""
    return content.replace(finding.matched_raw, "", 1)


def _comment_finding(content: str, finding: Finding) -> str:
    """Replace the matched text with a redaction marker."""
    marker = (
        f"[REDACTED: LLM instruction removed ({finding.rule}, {finding.risk.name})]"
    )
    return content.replace(finding.matched_raw, marker, 1)


def _highlight_finding(content: str, finding: Finding) -> str:
    """Wrap the matched text in visible warning markers."""
    marker = f"\u26a0\ufe0f[LLM-INSTRUCTION: {finding.matched}]\u26a0\ufe0f"
    return content.replace(finding.matched_raw, marker, 1)


def redact(
    content: str,
    result: ScanResult,
    mode: str = "strip",
) -> str:
    """Redact findings from *content* according to *mode*.

    Args:
        content: The original text content.
        result: ScanResult containing findings to redact.
        mode: "strip" | "comment" | "highlight"

    Returns:
        Redacted text content.
    """
    if mode not in ("strip", "comment", "highlight"):
        raise ValueError(f"Unknown redaction mode: {mode!r}. Use 'strip', 'comment', or 'highlight'.")

    redacted = content
    # Process findings in reverse order to preserve character offsets where possible.
    # Since we're doing simple string replacement, order matters only when the same
    # matched text appears multiple times — replace one at a time.
    for finding in result.findings:
        if finding.matched_raw and finding.matched_raw in redacted:
            if mode == "strip":
                redacted = _strip_finding(redacted, finding)
            elif mode == "comment":
                redacted = _comment_finding(redacted, finding)
            elif mode == "highlight":
                redacted = _highlight_finding(redacted, finding)

    return redacted


def redact_content(
    content: str,
    mode: str = "strip",
    source: str = "<inline>",
    sensitivity: str = "medium",
) -> tuple[str, ScanResult]:
    """Convenience: scan *content* and return (redacted_text, scan_result)."""
    from llm_sanitizer.scanner import scan_text

    result = scan_text(content, source=source, sensitivity=sensitivity)
    return redact(content, result, mode=mode), result


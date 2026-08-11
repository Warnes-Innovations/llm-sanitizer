# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Markdown output formatter — human-readable reports."""

from __future__ import annotations

from llm_sanitizer.models import DirScanResult, RiskLevel, ScanResult

_RISK_ICONS = {
    RiskLevel.info: "ℹ️ INFO",
    RiskLevel.low: "🟡 LOW",
    RiskLevel.medium: "🟠 MEDIUM",
    RiskLevel.high: "🔴 HIGH",
    RiskLevel.critical: "🚨 CRITICAL",
}


def _format_single(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"## Scan Report: `{result.source}`\n")

    if not result.findings:
        lines.append("✅ No findings.\n")
        return "\n".join(lines)

    summary = result.summary
    lines.append(
        f"**Summary:** {summary.total_findings} finding(s) — "
        f"max risk: **{summary.max_risk}**\n"
    )

    risk_parts = [
        f"{k}: {v}" for k, v in summary.by_risk.items() if v > 0
    ]
    if risk_parts:
        lines.append("**By risk:** " + ", ".join(risk_parts) + "\n")

    lines.append("---\n")

    for finding in result.findings:
        icon = _RISK_ICONS.get(finding.risk, str(finding.risk))
        lines.append(f"### [{icon}] {finding.rule_name} (Line {finding.location.line})\n")
        lines.append(f"**Rule:** `{finding.rule}`  ")
        lines.append(f"**Risk:** {finding.risk.name}  ")
        lines.append(f"**Location:** line {finding.location.line}, col {finding.location.column}\n")
        lines.append(f"**Matched:** `{finding.matched[:120]}`\n")
        lines.append(f"**Explanation:** {finding.explanation}\n")

        ctx = finding.context
        if ctx.before or ctx.line or ctx.after:
            lines.append("**Context:**\n```")
            for bl in ctx.before:
                lines.append(bl)
            if ctx.line:
                lines.append(f">>> {ctx.line}")
            for al in ctx.after:
                lines.append(al)
            lines.append("```\n")

    return "\n".join(lines)


def format_markdown(result: ScanResult | DirScanResult) -> str:
    """Format result as a Markdown report."""
    if isinstance(result, ScanResult):
        return _format_single(result)

    # DirScanResult
    lines: list[str] = []
    lines.append(f"# Directory Scan Report: `{result.source}`\n")
    lines.append(
        f"**Files scanned:** {result.files_scanned}  "
        f"**Total findings:** {result.total_findings}  "
        f"**Max risk:** {result.max_risk or 'none'}\n"
    )
    # WHERE THE SCANNER DID NOT LOOK — M0. Printed on EVERY dir report, including the
    # clean one and including runs where nothing was pruned, because a list that never
    # fires is exactly the list nobody re-derives. Three numbers with distinct units:
    # names specified, names matched, directories pruned. `dirs_pruned` counts
    # DIRECTORIES — the walk never descends into a pruned one, so the files beneath are
    # never enumerated and cannot honestly be counted.
    matched = ", ".join(f"`{n}`" for n in result.exclusion_names_matched) or "none"
    lines.append(
        f"**Directory exclusions:** {len(result.exclusion_names_matched)} of "
        f"{result.exclusions_specified} name(s) matched ({matched}), pruning "
        f"{result.dirs_pruned} director(ies). Files beneath a pruned directory were "
        "never enumerated or scanned.\n"
    )
    lines.append("---\n")

    for r in result.results:
        if r.findings:
            lines.append(_format_single(r))
            lines.append("\n---\n")

    if result.total_findings == 0:
        lines.append("✅ No findings across all files.\n")

    return "\n".join(lines)

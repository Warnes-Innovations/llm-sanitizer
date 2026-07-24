# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Redaction engine — produce cleaned content from scan findings."""

from __future__ import annotations

from llm_sanitizer.models import Finding, ScanResult


def _replacement_text(finding: Finding, mode: str) -> str:
    """The text that replaces a finding's matched span for a given mode."""
    if mode == "strip":
        return ""
    if mode == "comment":
        return (
            f"[REDACTED: LLM instruction removed "
            f"({finding.rule}, {finding.risk.name})]"
        )
    return _highlight_marker(finding)


def _highlight_marker(finding: Finding) -> str:
    """Visible warning marker wrapping the matched text."""
    return f"\u26a0\ufe0f[LLM-INSTRUCTION: {finding.matched}]\u26a0\ufe0f"


def _finding_offset(content: str, finding: Finding) -> int | None:
    r"""Best-effort absolute start offset of ``finding.matched_raw`` in
    ``content``, anchored at the finding's recorded (line, column).

    Two line-numbering schemes are in use across the rules: line-oriented
    rules index with ``content.splitlines()``, while whole-content rules
    (comment_directive, agent_config, system_prompt) compute the line as
    ``content[:start].count("\n")``. Both are tried, and each candidate is
    accepted only if the slice at that offset actually equals ``matched_raw``.
    Returns None when neither verifies (e.g. bare ``\r`` / Unicode line
    separators that make the schemes disagree), so the caller can fall back
    to occurrence-based replacement rather than edit the wrong span.
    """
    raw = finding.matched_raw
    if not raw:
        return None
    line_idx = finding.location.line - 1
    col_idx = finding.location.column - 1
    if line_idx < 0 or col_idx < 0:
        return None

    # Scheme A \u2014 splitlines(keepends=True): the line-oriented rules index the
    # separator-stripped lines, and keepends round-trips content exactly, so a
    # prefix-length sum gives the absolute start of the line.
    keep = content.splitlines(keepends=True)
    if line_idx < len(keep):
        start = sum(len(x) for x in keep[:line_idx]) + col_idx
        if content[start:start + len(raw)] == raw:
            return start

    # Scheme B \u2014 newline-only counting: walk to the start of the line_idx-th
    # "\n"-delimited line, matching the whole-content rules' own arithmetic.
    cursor = 0
    for _ in range(line_idx):
        nxt = content.find("\n", cursor)
        if nxt == -1:
            return None
        cursor = nxt + 1
    start = cursor + col_idx
    if content[start:start + len(raw)] == raw:
        return start

    return None


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

    # Each finding is edited AT its recorded location, not at the first
    # occurrence of its matched text anywhere in the document — a repeated
    # match string (e.g. a benign copy in a code sample alongside a flagged
    # copy) must not cause the wrong copy to be redacted. Coordinate-anchored
    # edits are applied right-to-left so earlier offsets stay valid; findings
    # whose location can't be verified against their matched text fall back to
    # first-occurrence replacement (the original behavior).
    anchored: list[tuple[int, int, str]] = []
    unanchored: list[Finding] = []
    for finding in result.findings:
        if not finding.matched_raw:
            continue
        offset = _finding_offset(content, finding)
        if offset is None:
            unanchored.append(finding)
        else:
            anchored.append((
                offset,
                offset + len(finding.matched_raw),
                _replacement_text(finding, mode),
            ))

    redacted = content
    # Apply from the end of the document backwards. Skip any edit whose span
    # overlaps one already applied to its right (this also drops exact
    # duplicates); the iterating redact_content re-scan picks up anything
    # skipped this pass.
    anchored.sort(key=lambda e: e[0], reverse=True)
    prev_start = len(content)
    for start, end, replacement in anchored:
        if end > prev_start:
            continue
        redacted = redacted[:start] + replacement + redacted[end:]
        prev_start = start

    for finding in unanchored:
        if finding.matched_raw in redacted:
            redacted = redacted.replace(
                finding.matched_raw, _replacement_text(finding, mode), 1
            )

    return redacted


def redact_content(
    content: str,
    mode: str = "strip",
    source: str = "<inline>",
    sensitivity: str = "medium",
    max_passes: int = 10,
) -> tuple[str, ScanResult]:
    """Scan *content*, redact findings, then re-scan until stable or *max_passes* reached.

    Iterating is necessary for layered attacks such as zero-width-interleaved
    instructions: the first pass strips invisible characters, exposing plain
    instruction text that the second pass then neutralises.

    Returns a tuple of (redacted_text, combined_result) where combined_result
    contains all findings from every pass so callers have a complete picture of
    what was detected and removed.
    """
    from llm_sanitizer.scanner import _build_summary, scan_text

    all_findings: list[Finding] = []
    first_result = scan_text(content, source=source, sensitivity=sensitivity)
    all_findings.extend(first_result.findings)
    current = redact(content, first_result, mode=mode)

    # Only "strip" benefits from re-scan-until-stable: removing one layer (e.g.
    # zero-width splitters) can expose plain instruction text underneath.
    # "comment"/"highlight" DELIBERATELY keep the matched text (as a marker), so
    # re-scanning always re-detects it — iterating those modes never converges,
    # nesting the marker max_passes deep and inflating the finding count
    # (committee MED-2). Redact them in a single pass.
    if mode == "strip":
        for _ in range(max_passes - 1):
            if current == content:
                break
            content = current
            next_result = scan_text(current, source=source, sensitivity=sensitivity)
            if not next_result.findings:
                break
            all_findings.extend(next_result.findings)
            current = redact(current, next_result, mode=mode)

    combined = first_result.model_copy(
        update={"findings": all_findings, "summary": _build_summary(all_findings)}
    )
    return current, combined


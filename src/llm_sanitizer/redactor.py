# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Redaction engine — produce cleaned content from scan findings."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from llm_sanitizer.models import Finding, ScanResult

#: Every redaction mode the engine accepts. Keep `redact`'s validation, the CLI
#: `--mode` choices and the MCP tool docstrings derived from this one tuple —
#: they drifted apart once already.
REDACTION_MODES: tuple[str, ...] = ("strip", "comment", "highlight", "placeholder")

#: The character a "placeholder" redaction substitutes, one per replaced
#: character. A FULL BLOCK (U+2588) is used rather than "*" or "X" so the
#: substitution is unmistakably a redaction and cannot itself be read as
#: content — and so it does not collide with the `*` that Markdown and glob
#: patterns give meaning to.
PLACEHOLDER_CHAR = "█"


def _replacement_text(finding: Finding, mode: str) -> str:
    """The text that replaces a finding's matched span for a given mode."""
    if mode == "strip":
        return ""
    if mode == "placeholder":
        # Same number of characters, same position — so every byte offset,
        # line number and column in the document is unchanged. That is what
        # makes this mode safe to apply to content whose structure another
        # tool has already indexed.
        #
        # KNOWN DISCLOSURE, accepted deliberately: a same-length placeholder
        # reveals the LENGTH of what it replaced. That is unimportant for
        # injected instruction text (the threat this tool redacts) but would
        # be informative for a short secret. Do not point this mode at
        # credentials without revisiting that trade-off.
        return PLACEHOLDER_CHAR * len(finding.matched_raw)
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
        mode: one of :data:`REDACTION_MODES`.

    Returns:
        Redacted text content.
    """
    if mode not in REDACTION_MODES:
        raise ValueError(
            f"Unknown redaction mode: {mode!r}. "
            f"Use one of {', '.join(repr(m) for m in REDACTION_MODES)}."
        )

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

    # Only the modes that REMOVE the matched text benefit from
    # re-scan-until-stable: peeling one layer (e.g. zero-width splitters) can
    # expose plain instruction text underneath. "comment"/"highlight"
    # DELIBERATELY keep the matched text (as a marker), so re-scanning always
    # re-detects it — iterating those modes never converges, nesting the marker
    # max_passes deep and inflating the finding count (committee MED-2). Redact
    # them in a single pass.
    #
    # "placeholder" belongs with "strip", not with the marker modes: the
    # matched text is gone (replaced by block characters), so the loop
    # converges, and a layered attack needs the same peeling.
    if mode in ("strip", "placeholder"):
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


# --- File-level redaction policy (issue #51) ---------------------------------
#
# ONE implementation, deliberately. Before this existed, the "what do we write
# for a binary input" decision was made independently at seven `shutil.copy2`
# call sites across server.py and cli.py, each with its own copy of the same
# comment, and each copying the ORIGINAL BYTES to the caller's output path
# while reporting success. Every redact entry point now routes through
# `redact_file_to` so the policy cannot diverge again. Do not re-inline this
# decision into a caller.


@dataclass(frozen=True)
class RedactedFile:
    """What a redact path actually did with one input file.

    `written` is the only field that means "there is an output file". A caller
    must never infer that from `status == "ok"` or from the output path being
    present in the response — that inference is precisely what issue #51 was.
    """

    source: str
    written: bool
    output_path: str | None
    #: "text" when the output is the input's own redacted text; "extracted-text"
    #: when the input was binary and the output is text pulled out of it.
    output_format: str | None
    #: "text" or "binary", decided by CONTENT sniffing, never by extension.
    original_format: str
    findings_redacted: int
    refused: bool
    #: Machine-readable refusal cause: "no-extractable-text" or "binary-skipped".
    refusal_code: str | None
    refusal_reason: str | None
    #: True when the file was clean and the caller asked for affected-only
    #: output. Not a refusal: there was nothing to redact.
    skipped_clean: bool = False


def _refusal(
    source: str, code: str, reason: str, original_format: str
) -> RedactedFile:
    return RedactedFile(
        source=source,
        written=False,
        output_path=None,
        output_format=None,
        original_format=original_format,
        findings_redacted=0,
        refused=True,
        refusal_code=code,
        refusal_reason=reason,
    )


def redact_file_to(
    path: str | Path,
    output_path: str | Path,
    *,
    mode: str = "strip",
    binary_mode: str = "extract",
    sensitivity: str = "medium",
    text_suffix_for_binary: bool = False,
    skip_clean: bool = False,
) -> RedactedFile:
    """Redact one file to *output_path*, never writing unredacted binary.

    The contract, from the owner's rulings on issue #51:

    1. **The original bytes are never copied to an output path when the input
       is binary.** An unredacted copy is worse than no file, because a
       consuming protocol treats the output's existence — and even its name —
       as evidence that the content was sanitized.
    2. **The redacted extracted text is always written instead.** The scan
       already extracted that text in order to scan it; throwing it away and
       copying the original was the defect.
    3. **Refuse, writing nothing at all, only when there is no usable text** —
       extraction failed, no extractor exists for the format, the input is a
       recognized archive, or the caller passed ``binary_mode="skip"``. That is
       the genuine "cannot redact at the requested level" case, and it is much
       narrower than "the input was binary".

    A CLEAN TEXT file is still copied byte-for-byte: re-encoding content that
    nothing asked us to change would corrupt any non-UTF-8 bytes in it, and a
    clean text file is not the hazard this function exists to prevent.

    Args:
        path: The file to redact.
        output_path: Where to write. For a binary input with
            *text_suffix_for_binary*, ``.txt`` is appended so the name says
            what the bytes are.
        mode: One of :data:`REDACTION_MODES`.
        binary_mode: "extract" | "text" | "skip" — see
            ``scanner.read_scannable_content``.
        sensitivity: "low" | "medium" | "high".
        text_suffix_for_binary: Append ``.txt`` to the output name for a binary
            input. Directory mirroring sets this (the output name is derived,
            not chosen by the caller); the single-file paths do not, because
            there the caller named the output path themselves.
        skip_clean: Write nothing when the file has no findings (the CLI's
            ``--affected-only``).

    Raises:
        ExtractorUnavailableError: markitdown is required but absent. Allowed
            to propagate — a systemic coverage gap, not a per-file decision.
    """
    from llm_sanitizer.scanner import _is_binary, read_scannable_content

    src = Path(path)
    is_binary_content = binary_mode != "text" and _is_binary(src)
    original_format = "binary" if is_binary_content else "text"

    content = read_scannable_content(src, binary_mode=binary_mode)
    if content is None:
        if binary_mode == "skip":
            return _refusal(
                str(path),
                "binary-skipped",
                f"binary content and binary_mode='skip': {path} was never read, "
                "so nothing could be redacted and no output was written",
                original_format,
            )
        return _refusal(
            str(path),
            "no-extractable-text",
            f"no extractable text from {path} (unsupported or failed extractor, "
            "a recognized archive, or an archive bomb): the content was never "
            "scanned, so it cannot be redacted and no output was written",
            original_format,
        )

    clean, result = redact_content(
        content, mode=mode, source=str(path), sensitivity=sensitivity
    )
    findings = result.summary.total_findings

    if skip_clean and findings == 0:
        return RedactedFile(
            source=str(path),
            written=False,
            output_path=None,
            output_format=None,
            original_format=original_format,
            findings_redacted=0,
            refused=False,
            refusal_code=None,
            refusal_reason=None,
            skipped_clean=True,
        )

    out = Path(output_path)
    if is_binary_content and text_suffix_for_binary:
        # Append rather than replace the suffix: "report.pdf" ->
        # "report.pdf.txt" keeps the original name visible, and replacing it
        # would map "a.pdf" and "a.docx" onto the same output.
        #
        # A source directory holding BOTH "report.pdf" and a real
        # "report.pdf.txt" still collides. Callers iterate in sorted order, so
        # the genuine text file is written second and wins — the safe way
        # round, since it is the file that was actually redacted as itself.
        out = out.with_name(out.name + ".txt")
    out.parent.mkdir(parents=True, exist_ok=True)

    if not is_binary_content and findings == 0:
        # Byte-exact passthrough for an untouched text file. This is NOT the
        # binary copy-through: the content was read, scanned and found clean,
        # and copying preserves an encoding that `errors="replace"` would
        # otherwise mangle on the way back out.
        shutil.copy2(src, out)
        return RedactedFile(
            source=str(path),
            written=True,
            output_path=str(out),
            output_format="text",
            original_format=original_format,
            findings_redacted=0,
            refused=False,
            refusal_code=None,
            refusal_reason=None,
        )

    out.write_text(clean, encoding="utf-8")
    return RedactedFile(
        source=str(path),
        written=True,
        output_path=str(out),
        output_format="extracted-text" if is_binary_content else "text",
        original_format=original_format,
        findings_redacted=findings,
        refused=False,
        refusal_code=None,
        refusal_reason=None,
    )


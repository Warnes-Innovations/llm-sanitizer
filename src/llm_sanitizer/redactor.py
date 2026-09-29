# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Redaction engine — produce cleaned content from scan findings."""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from llm_sanitizer.models import Finding, ScanResult

if TYPE_CHECKING:
    from llm_sanitizer.binary_redactors import BinaryRedaction

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
    rescans = mode in ("strip", "placeholder")
    # CONVERGED MEANS A RE-SCAN CAME BACK EMPTY — nothing weaker. 0.7.1 also
    # stopped when the text merely stopped CHANGING, or when the pass budget ran
    # out, and returned the result as if clean. A finding redaction cannot
    # anchor (homoglyph's normalised span never occurs in the original) leaves
    # the text unchanged AND the payload in place (0.7.2 fix, ported from the
    # redesign branch).
    converged = not first_result.findings
    if not rescans:
        # Single-pass modes keep the matched text as a marker, so a re-scan
        # always re-detects it and cannot be the test. Ask instead whether
        # each finding could be placed at its own location; one that could
        # not was never acted on.
        # And a budget refusal (input_too_large, scan_timeout, the scanner's own
        # rescan_incomplete) means the text was never fully examined, which no
        # marker can fix — strip mode already treated these as residue; the
        # marker modes wrote the file with exit 0 (0.7.2 review, pass 2).
        from llm_sanitizer.rules import integrity

        never_examined = {
            integrity.INPUT_TOO_LARGE, integrity.SCAN_TIMEOUT, integrity.RESCAN_INCOMPLETE,
        }
        converged = not [
            f for f in first_result.findings
            if (f.matched_raw and f.location.line != 0
                and _finding_offset(content, f) is None)
            or f.rule in never_examined
        ]
        if converged and first_result.findings:
            # LOCATED IS NOT APPLIED. `redact()` skips an edit that overlaps an
            # earlier one, so a finding can be placeable and still left in the
            # output (0.7.2 review, pass 3). The text a marker mode leaves
            # OUTSIDE its markers is exactly what strip mode leaves after the
            # same edits — so re-scan that. Anything text-anchored left there
            # is payload the markers did not cover.
            outside = redact(content, first_result, mode="strip")
            converged = not [
                f for f in scan_text(outside, source=source, sensitivity=sensitivity).findings
                if f.location.line != 0
            ]
    else:
        original = content
        for _ in range(max_passes - 1):
            if current == content:
                break  # stable is NOT clean — fall through to the residual scan
            content = current
            next_result = scan_text(current, source=source, sensitivity=sensitivity)
            if not next_result.findings:
                converged = True
                break
            all_findings.extend(next_result.findings)
            current = redact(current, next_result, mode=mode)
        content = original

    if not converged:
        from llm_sanitizer.rules.integrity import (
            INPUT_TOO_LARGE,
            RESCAN_INCOMPLETE,
            SCAN_TIMEOUT,
            make_integrity_finding,
        )

        residual = scan_text(current, source=source, sensitivity=sensitivity)
        # A PATH-anchored finding (line 0, matched == source: the
        # legitimate-file marker, most integrity facts) describes the file and
        # has nothing in the text to remove; counting it as residue would call
        # every clean CLAUDE.md unsanitised. The budget refusals are the
        # exception — they mean the text was never fully examined.
        incomplete = {INPUT_TOO_LARGE, SCAN_TIMEOUT, RESCAN_INCOMPLETE}
        actionable = [
            f for f in residual.findings
            if not (f.location.line == 0 and f.matched == source)
            or f.rule in incomplete
        ]
        if actionable:
            if rescans:
                all_findings.extend(actionable)
            all_findings.append(
                make_integrity_finding(
                    RESCAN_INCOMPLETE,
                    source,
                    f"Redaction did not converge: {len(actionable)} finding(s) "
                    "REMAIN IN THE OUTPUT. The written content is not clean; do "
                    "not treat it as sanitised.",
                    finding_id=len(all_findings) + 1,
                )
            )

    combined = first_result.model_copy(
        update={"findings": all_findings, "summary": _build_summary(all_findings)}
    )
    return current, combined


NOT_FULLY_SCANNED_MESSAGE = (
    "the content was not fully scanned (it exceeded the scan size or time "
    "budget), so it cannot be verified clean and no output was written."
)


def refusal_for(result: ScanResult) -> tuple[str, str]:
    """(refusal_code, message) for an unclean result, naming the real cause."""
    triggered = set(result.summary.rules_triggered)
    if triggered & {"input_too_large", "scan_timeout"}:
        return "not-fully-scanned", NOT_FULLY_SCANNED_MESSAGE
    return "not-converged", NOT_CONVERGED_MESSAGE


NOT_CONVERGED_MESSAGE = (
    "redaction did not converge: the redacted text still contains at least one "
    "finding (e.g. an injection that could not be located in the original "
    "text), so no output was written. Inspect it with the scan tools."
)


def not_converged(result: ScanResult) -> bool:
    """True when `redact_content` reported that its output is not clean."""
    return "rescan_incomplete" in result.summary.rules_triggered


# --- File-level redaction policy (issue #51) ---------------------------------
#
# ONE implementation, deliberately. Before this existed, the "what do we write
# for a binary input" decision was made independently at seven `shutil.copy2`
# call sites across server.py and cli.py, each with its own copy of the same
# comment, and each copying the ORIGINAL BYTES to the caller's output path
# while reporting success. Every redact entry point now routes through
# `redact_file_to` so the policy cannot diverge again. Do not re-inline this
# decision into a caller.


class OutputOverlapError(ValueError):
    """The requested output overlaps the source; nothing was written."""


def _same(a: Path, b: Path) -> bool:
    try:
        return a.exists() and b.exists() and a.samefile(b)
    except OSError:
        return False




def _output_refusal(
    src: Path, out: Path, source_root: Path | None, output_root: Path | None = None
) -> RedactedFile | None:
    """Refuse an output that would land on the source, judged on the RESOLVED path.

    REGRESSION (0.7.2 review): `-o src/nope/../a.md` names `src/a.md`, and a
    link already present in an output directory can point anywhere; comparing
    the requested path let both write over originals. Resolving first closes
    both. With *source_root* (directory mode) an output resolving anywhere
    inside the source tree is refused too — that is how a planted
    `out/sub -> src` would have written new files into the source.
    """
    from llm_sanitizer.scanner import path_within

    resolved = Path(os.path.realpath(out))
    if _same(src, resolved):
        return _refusal(
            str(src), "output-is-source",
            f"output {out!s} resolves to the source file itself; refusing to "
            "overwrite the original",
            "text",
        )
    if source_root is not None and path_within(resolved, source_root):
        return _refusal(
            str(src), "output-inside-source",
            f"output {out!s} resolves to {resolved}, inside the source tree; "
            "refusing to write into the input",
            "text",
        )
    if output_root is not None and not path_within(resolved, output_root):
        # A directory symlink planted in the output tree resolved this write
        # somewhere else entirely — it overwrote an unrelated file (0.7.2
        # review, pass 2). A mirror entry must stay inside the mirror.
        return _refusal(
            str(src), "output-escapes-root",
            f"output {out!s} resolves to {resolved}, outside the output "
            "directory; refusing to write there",
            "text",
        )
    return None


def publish_text(out: str | Path, text: str) -> None:
    """Write *text* to *out* the same way every redact output is written.

    For writers that have no source file (stdin, a URL): they still must not
    write THROUGH a link or into a FIFO sitting at the output path (0.7.2
    review, pass 2 — both did).
    """
    _publish(Path(out), text.encode("utf-8"))


def _publish(out: Path, data: bytes, *, copystat_from: Path | None = None) -> None:
    """Write *data* via a temp file in the same directory, then `os.replace` it in.

    `os.replace` swaps the DIRECTORY ENTRY: a symlink or hardlink already
    sitting at *out* is replaced, never written through. Writing in place
    followed such links onto whatever they pointed at (0.7.2 review). The bytes
    go through the descriptor `O_EXCL` created — never a re-open by name, which
    left a window for the temp path to be swapped (review pass 2). Created with
    mode 0o666 so the umask applies, as for an ordinary write.
    """
    tmp = out.with_name(f".{out.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if copystat_from is not None:
            shutil.copystat(copystat_from, tmp)
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def refuse_overlapping_output(source: str | Path, output: str | Path) -> None:
    """Raise OutputOverlapError if a directory redaction's output overlaps its source.

    REGRESSION (0.7.2): output == source overwrote every original with its
    redacted text and reported success; output inside the source re-ingested
    its own earlier output on the next run; source inside the output let the
    mirror overwrite the input. Checked before anything is created or written.
    Do not reduce this to a path-string comparison — see `scanner.path_within`.
    """
    from llm_sanitizer.scanner import path_within

    src, out = Path(source), Path(output)
    if path_within(out, src) or path_within(src, out):
        raise OutputOverlapError(
            f"output {output!s} overlaps source {source!s} (same directory, or "
            "one inside the other); refusing so the originals are not "
            "overwritten. Choose an output directory outside the source."
        )


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
    #: Where a VERIFIED-clean rewrite of the original binary was written, if one
    #: was possible. None is the normal case and never means "the text output is
    #: untrustworthy" — the text output stands on its own.
    redacted_binary_path: str | None = None
    #: "ok" | "unavailable" | "refused" | "not-applicable" — see
    #: llm_sanitizer.binary_redactors. "refused" specifically means a rewrite
    #: was produced, FAILED verification and was deleted.
    binary_redaction: str = "not-applicable"
    binary_redaction_detail: str | None = None


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
    source_root: Path | None = None,
    output_root: Path | None = None,
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
    from llm_sanitizer.scanner import (
        require_admitted,
    )

    src = Path(path)
    # Admission BEFORE any open: a FIFO blocks forever on open (0.7.2). Raises
    # an OSError, so a named path is a caller error (exit 2) and a directory
    # loop records the file as refused. `source_root` re-applies the walk's
    # symlink-escape rule to a file swapped after the walk admitted it.
    require_admitted(src, source_root)
    refusal = _output_refusal(src, Path(output_path), source_root, output_root)
    if refusal is not None:
        return refusal
    if _same(src, Path(output_path)):
        # Writing the redacted text over the input would destroy the original
        # (0.7.2 regression fix). A refusal, not an exception: no file written.
        return _refusal(
            str(path),
            "output-is-source",
            f"output path {output_path!s} is the source file itself; refusing "
            "to overwrite the original",
            "text",
        )
    # PUBLISH WHAT WAS SCANNED. Everything below reads one private snapshot
    # of the source, taken right after admission: re-opening the source to
    # copy or rewrite it published whatever was there by then, which a swap
    # after the scan made unscanned bytes (0.7.2 review, pass 2).
    snapdir = Path(tempfile.mkdtemp(prefix="llm-sanitizer-snap-"))
    try:
        snap = snapdir / src.name
        _snapshot(src, snap)
        return _redact_snapshot(
            path, src, snap, Path(output_path),
            mode=mode, binary_mode=binary_mode, sensitivity=sensitivity,
            text_suffix_for_binary=text_suffix_for_binary, skip_clean=skip_clean,
            source_root=source_root, output_root=output_root,
        )
    finally:
        shutil.rmtree(snapdir, ignore_errors=True)


def _snapshot(src: Path, snap: Path) -> None:
    """Copy *src* to *snap* through ONE descriptor, checked after opening.

    O_NONBLOCK so a file swapped for a FIFO after admission cannot block the
    open, and `fstat` on the descriptor itself — not the path — so the check
    describes the file actually being read.
    """
    from llm_sanitizer.scanner import PathNotAdmittedError, WalkIssue

    fd = os.open(src, os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PathNotAdmittedError(WalkIssue(
                src, "not-regular-file",
                "not a regular file when opened (changed after admission); not read",
            ))
        with os.fdopen(fd, "rb", closefd=False) as fin, open(snap, "wb") as fout:
            shutil.copyfileobj(fin, fout)
    finally:
        os.close(fd)
    shutil.copystat(src, snap)


def _redact_snapshot(
    path: str | Path,
    src: Path,
    snap: Path,
    output_path: Path,
    *,
    mode: str,
    binary_mode: str,
    sensitivity: str,
    text_suffix_for_binary: bool,
    skip_clean: bool,
    source_root: Path | None,
    output_root: Path | None,
) -> RedactedFile:
    """The body of `redact_file_to`, reading only the snapshot *snap*.

    *src* is the real source, used only for identity checks against outputs.
    """
    from llm_sanitizer.scanner import _is_binary, read_scannable_content

    is_binary_content = binary_mode != "text" and _is_binary(snap)
    original_format = "binary" if is_binary_content else "text"

    content = read_scannable_content(snap, binary_mode=binary_mode)
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

    raw = snap.read_bytes()
    clean, result = redact_content(
        content, mode=mode, source=str(path), sensitivity=sensitivity
    )
    if not is_binary_content:
        from llm_sanitizer.scanner import legacy_byte_findings

        hidden = legacy_byte_findings(raw, result.findings, str(path), sensitivity)
        if hidden:
            # A payload only a Latin-1 reading of the invalid bytes shows: the
            # UTF-8 text cannot be redacted to remove it, and a clean copy
            # would publish the bytes byte-for-byte (0.7.2 review, pass 3).
            return _refusal(
                str(path), "hidden-in-invalid-bytes",
                "the bytes that are not valid UTF-8 read, in Latin-1, as text "
                f"that trips {', '.join(sorted({f.rule for f in hidden}))}; no "
                "output was written.",
                original_format,
            )
    if not_converged(result):
        # The output would still carry a finding. Write NOTHING: an output
        # file's existence is read downstream as "sanitised" (#51), so an
        # unclean one is worse than none (Dr. Greg, 2026-09-28).
        code, message = refusal_for(result)
        return _refusal(str(path), code, message, original_format)
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
    # AGAIN, on the FINAL path, after mkdir and the suffix: the check above ran
    # on the requested path, and the path actually written can differ.
    refusal = _output_refusal(src, out, source_root, output_root)
    if refusal is not None:
        return refusal

    if not is_binary_content and findings == 0:
        # Byte-exact passthrough for an untouched text file. This is NOT the
        # binary copy-through: the content was read, scanned and found clean,
        # and copying preserves an encoding that `errors="replace"` would
        # otherwise mangle on the way back out.
        _publish(out, snap.read_bytes(), copystat_from=snap)
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

    _publish(out, clean.encode("utf-8"))

    # ALSO rewrite the original format where that is possible and provable.
    # This never changes what `out` holds and never gates it: the redacted text
    # is the contract, and the binary rewrite is an extra artifact for callers
    # who need the original format back. A rewrite that cannot be PROVED clean
    # is not written at all (see binary_redactors), so its absence is safe and
    # its presence is verified.
    binary = _maybe_redact_binary_in_place(
        snap, out, result.findings, mode=mode, sensitivity=sensitivity
    )

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
        redacted_binary_path=binary.output_path,
        binary_redaction=binary.status,
        binary_redaction_detail=binary.detail or None,
    )


def _maybe_redact_binary_in_place(
    src: Path,
    text_out: Path,
    findings: Sequence[Finding],
    *,
    mode: str,
    sensitivity: str,
) -> BinaryRedaction:
    """Try to write a verified-clean rewrite of *src* in its own format.

    Placed beside the text output as ``<stem>.redacted<suffix>`` — derived from
    the SOURCE name, not from the text output's, so a directory mirror's
    ``report.pdf.txt`` does not yield ``report.pdf.redacted.pdf``.
    """
    from llm_sanitizer.binary_redactors import BinaryRedaction as _BR
    from llm_sanitizer.binary_redactors import is_pdf, redact_pdf_in_place

    if not findings or not is_pdf(src):
        return _BR("not-applicable", "")
    target = text_out.with_name(f"{src.stem}.redacted{src.suffix or '.pdf'}")
    return redact_pdf_in_place(
        src, target, findings, mode=mode, sensitivity=sensitivity
    )


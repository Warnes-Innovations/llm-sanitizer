# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP server for llm-sanitizer — 9 tools for scanning and redacting LLM instructions."""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(
    "llm-sanitizer",
    instructions="Scan documents, source code, and web pages for embedded LLM agent instructions. "
    "Classify findings by risk level and optionally redact them.",
)


# --- Scan tools ---


@mcp.tool()
def scan_text(content: str, sensitivity: str = "medium") -> str:
    """Scan inline text content for embedded LLM instructions.

    Args:
        content: The text content to scan.
        sensitivity: Detection sensitivity — "low", "medium", or "high".

    Returns:
        JSON string with findings report.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.scanner import Scanner

    result = Scanner().scan(content, source="<inline>", sensitivity=sensitivity)
    return format_json(result)


@mcp.tool()
def scan_file(path: str, sensitivity: str = "medium", binary_mode: str = "extract") -> str:
    """Scan a local file for embedded LLM instructions.

    Supports text, markdown, HTML, source code, and (with markitdown) PDF/DOCX.
    Binary-ness and archive type are detected from file content, not the
    extension, so renaming a file cannot change how it is classified.
    Recognized archives (zip/tar/gz/bz2/xz, plus 7z/rar with the optional
    extras) are expanded and their members recursively scanned; an archive
    whose declared type doesn't match its content, that is corrupt, or that
    needs an uninstalled tool yields a CRITICAL finding rather than being
    silently mis-scanned.

    Args:
        path: Absolute or relative path to the file to scan.
        sensitivity: Detection sensitivity — "low", "medium", or "high".
        binary_mode: How to handle content sniffed as binary — "extract"
            (default; pull embedded text via markitdown and expand archives),
            "text" (force raw bytes to be scanned as literal UTF-8 text —
            use when a file's extension is suspected of being swapped to
            evade extraction/skipping), or "skip" (never read binary
            content).

    Returns:
        JSON string with findings report, or {"status": "error", ...} if
        the file could not be read or yielded no scannable text content.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.scanner import ExtractorUnavailableError, Scanner

    try:
        result = Scanner().scan_file(
            path, sensitivity=sensitivity, binary_mode=binary_mode
        )
    except ExtractorUnavailableError as exc:
        return json.dumps({"status": "error", "message": exc.hint})
    except (OSError, ImportError, RuntimeError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})
    if result is None:
        return json.dumps({
            "status": "error",
            "message": f"No scannable text content (binary file, binary_mode={binary_mode!r}): {path}",
        })

    return format_json(result)


@mcp.tool()
def scan_url(url: str, sensitivity: str = "medium") -> str:
    """Fetch and scan a web page for embedded LLM instructions.

    Args:
        url: The URL to fetch and scan.
        sensitivity: Detection sensitivity — "low", "medium", or "high".

    Returns:
        JSON string with findings report. On refusal — a binary document whose
        text could not be extracted — `{"status": "error", "error_type":
        "unscannable", "refusal_code": "no-extractable-text", ...}` and no
        report, mirroring redact_file's refusal shape.

        NOTE (#53): a PDF/DOCX URL now yields a report of the document's TEXT.
        It previously yielded findings matched against the container's bytes —
        typically CRITICAL homoglyph hits on font-width arrays — so verdicts on
        such URLs have moved, by design.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.readers.url_reader import FetchBlockedError, read_url
    from llm_sanitizer.scanner import Scanner

    try:
        content = read_url(url)
    except FetchBlockedError as exc:
        # The remote server refused the fetch (WAF/4xx) — distinct from a
        # scan failure: the caller cannot verify this page and should route
        # it to human review, not treat it as "the scanner is broken" (#19).
        return json.dumps({
            "status": "error",
            "error_type": "fetch_blocked",
            "http_status": exc.status_code,
            "message": str(exc),
        })
    except RuntimeError as exc:
        return json.dumps({"status": "error", "message": str(exc)})

    if content is None:
        # No usable text. Refusing is the point: reporting zero findings here
        # would be a clean verdict on a document that was never read (#53).
        return json.dumps({
            "status": "error",
            "error_type": "unscannable",
            "refusal_code": "no-extractable-text",
            "source": url,
            "message": (
                f"no extractable text from {url} (a binary document no "
                "extractor could read, or one that extracted to nothing): the "
                "content was never scanned, so no report is given"
            ),
        })

    result = Scanner().scan(content, source=url, sensitivity=sensitivity)
    return format_json(result)


@mcp.tool()
def scan_dir(
    path: str,
    glob: str = "**/*",
    sensitivity: str = "medium",
    binary_mode: str = "extract",
) -> str:
    """Recursively scan a directory for embedded LLM instructions.

    Args:
        path: Path to the directory to scan.
        glob: File pattern filter, e.g. "**/*.md". Defaults to all files.
        sensitivity: Detection sensitivity — "low", "medium", or "high".
        binary_mode: How to handle content sniffed as binary (by content,
            not extension) — "extract" (default; pull embedded text via
            markitdown), "text" (force raw bytes to be scanned as literal
            text — use when a file's extension is suspected of being
            swapped to evade extraction/skipping), or "skip" (exclude
            binary files from the scan entirely).

    Returns:
        JSON string with aggregated findings report.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.scanner import ExtractorUnavailableError, Scanner

    try:
        result = Scanner().scan_dir(
            path, glob_pattern=glob, sensitivity=sensitivity, binary_mode=binary_mode
        )
    except ExtractorUnavailableError as exc:
        return json.dumps({"status": "error", "message": exc.hint})
    except (OSError, RuntimeError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})

    return format_json(result)


# --- Redact tools ---


@mcp.tool()
def redact(content: str, mode: str = "strip", sensitivity: str = "medium") -> str:
    """Redact embedded LLM instructions from inline text content.

    Scans and redacts iteratively until the content is stable — a single
    pass can expose new findings (e.g. stripping zero-width characters
    reveals plain instruction text underneath).

    Args:
        content: The text content to redact.
        mode: Redaction mode — "strip" (remove), "comment" (replace with marker),
              "highlight" (wrap in visible markers), or "placeholder" (replace
              each character with a block character, so the text is removed
              while every offset, line number and column stays put).
        sensitivity: Detection sensitivity ("low" | "medium" | "high") —
              use the same value as the scan call so redaction removes
              everything the scan reported.

    Returns:
        Cleaned text content on success. On invalid input the tool raises, which
        the MCP layer surfaces as a tool error — so an error is never confusable
        with a successful redaction whose cleaned text merely happens to be JSON
        (committee H4). (Previously the error path returned a JSON string that a
        caller could not distinguish from cleaned content.)
    """
    from llm_sanitizer.redactor import redact_content

    # Let ValueError propagate: MCPServer returns it as an MCP error response,
    # which is distinguishable from a successful text return. Do NOT catch it
    # and return a look-alike JSON string.
    clean, _ = redact_content(
        content, mode=mode, source="<inline>", sensitivity=sensitivity
    )
    return clean


@mcp.tool()
def redact_file(
    path: str,
    output_path: str,
    mode: str = "strip",
    binary_mode: str = "extract",
    sensitivity: str = "medium",
) -> str:
    """Redact a file and write a clean copy to the output path.

    Scans and redacts iteratively until the content is stable — a single
    pass can expose new findings (e.g. stripping zero-width characters
    reveals plain instruction text underneath).

    **A binary input never yields binary output.** The scan has to extract the
    document's text in order to scan it, so that redacted text is what gets
    written, and the response says so via `output_format: "extracted-text"`.
    The original bytes are never copied to `output_path`. When there is no
    usable text at all — no extractor for the format, extraction failed, or
    `binary_mode="skip"` — the tool REFUSES: `status: "error"` with
    `error_type: "unredactable"`, and **no output file is created**, so a
    caller that treats the output's existence as evidence cannot be fooled.

    Args:
        path: Path to the file to redact.
        output_path: Path where the clean copy will be written. For a binary
            input this receives UTF-8 text, so name it `.txt`.
        mode: Redaction mode — "strip", "comment", "highlight", or
            "placeholder" (replace each character of the matched text with a
            block character, preserving length, line numbers and columns).
        binary_mode: How to handle content sniffed as binary (by content,
            not extension) — "extract" (default; pull embedded text via
            markitdown), "text" (force raw bytes to be scanned as literal
            text), or "skip" (never read binary content — which now means
            the call is refused rather than passing the file through).
        sensitivity: Detection sensitivity ("low" | "medium" | "high") —
            use the same value as the scan call so redaction removes
            everything the scan reported.

    Returns:
        JSON string. On success: `status`, `source`, `output_path`,
        `output_format` ("text" | "extracted-text"), `original_format`
        ("text" | "binary") and `findings_redacted` — which now counts
        findings REMOVED, not findings left behind. On refusal:
        `{"status": "error", "error_type": "unredactable", ...}` with no file
        written.
    """
    from llm_sanitizer.redactor import redact_file_to

    try:
        outcome = redact_file_to(
            path,
            output_path,
            mode=mode,
            binary_mode=binary_mode,
            sensitivity=sensitivity,
        )
    except (OSError, ImportError, RuntimeError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})

    if outcome.refused:
        return json.dumps({
            "status": "error",
            "error_type": "unredactable",
            "refusal_code": outcome.refusal_code,
            "source": path,
            "output_written": False,
            "message": outcome.refusal_reason,
        })
    return json.dumps({
        "status": "ok",
        "source": path,
        "output_path": outcome.output_path,
        "output_format": outcome.output_format,
        "original_format": outcome.original_format,
        "findings_redacted": outcome.findings_redacted,
        "redacted_binary_path": outcome.redacted_binary_path,
        "binary_redaction": outcome.binary_redaction,
        "binary_redaction_detail": outcome.binary_redaction_detail,
    })


@mcp.tool()
def redact_url(url: str, output_path: str, mode: str = "strip", sensitivity: str = "medium") -> str:
    """Fetch a URL, redact its content, and write a clean copy to a local file.

    Scans and redacts iteratively until the content is stable — a single
    pass can expose new findings (e.g. stripping zero-width characters
    reveals plain instruction text underneath).

    Args:
        url: The URL to fetch and redact.
        output_path: Local path where the clean content will be written.
        mode: Redaction mode — "strip", "comment", or "highlight".
        sensitivity: Detection sensitivity ("low" | "medium" | "high") —
            use the same value as the scan call so redaction removes
            everything the scan reported.

    Returns:
        JSON string with status and output path. On refusal — a binary document
        whose text could not be extracted — `{"status": "error", "error_type":
        "unredactable", "refusal_code": "no-extractable-text",
        "output_written": false, ...}` and NO file is written.

        NOTE (#53): for a PDF/DOCX URL the output is now the redacted EXTRACTED
        TEXT of the document. It was previously the redacted decoding of the
        container's bytes.
    """
    from llm_sanitizer.readers.url_reader import FetchBlockedError
    from llm_sanitizer.readers.url_reader import read_url as _read_url
    from llm_sanitizer.redactor import redact_content

    try:
        content = _read_url(url)
        if content is None:
            # Same contract as redact_file: refuse, and write NOTHING. An
            # output file's mere existence is read downstream as evidence that
            # the content was sanitized (#51), so a file here would be worse
            # than no file at all.
            return json.dumps({
                "status": "error",
                "error_type": "unredactable",
                "refusal_code": "no-extractable-text",
                "source": url,
                "output_written": False,
                "message": (
                    f"no extractable text from {url} (a binary document no "
                    "extractor could read, or one that extracted to nothing): "
                    "the content was never scanned, so it cannot be redacted "
                    "and no output was written"
                ),
            })
        clean, result = redact_content(
            content, mode=mode, source=url, sensitivity=sensitivity
        )
        Path(output_path).write_text(clean, encoding="utf-8")
        return json.dumps({
            "status": "ok",
            "source": url,
            "output_path": output_path,
            "findings_redacted": result.summary.total_findings,
        })
    except FetchBlockedError as exc:
        # See scan_url: distinct from a redact failure (#19).
        return json.dumps({
            "status": "error",
            "error_type": "fetch_blocked",
            "http_status": exc.status_code,
            "message": str(exc),
        })
    except (RuntimeError, OSError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})


@mcp.tool()
def redact_dir(
    path: str,
    output_dir: str,
    mode: str = "strip",
    glob: str = "**/*",
    binary_mode: str = "extract",
    sensitivity: str = "medium",
) -> str:
    """Redact a directory, mirroring its structure under the output directory.

    Clean text files pass through byte-for-byte; text files with findings are
    redacted in place in the mirror.

    **The output is NOT a drop-in replacement directory for binaries**, and
    that is deliberate (issue #51). A binary member is written as its redacted
    *extracted text* under `<name>.txt`; the original bytes are never copied,
    because an unredacted copy carrying the original's name is worse than no
    file. A member with no usable text — no extractor, failed extraction, a
    recognized archive, or `binary_mode="skip"` — is **not written at all** and
    is listed in the response's `refused` array with a reason, so nothing is
    dropped silently.

    Args:
        path: Path to the source directory.
        output_dir: Path to the output directory (will be created).
        mode: Redaction mode — "strip", "comment", "highlight", or
            "placeholder" (length-preserving block substitution).
        glob: File pattern filter. Defaults to all files.
        sensitivity: Detection sensitivity ("low" | "medium" | "high") — the
            redaction removes what a scan at THIS sensitivity reports, so a
            caller scanning at "high" must also redact at "high" or the
            output keeps findings the scan flagged. Appended last so existing
            positional callers are unaffected.
        binary_mode: How to handle content sniffed as binary (by content,
            not extension) — "extract" (default; pull embedded text via
            markitdown and write the redacted text as `<name>.txt`), "text"
            (force raw bytes to be scanned *and* redacted as literal text —
            only safe for files you already know aren't genuinely binary), or
            "skip" (never read binary content, so every binary member is
            refused rather than copied through unscanned).

    Returns:
        JSON string with `status`, `files_written`, and `refused` — a list of
        `{source, refusal_code, message}` for every input that produced no
        output.
    """
    from llm_sanitizer.redactor import redact_file_to
    from llm_sanitizer.scanner import ExtractorUnavailableError, iter_scannable_files

    src_path = Path(path)
    dst_path = Path(output_dir)

    try:
        dst_path.mkdir(parents=True, exist_ok=True)
        files_written: list[str] = []
        refused: list[dict[str, str | None]] = []

        files = iter_scannable_files(src_path, glob)

        for file_path in sorted(files):
            rel = file_path.relative_to(src_path)
            out_path = dst_path / rel
            try:
                outcome = redact_file_to(
                    file_path,
                    out_path,
                    mode=mode,
                    binary_mode=binary_mode,
                    sensitivity=sensitivity,
                    text_suffix_for_binary=True,
                )
            except OSError:
                continue
            if outcome.refused:
                refused.append({
                    "source": str(file_path),
                    "refusal_code": outcome.refusal_code,
                    "message": outcome.refusal_reason,
                })
                continue
            if outcome.written and outcome.output_path is not None:
                files_written.append(outcome.output_path)
            if outcome.redacted_binary_path is not None:
                files_written.append(outcome.redacted_binary_path)

        return json.dumps({
            "status": "ok",
            "source": path,
            "output_dir": output_dir,
            "files_written": files_written,
            "refused": refused,
        })
    except ExtractorUnavailableError as exc:
        return json.dumps({"status": "error", "message": exc.hint})
    except (OSError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})


# --- Utility tools ---


@mcp.tool()
def list_rules(category: str | None = None) -> str:
    """List detection rules and their effective configuration.

    Reflects the discovered configuration (`.llm-sanitizer.yml` in the working
    directory, if any): each rule reports whether it is currently `enabled` and
    its `effective_sensitivity`, so the output describes what actually runs
    rather than just the built-in defaults (committee M8).

    Args:
        category: Optional category filter to show only rules in that category.

    Returns:
        JSON string with rule details.
    """
    from llm_sanitizer.config import load_config
    from llm_sanitizer.rules import get_all_rules

    config = load_config()
    rules = get_all_rules()
    if category:
        rules = [r for r in rules if r.category == category]

    return json.dumps([
        {
            "id": r.rule_id,
            "name": r.rule_name,
            "category": r.category,
            "default_risk": r.default_risk.name,
            "enabled": config.is_rule_enabled(r.rule_id),
            "effective_sensitivity": config.rule_sensitivity(r.rule_id),
            "description": r.description,
        }
        for r in rules
    ], indent=2)


# --- Entry point ---


def main() -> None:
    """Start the llm-sanitizer MCP server."""
    import sys

    if "--version" in sys.argv[1:]:
        from llm_sanitizer import __version__

        print(f"llm-sanitizer {__version__}")
        return
    mcp.run()


if __name__ == "__main__":
    main()


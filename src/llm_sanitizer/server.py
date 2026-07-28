# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP server for llm-sanitizer — 9 tools for scanning and redacting LLM instructions."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
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
        JSON string with findings report.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.readers.url_reader import read_url
    from llm_sanitizer.scanner import Scanner

    try:
        content = read_url(url)
    except RuntimeError as exc:
        return json.dumps({"status": "error", "message": str(exc)})

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
              or "highlight" (wrap in visible markers).
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

    # Let ValueError propagate: FastMCP returns it as an MCP error response,
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

    Args:
        path: Path to the file to redact.
        output_path: Path where the clean copy will be written.
        mode: Redaction mode — "strip", "comment", or "highlight".
        binary_mode: How to handle content sniffed as binary (by content,
            not extension) — "extract" (default; pull embedded text via
            markitdown), "text" (force raw bytes to be scanned as literal
            text), or "skip" (never read binary content).
        sensitivity: Detection sensitivity ("low" | "medium" | "high") —
            use the same value as the scan call so redaction removes
            everything the scan reported.

    Returns:
        JSON string with status and output path, or {"status": "error", ...}
        if the file could not be read or yielded no scannable text content.
    """
    from llm_sanitizer.readers import read_file
    from llm_sanitizer.redactor import redact_content
    from llm_sanitizer.scanner import _is_binary

    try:
        content = read_file(path, binary_mode=binary_mode)
        if content is None:
            return json.dumps({
                "status": "error",
                "message": f"No scannable text content (binary file, binary_mode={binary_mode!r}): {path}",
            })
        is_binary_content = binary_mode != "text" and _is_binary(Path(path))
        if is_binary_content:
            # A binary file's *extracted* text can be scanned for findings,
            # but a redacted version of that extracted text can't be written
            # back into the original binary format — so binary files are
            # copied through unmodified rather than replaced with mangled
            # text (mirrors redact_dir's handling of the same case).
            from llm_sanitizer.scanner import Scanner

            result = Scanner().scan(content, source=path, sensitivity=sensitivity)
            shutil.copy2(path, output_path)
        else:
            clean, result = redact_content(
                content, mode=mode, source=path, sensitivity=sensitivity
            )
            Path(output_path).write_text(clean, encoding="utf-8")
        return json.dumps({
            "status": "ok",
            "source": path,
            "output_path": output_path,
            "findings_redacted": result.summary.total_findings,
        })
    except (OSError, ImportError, RuntimeError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})


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
        JSON string with status and output path.
    """
    from llm_sanitizer.readers.url_reader import read_url as _read_url
    from llm_sanitizer.redactor import redact_content

    try:
        content = _read_url(url)
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
    except (RuntimeError, OSError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})


@mcp.tool()
def redact_dir(
    path: str,
    output_dir: str,
    mode: str = "strip",
    glob: str = "**/*",
    binary_mode: str = "extract",
) -> str:
    """Redact a directory, mirroring its structure under the output directory.

    All files are copied — clean files pass through unchanged, files with
    findings are redacted. Produces a drop-in replacement directory.

    Args:
        path: Path to the source directory.
        output_dir: Path to the output directory (will be created).
        mode: Redaction mode — "strip", "comment", or "highlight".
        glob: File pattern filter. Defaults to all files.
        binary_mode: How to handle content sniffed as binary (by content,
            not extension) — "extract" (default; scan embedded text via
            markitdown but always copy the original binary through
            unchanged, since redacting extracted text can't be written back
            into e.g. a PDF), "text" (force raw bytes to be scanned *and
            redacted* as literal text — only safe for files you already
            know aren't genuinely binary), or "skip" (copy binary files
            through unscanned).

    Returns:
        JSON string with status and list of files written.
    """
    from llm_sanitizer import redactor as _redactor
    from llm_sanitizer.scanner import (
        ExtractorUnavailableError,
        Scanner,
        _is_binary,
        iter_scannable_files,
        read_scannable_content,
    )

    src_path = Path(path)
    dst_path = Path(output_dir)

    try:
        dst_path.mkdir(parents=True, exist_ok=True)
        scanner = Scanner()
        files_written: list[str] = []

        files = iter_scannable_files(src_path, glob)

        for file_path in sorted(files):
            rel = file_path.relative_to(src_path)
            out_path = dst_path / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                # A binary file's *extracted* text can be scanned for
                # findings, but a redacted version of that extracted text
                # can't be written back into the original binary format —
                # so binary files always pass through via copy2, regardless
                # of what the scan finds, unless binary_mode="text" (an
                # explicit opt-in to treat this file's raw bytes as text).
                is_binary_content = binary_mode != "text" and _is_binary(file_path)
                content = read_scannable_content(file_path, binary_mode=binary_mode)
                if content is None:
                    # Never scanned (binary_mode="skip", or "extract" with
                    # extraction unavailable/failed) — still copy the
                    # original through so it isn't silently dropped from
                    # what's meant to be a drop-in replacement directory
                    # (matches the documented --binary-mode behavior for
                    # both "skip" and "extract").
                    shutil.copy2(file_path, out_path)
                    files_written.append(str(out_path))
                    continue
                scan_result = scanner.scan(content, source=str(file_path))
                if scan_result.findings and not is_binary_content:
                    out_path.write_text(
                        _redactor.redact(content, scan_result, mode=mode),
                        encoding="utf-8",
                    )
                else:
                    shutil.copy2(file_path, out_path)
                files_written.append(str(out_path))
            except OSError:
                continue

        return json.dumps({
            "status": "ok",
            "source": path,
            "output_dir": output_dir,
            "files_written": files_written,
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


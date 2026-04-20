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
def scan_file(path: str, sensitivity: str = "medium") -> str:
    """Scan a local file for embedded LLM instructions.

    Supports text, markdown, HTML, source code, and (with markitdown) PDF/DOCX.

    Args:
        path: Absolute or relative path to the file to scan.
        sensitivity: Detection sensitivity — "low", "medium", or "high".

    Returns:
        JSON string with findings report.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.readers import read_file
    from llm_sanitizer.scanner import Scanner

    try:
        content = read_file(path)
    except (OSError, ImportError, RuntimeError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})

    result = Scanner().scan(content, source=path, sensitivity=sensitivity)
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
def scan_dir(path: str, glob: str = "**/*", sensitivity: str = "medium") -> str:
    """Recursively scan a directory for embedded LLM instructions.

    Args:
        path: Path to the directory to scan.
        glob: File pattern filter, e.g. "**/*.md". Defaults to all files.
        sensitivity: Detection sensitivity — "low", "medium", or "high".

    Returns:
        JSON string with aggregated findings report.
    """
    from llm_sanitizer.formatters.json_format import format_json
    from llm_sanitizer.scanner import Scanner

    try:
        result = Scanner().scan_dir(path, glob_pattern=glob, sensitivity=sensitivity)
    except (OSError, RuntimeError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})

    return format_json(result)


# --- Redact tools ---


@mcp.tool()
def redact(content: str, mode: str = "strip") -> str:
    """Redact embedded LLM instructions from inline text content.

    Args:
        content: The text content to redact.
        mode: Redaction mode — "strip" (remove), "comment" (replace with marker),
              or "highlight" (wrap in visible markers).

    Returns:
        Cleaned text content.
    """
    from llm_sanitizer import redactor as _redactor
    from llm_sanitizer.scanner import Scanner

    try:
        result = Scanner().scan(content, source="<inline>")
        return _redactor.redact(content, result, mode=mode)
    except ValueError as exc:
        return json.dumps({"status": "error", "message": str(exc)})


@mcp.tool()
def redact_file(path: str, output_path: str, mode: str = "strip") -> str:
    """Redact a file and write a clean copy to the output path.

    Args:
        path: Path to the file to redact.
        output_path: Path where the clean copy will be written.
        mode: Redaction mode — "strip", "comment", or "highlight".

    Returns:
        JSON string with status and output path.
    """
    from llm_sanitizer import redactor as _redactor
    from llm_sanitizer.readers import read_file
    from llm_sanitizer.scanner import Scanner

    try:
        content = read_file(path)
        result = Scanner().scan(content, source=path)
        clean = _redactor.redact(content, result, mode=mode)
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
def redact_url(url: str, output_path: str, mode: str = "strip") -> str:
    """Fetch a URL, redact its content, and write a clean copy to a local file.

    Args:
        url: The URL to fetch and redact.
        output_path: Local path where the clean content will be written.
        mode: Redaction mode — "strip", "comment", or "highlight".

    Returns:
        JSON string with status and output path.
    """
    from llm_sanitizer import redactor as _redactor
    from llm_sanitizer.readers.url_reader import read_url as _read_url
    from llm_sanitizer.scanner import Scanner

    try:
        content = _read_url(url)
        result = Scanner().scan(content, source=url)
        clean = _redactor.redact(content, result, mode=mode)
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
    path: str, output_dir: str, mode: str = "strip", glob: str = "**/*"
) -> str:
    """Redact a directory, mirroring its structure under the output directory.

    All files are copied — clean files pass through unchanged, files with
    findings are redacted. Produces a drop-in replacement directory.

    Args:
        path: Path to the source directory.
        output_dir: Path to the output directory (will be created).
        mode: Redaction mode — "strip", "comment", or "highlight".
        glob: File pattern filter. Defaults to all files.

    Returns:
        JSON string with status and list of files written.
    """
    import fnmatch

    from llm_sanitizer import redactor as _redactor
    from llm_sanitizer.scanner import Scanner

    src_path = Path(path)
    dst_path = Path(output_dir)

    try:
        dst_path.mkdir(parents=True, exist_ok=True)
        scanner = Scanner()
        files_written: list[str] = []

        files = [p for p in src_path.rglob("*") if p.is_file()]
        if glob != "**/*":
            files = [p for p in files if fnmatch.fnmatch(p.name, glob.lstrip("**/"))]

        for file_path in sorted(files):
            rel = file_path.relative_to(src_path)
            out_path = dst_path / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                scan_result = scanner.scan(content, source=str(file_path))
                if scan_result.findings:
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
    except (OSError, ValueError) as exc:
        return json.dumps({"status": "error", "message": str(exc)})


# --- Utility tools ---


@mcp.tool()
def list_rules(category: str | None = None) -> str:
    """List active detection rules and their configuration.

    Args:
        category: Optional category filter to show only rules in that category.

    Returns:
        JSON string with rule details.
    """
    from llm_sanitizer.rules import get_all_rules

    rules = get_all_rules()
    if category:
        rules = [r for r in rules if r.category == category]

    return json.dumps([
        {
            "id": r.rule_id,
            "name": r.rule_name,
            "category": r.category,
            "default_risk": r.default_risk.name,
            "description": r.description,
        }
        for r in rules
    ], indent=2)


# --- Entry point ---


def main() -> None:
    """Start the llm-sanitizer MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()


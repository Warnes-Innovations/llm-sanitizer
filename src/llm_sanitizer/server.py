# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MCP server for llm-sanitizer — 9 tools for scanning and redacting LLM instructions."""

from __future__ import annotations

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
    raise NotImplementedError("scan_text not yet implemented")


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
    raise NotImplementedError("scan_file not yet implemented")


@mcp.tool()
def scan_url(url: str, sensitivity: str = "medium") -> str:
    """Fetch and scan a web page for embedded LLM instructions.

    Args:
        url: The URL to fetch and scan.
        sensitivity: Detection sensitivity — "low", "medium", or "high".

    Returns:
        JSON string with findings report.
    """
    raise NotImplementedError("scan_url not yet implemented")


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
    raise NotImplementedError("scan_dir not yet implemented")


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
    raise NotImplementedError("redact not yet implemented")


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
    raise NotImplementedError("redact_file not yet implemented")


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
    raise NotImplementedError("redact_url not yet implemented")


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
    raise NotImplementedError("redact_dir not yet implemented")


# --- Utility tools ---


@mcp.tool()
def list_rules(category: str | None = None) -> str:
    """List active detection rules and their configuration.

    Args:
        category: Optional category filter to show only rules in that category.

    Returns:
        JSON string with rule details.
    """
    raise NotImplementedError("list_rules not yet implemented")


# --- Entry point ---


def main() -> None:
    """Start the llm-sanitizer MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()

# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Binary document reader — PDF/DOCX/PPTX/XLSX via markitdown."""

from __future__ import annotations


def read_binary(path: str) -> str:
    """Extract text from a binary document (PDF, DOCX, PPTX, XLSX).

    Requires the 'binary' optional dependency: pip install llm-sanitizer[binary]

    Args:
        path: Path to the binary document.

    Raises:
        ImportError: If markitdown is not installed.
        RuntimeError: If extraction fails.
    """
    try:
        from markitdown import MarkItDown  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "Binary document support requires the 'binary' extra: "
            "pip install llm-sanitizer[binary]"
        ) from exc

    try:
        md = MarkItDown()
        result = md.convert(path)
        return result.text_content or ""
    except Exception as exc:
        raise RuntimeError(f"Failed to extract text from {path}: {exc}") from exc

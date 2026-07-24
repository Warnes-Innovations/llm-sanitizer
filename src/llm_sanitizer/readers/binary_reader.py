# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Binary document reader — PDF/DOCX/PPTX/XLSX via markitdown."""

from __future__ import annotations


def read_binary(path: str) -> str:
    """Extract text from a binary document (PDF, DOCX, PPTX, XLSX).

    markitdown is a core dependency, so this should always be importable in a
    correctly installed environment; a failure here means the environment is
    broken (e.g. the server was launched from an env where the declared
    dependencies were never synced), not that an optional feature is missing.

    Args:
        path: Path to the binary document.

    Raises:
        ImportError: If markitdown is not installed (broken install).
        RuntimeError: If extraction fails.
    """
    try:
        from markitdown import MarkItDown
    except ImportError as exc:
        raise ImportError(
            "markitdown is unavailable, but it is a core dependency of "
            "llm-sanitizer — the running environment is missing declared "
            "dependencies. Reinstall/sync it (e.g. 'uv sync' or "
            "'pip install -e .') and relaunch the server."
        ) from exc

    try:
        md = MarkItDown()
        result = md.convert(path)
        return result.text_content or ""
    except Exception as exc:
        raise RuntimeError(f"Failed to extract text from {path}: {exc}") from exc

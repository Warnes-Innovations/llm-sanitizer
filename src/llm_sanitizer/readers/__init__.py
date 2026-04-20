# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Content reader registry — read text from files, URLs, and binary docs."""

from __future__ import annotations

from pathlib import Path


def read_file(path: str | Path) -> str:
    """Read a file and return its text content.

    Automatically selects the appropriate reader based on file extension.
    Binary formats (PDF, DOCX) require the optional 'binary' extra.
    """
    p = Path(path)
    suffix = p.suffix.lower()

    if suffix in (".pdf", ".docx", ".pptx", ".xlsx", ".odt"):
        from llm_sanitizer.readers.binary_reader import read_binary
        return read_binary(str(p))

    from llm_sanitizer.readers.text_reader import read_text
    return read_text(str(p))


def read_url(url: str) -> str:
    """Fetch a URL and return its text content."""
    from llm_sanitizer.readers.url_reader import read_url as _read_url
    return _read_url(url)


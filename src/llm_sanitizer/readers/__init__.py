# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Content reader registry — read text from files, URLs, and binary docs."""

from __future__ import annotations

from pathlib import Path


def read_file(path: str | Path, binary_mode: str = "extract") -> str | None:
    """Read a file for scanning, honoring binary_mode for content sniffed as
    binary (NUL byte in the first few KB — content-based, not extension-
    based, so renaming a file can't change how it's classified). See
    llm_sanitizer.scanner.read_scannable_content for the "extract"/"text"/
    "skip" semantics. Returns None when the file should be excluded from
    scanning entirely (binary content, extraction unavailable/failed or
    binary_mode="skip").
    """
    from llm_sanitizer.scanner import read_scannable_content
    return read_scannable_content(Path(path), binary_mode=binary_mode)


def read_url(url: str) -> str | None:
    """Fetch a URL and return its scannable text content.

    Returns None when the fetched content holds no usable text (a binary
    document no extractor can read, or one that extracted to nothing) — the
    same refusal contract as read_file, so callers must treat None as "refuse
    this content", never as empty. See readers.url_reader.read_url.
    """
    from llm_sanitizer.readers.url_reader import read_url as _read_url
    return _read_url(url)


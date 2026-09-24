# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Plain text, markdown, and source code reader."""

from __future__ import annotations

import sys

from llm_sanitizer.readers.bytes_reader import scannable_text


def read_text(path: str) -> str:
    """Read a text FILE and return its content.

    Args:
        path: File path. ``'-'`` is not accepted here — see :func:`read_stdin`.

    Raises:
        ValueError: If *path* is ``'-'``. Stdin used to be handled in this
            function by ``sys.stdin.read()``, which is text-mode by
            construction and so could neither sniff nor extract a piped binary
            (issue #55). Refusing the sentinel loudly, and naming the
            replacement, is deliberate: silently returning `str` here is what
            let a caller pipe in a PDF and get a `UnicodeDecodeError` traceback.
    """
    if path == "-":
        raise ValueError(
            "read_text() no longer reads stdin — use read_stdin(), which "
            "classifies and extracts piped binary instead of decoding it "
            "as text (issue #55)"
        )

    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def read_stdin() -> str | None:
    """Read piped stdin as BYTES and return scannable text, or None to refuse.

    Returns None when the piped content holds no usable text — a binary
    document no extractor can read, or one that extracted to nothing. Callers
    must treat that as "refuse this content", never as empty input.

    **Why bytes.** ``sys.stdin.read()`` decodes with the locale codec before any
    code here sees the input, so there is no point at which a piped PDF could be
    sniffed, and non-UTF-8 bytes raise ``UnicodeDecodeError`` out of the reader.
    That was issue #55: `llm-sanitize scan -` with a piped PDF crashed with a
    traceback. Reading ``sys.stdin.buffer`` keeps the bytes intact so the shared
    classifier and extractor can do the same job they do for a file.

    The declared encoding is still honoured for genuine text, so a pipe under a
    non-UTF-8 locale decodes as it always did rather than through ``replace``.
    """
    raw = sys.stdin.buffer.read()
    encoding = getattr(sys.stdin, "encoding", None) or "utf-8"
    return scannable_text(raw, encoding, origin="stdin")

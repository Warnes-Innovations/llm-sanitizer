# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Turn a buffer of untrusted bytes into scannable text, or refuse it.

**The one implementation.** Every entry point that receives a document as
*bytes* rather than as a path on disk routes through here: `read_url` (issue
#53) and `llm-sanitize scan -` / `redact -` reading piped stdin (issue #55).
The file path already had this behaviour via `read_scannable_content`; these two
did not, and each decoded its bytes as text instead. That family — *the binary
path does not do what the text path does* — is the same one #51 closed for
`redact_file`.

This module exists so the second entry point did not get a second answer to the
same question. The `_is_binary` rule was duplicated once before (scanner and
`integrity_checks`, with a comment on one saying it mirrored the other), they
agreed only because nobody had changed either, and commit 1b66094 had to merge
them back together. Adding a private copy of the staging logic to the stdin path
would have recreated exactly that.

Nothing here re-implements a decision. `is_binary_content` classifies,
`sniff_rtf` detects presentation markup, and `read_scannable_content` extracts;
the only thing this module owns is *staging the bytes on disk safely* so those
path-taking functions can run.
"""

from __future__ import annotations

from pathlib import Path


def suffix_from_magic(raw: bytes) -> str:
    """Return a filename suffix (``".pdf"``, ``".docx"``, …) derived ONLY from
    *raw*'s magic bytes, or ``""`` when nothing is recognised.

    **Content decides, and nothing else may.** Not a URL path, not
    Content-Type, not Content-Disposition, not a filename a user piped in
    alongside — all of those are attacker-controlled at these entry points, and
    all are wrong often enough by accident.

    Measured against markitdown, a *wrong* suffix is worse than none at all: a
    PDF written as ``.txt`` came back as 594 bytes of raw PDF source, and a DOCX
    written as ``.txt`` came back as 4 bytes **with the injected sentence
    missing entirely**. A suffix-less file, by contrast, extracts correctly —
    markitdown sniffs.

    So why derive one at all? Because
    :func:`~llm_sanitizer.readers.archive_reader.is_zip_based_document` decides
    on the file NAME. Without a ``.docx`` suffix a staged DOCX is ZIP magic with
    no document extension, which ``read_scannable_content`` treats as an
    archive-to-expand and refuses — the document would never reach the
    extractor at all.

    ``filetype`` supplies the extension, so the value comes from a fixed
    library-controlled vocabulary rather than from the input. The alphanumeric
    guard is belt-and-braces against that assumption changing: this string
    becomes part of a filesystem path.
    """
    try:
        import filetype
    except ImportError:
        # Core dep missing → no suffix. Same graceful degradation as the
        # integrity checks; markitdown still sniffs for the formats it handles.
        return ""
    try:
        kind = filetype.guess(raw)
    except (TypeError, ValueError):
        return ""
    if kind is None:
        return ""
    ext = str(kind.extension)
    if not ext.isalnum():
        return ""
    return f".{ext}"


def scannable_text(raw: bytes, encoding: str = "utf-8", *, origin: str = "bytes") -> str | None:
    """Turn *raw* into text worth scanning, or None to refuse it.

    The decision is DELEGATED, never re-implemented. ``is_binary_content`` is
    the one binary/text classifier, ``sniff_rtf`` is the one RTF check, and
    ``read_scannable_content`` is the one extraction path. The branch order here
    mirrors ``read_scannable_content``'s own — markup, then binary, then text —
    because anything else would decide the same question two different ways.

    Genuine text is decoded with *encoding*, the charset the source declared.
    That matters: staging text through a temp file and reading it back as UTF-8
    would silently mangle anything served or piped as iso-8859-1.

    An extraction that yields nothing is a REFUSAL, not empty content. That is
    the precise hazard in issue #53 — "zero findings on a document whose text
    was never read" — and it matches the scanner's own default
    ``unprocessable_binary_policy="fail"``. An empty *text* input is still just
    empty text; only the extraction branch refuses.

    *origin* only names the temp directory, to make a stray file attributable.
    It never reaches the staged file's own name.
    """
    import tempfile

    from llm_sanitizer.readers.integrity_checks import is_binary_content
    from llm_sanitizer.readers.markup_reader import sniff_rtf
    from llm_sanitizer.scanner import read_scannable_content

    if not raw:
        return ""

    with tempfile.TemporaryDirectory(prefix=f"llm-sanitizer-{origin}-") as tmpdir:
        # A fixed basename plus a magic-derived suffix. Nothing from the input's
        # own metadata reaches the filesystem, so a hostile Content-Disposition
        # (or a filename piped alongside) cannot steer where this lands.
        # tempfile creates the directory 0700 and removes it — and the staged
        # bytes — on the way out, including on the error path.
        path = Path(tmpdir) / f"body{suffix_from_magic(raw)}"
        path.write_bytes(raw)

        if not sniff_rtf(raw) and not is_binary_content(path):
            return raw.decode(encoding, errors="replace")

        text = read_scannable_content(path, binary_mode="extract")
        if text is None or not text.strip():
            return None
        return text

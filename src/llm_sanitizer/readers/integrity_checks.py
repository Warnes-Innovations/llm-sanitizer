# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Content-type and structural integrity checks for non-archive files.

Two tiers, both fail-closed and resource-bounded, both operating on the same
principle the archive path already applies — a file's real content, not its
name, governs how it's treated:

  * Tier 1 (:func:`detect_type_mismatch`) — generalize magic-based type
    detection to ALL files: detect the real content type (via the pure-Python
    ``filetype`` library) and compare it against what the extension claims.
    A genuine mismatch (e.g. a ``.png`` whose bytes are an executable) is
    reported so the scanner can emit a CRITICAL ``type_mismatch`` finding.

  * Tier 2 (:func:`validate_structure`) — for the formats that are actually
    ingested and worth a deeper look (PDF and OOXML/ODF office documents),
    perform a *bounded* structural parse (never a full render/decode of
    untrusted input). A structural failure is reported so the scanner can emit
    a CRITICAL ``corrupt_file`` finding.

Both tiers degrade gracefully (return None) when their optional-at-runtime
backend isn't importable, so the package keeps working in a partial install;
in a complete install (``filetype`` and ``pypdf`` are declared core deps) both
tiers are always active.

These functions never raise for a "bad file" — they return an explanation
string on a problem, or None when the file looks fine / can't be judged. The
scanner turns a returned string into a finding.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

from llm_sanitizer.readers.archive_reader import is_zip_based_document

# Text/source extensions that legitimately hold plain text. `file`/libmagic
# would mislabel many of these by CONTENT heuristics (Markdown embedding HTML
# gets called "text/html"; a fenced code block gets called "text/x-java"),
# producing a flood of false-positive mismatches. We deliberately do NOT use
# content-heuristic text classification for the mismatch decision — the only
# thing we assert about a text extension is: its bytes must not be *binary*
# (NUL-containing). A Markdown/source file (no NUL) is therefore never flagged,
# while an unidentified binary hiding under a text name is.
_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".txt", ".text", ".md", ".markdown", ".rst", ".org", ".adoc", ".asciidoc",
    ".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".tab",
    ".html", ".htm", ".xhtml", ".xml", ".svg", ".rss", ".atom",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env",
    ".log", ".tex", ".bib", ".ipynb", ".sql",
    ".py", ".pyi", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".scala", ".groovy", ".c", ".h", ".cc", ".cpp",
    ".cxx", ".hpp", ".hh", ".cs", ".go", ".rs", ".rb", ".php", ".pl", ".pm",
    ".lua", ".r", ".jl", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
    ".cmd", ".css", ".scss", ".sass", ".less", ".vue", ".svelte",
    ".gradle", ".cmake", ".mk", ".make", ".dockerfile", ".gitignore",
})

# Bytes sniffed to decide whether unrecognized content is binary (NUL present),
# mirroring the scanner's _is_binary heuristic (kept local to avoid an import
# cycle: the scanner imports this module).
_BINARY_SNIFF_BYTES = 8000


def _is_binary_content(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return b"\x00" in fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return False


# --- Tier 2 scope: the office formats we structurally validate --------------
_OOXML_PRIMARY_PART: dict[str, str] = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}
_ODF_EXTENSIONS: frozenset[str] = frozenset({".odt", ".ods", ".odp"})


def detect_type_mismatch(path: Path) -> str | None:
    """Tier 1: compare *path*'s extension against its real content type (magic).
    Return an explanation on a genuine mismatch, else None.

    The decision is driven by content, using the key property of the
    ``filetype`` library: it matches only known *binary* magic signatures
    (archives, images, audio/video, fonts, executables, some documents) and
    returns None for plain text and source code. That property is what keeps
    this precise — Markdown that embeds HTML, or a fenced code block, is text
    (``filetype.guess`` → None) and is NEVER flagged, avoiding a flood of
    false-positive CRITICALs.

    A mismatch is emitted only when:
      * the content resolves to a concrete BINARY type that contradicts the
        extension (a .md/.txt/.json whose bytes are an ELF/PE/image, a .png
        whose bytes are a different binary type); or
      * the content is unidentified *binary* (NUL bytes, no known signature)
        hiding under a text/source extension (a disguised ``application/
        octet-stream`` payload).

    ZIP-based office documents are legitimately ZIP and validated by Tier 2, so
    they're skipped here; recognized archives are handled by the scanner's
    archive path before reaching Tier 1.
    """
    # OOXML/ODF are legitimately ZIP — don't flag them as zip↔document
    # mismatches; Tier 2 validates their structure instead.
    if is_zip_based_document(path):
        return None

    try:
        import filetype
    except ImportError:
        # Core dep missing → Tier 1 inactive (graceful degradation).
        return None

    ext = path.suffix.lower()
    ext_bare = ext.lstrip(".")

    try:
        detected = filetype.guess(str(path))
    except OSError:
        return None

    if detected is not None:
        # Content is a concrete binary type. Compare it against whatever binary
        # type the extension itself claims (None for text/source/unknown exts).
        expected = filetype.get_type(ext=ext_bare) if ext_bare else None
        if expected is not None:
            if detected.mime != expected.mime:
                return (
                    f"File extension '.{ext_bare}' implies '{expected.mime}', but "
                    f"its content magic is '{detected.mime}' — declared type does "
                    "not match content."
                )
            return None
        # Extension does not claim a binary type, yet the bytes are a concrete
        # binary type → a disguised payload (e.g. a .md that is really a PNG).
        return (
            f"File extension '.{ext_bare}' is not a binary type, but its content "
            f"magic is '{detected.mime}' — content is disguised."
        )

    # No binary signature: plain text/source (never flagged), OR an
    # unidentified binary. Only flag the latter when it hides under a text
    # extension. Markdown/source have no NUL bytes, so _is_binary_content is
    # False and they are never flagged — the whole point of using NUL, not
    # content heuristics, here.
    if ext in _TEXT_EXTENSIONS and _is_binary_content(path):
        return (
            f"File extension '.{ext_bare}' implies text, but its content is "
            "unidentified binary (contains NUL bytes) — content is disguised."
        )
    return None


def validate_structure(
    path: Path, *, max_entries: int, max_bytes: int
) -> str | None:
    """Tier 2: bounded structural validation for PDF and OOXML/ODF documents.

    Returns an explanation on structural failure, else None (valid, or out of
    scope, or backend unavailable). Never fully renders/decodes untrusted input;
    reads are bounded by *max_entries* / *max_bytes* (the archive limits).
    """
    ext = path.suffix.lower()
    if ext == ".pdf":
        return _validate_pdf(path)
    if ext in _OOXML_PRIMARY_PART:
        return _validate_office(path, ext, ooxml=True, max_entries=max_entries, max_bytes=max_bytes)
    if ext in _ODF_EXTENSIONS:
        return _validate_office(path, ext, ooxml=False, max_entries=max_entries, max_bytes=max_bytes)
    return None


def _validate_pdf(path: Path) -> str | None:
    try:
        import pypdf
    except ImportError:
        # Core dep missing → PDF validation inactive (graceful degradation).
        return None
    try:
        reader = pypdf.PdfReader(str(path), strict=False)
        # Force the trailer/xref and page-tree to be parsed — a corrupt PDF
        # fails here — without rendering any page content.
        _ = reader.trailer
        _ = len(reader.pages)
    except Exception as exc:  # pypdf raises a variety of parse errors
        return f"PDF failed bounded structural validation: {exc}"
    return None


def _validate_office(
    path: Path,
    ext: str,
    *,
    ooxml: bool,
    max_entries: int,
    max_bytes: int,
) -> str | None:
    import zipfile

    if not zipfile.is_zipfile(path):
        return (
            f"Office document '{ext}' is not a valid ZIP container "
            "(structure is corrupt or the type is disguised)."
        )
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if len(names) > max_entries:
                return f"Office document has more than {max_entries} parts."

            if ooxml:
                if "[Content_Types].xml" not in names:
                    return "OOXML document is missing its required [Content_Types].xml part."
                parts_to_check = ["[Content_Types].xml"]
                primary = _OOXML_PRIMARY_PART.get(ext)
                if primary and primary in names:
                    parts_to_check.append(primary)
            else:
                if "mimetype" not in names:
                    return "ODF document is missing its required 'mimetype' entry."
                parts_to_check = ["content.xml"] if "content.xml" in names else []

            for part in parts_to_check:
                info = zf.getinfo(part)
                if info.file_size > max_bytes:
                    # Resource bound: don't parse an oversized XML part.
                    return (
                        f"Office document part '{part}' is too large to validate "
                        f"({info.file_size} bytes)."
                    )
                raw = zf.read(part)
                # Defense-in-depth (committee round-2): stdlib ElementTree/expat
                # expands internal entities, so a <1 KB "billion laughs" DTD in an
                # OOXML/ODF part can exhaust memory — and whether it's stopped
                # depends entirely on the interpreter's libexpat version, which we
                # must not trust (same principle as the IPv6 SSRF unwrap). Office
                # document parts have no legitimate DTD/entity, so refuse to parse
                # any that declares one, fail-closed, before it reaches the parser.
                # A DTD/entity declaration lives in the prolog, before the root
                # element; scan a generous prolog window for it.
                prolog = raw[:16384]
                if b"<!DOCTYPE" in prolog or b"<!ENTITY" in prolog:
                    return (
                        f"Office document part '{part}' declares a DTD/entity, "
                        "which is not valid in an OOXML/ODF part and is a common "
                        "XML-bomb vector; refusing to parse."
                    )
                try:
                    ElementTree.fromstring(raw)
                except ElementTree.ParseError as exc:
                    return f"Office document part '{part}' is not well-formed XML: {exc}"
    except zipfile.BadZipFile as exc:
        return f"Office document ZIP container is corrupt: {exc}"
    except (OSError, RuntimeError) as exc:
        return f"Office document could not be structurally validated: {exc}"
    return None

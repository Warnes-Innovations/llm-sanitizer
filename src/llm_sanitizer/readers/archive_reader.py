# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Archive type detection and member extraction.

Content-based archive handling for the scanner. Archive *type* is determined
from the file's magic bytes (not its extension), so a renamed or disguised
archive can't change how it is treated. The scanner uses this module to:

  * detect whether a file is an archive, and of which format;
  * detect a mismatch between a file's extension and its real content;
  * extract each member's bytes for recursive scanning.

Stdlib formats (ZIP, TAR, TAR.GZ/BZ2/XZ, and bare GZ/BZ2/XZ streams) are always
available. 7z and RAR need optional backends (``py7zr`` / ``libarchive-c``),
imported lazily so the package works without them — a supported-but-uninstalled
format raises :class:`ArchiveToolUnavailable` with an actionable install hint,
which the scanner surfaces as a CRITICAL finding rather than silently skipping.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ArchiveError(Exception):
    """An archive is corrupt, unreadable, or expands past its size budget.

    Raised for archives whose *type* is recognized and supported but whose
    *content* can't be safely extracted. The scanner turns this into a CRITICAL
    finding — an unopenable archive is a potential evasion attempt, not a file
    to silently pass through or raw-text scan.
    """


class ArchiveToolUnavailable(ArchiveError):
    """An archive uses a supported format whose optional backend isn't installed.

    Carries an actionable install hint (e.g. ``pip install llm-sanitizer[7z]``).
    A subclass of :class:`ArchiveError` so callers that only care about "could
    not extract" can catch the base class, while the scanner can distinguish
    "no tool" (unsupported) from "corrupt" for the finding message.
    """


# ---------------------------------------------------------------------------
# Format registry
# ---------------------------------------------------------------------------

# Canonical archive-format identifiers. These are the *outer* container type as
# the magic bytes reveal it — a ``.tar.gz`` reads as "gz" (gzip stream), which
# once decompressed re-detects as "tar" on the next recursion level. Keeping the
# identifier tied to the outer wrapper means extension/magic comparison is a
# plain equality check (see archive_type_from_extension).
ALL_FORMATS: tuple[str, ...] = ("zip", "tar", "gz", "bz2", "xz", "7z", "rar")

# Extensions that denote a *true* archive meant to be expanded. Deliberately
# excludes ZIP-based *document* formats (see _ZIP_BASED_DOCUMENT_EXTENSIONS):
# those carry ZIP magic but are documents to be handled by markitdown, not
# archives to be unpacked. Double extensions are listed first and checked first.
_EXTENSION_TO_FORMAT: tuple[tuple[str, str], ...] = (
    (".tar.gz", "gz"),
    (".tar.bz2", "bz2"),
    (".tar.xz", "xz"),
    (".tgz", "gz"),
    (".tbz2", "bz2"),
    (".tbz", "bz2"),
    (".txz", "xz"),
    (".tar", "tar"),
    (".zip", "zip"),
    (".gz", "gz"),
    (".bz2", "bz2"),
    (".xz", "xz"),
    (".7z", "7z"),
    (".rar", "rar"),
)

# ZIP-based container formats that are documents, not archives-to-expand. These
# have ZIP magic bytes but must flow to the normal binary-extraction path
# (markitdown), so the scanner treats their ZIP magic as expected rather than as
# a disguised archive.
_ZIP_BASED_DOCUMENT_EXTENSIONS: frozenset[str] = frozenset({
    ".docx", ".pptx", ".xlsx", ".dotx", ".xltx", ".potx",
    ".odt", ".ods", ".odp", ".odg",
    ".epub", ".jar", ".war", ".ear", ".apk", ".xpi", ".vsix", ".whl", ".egg",
})

# Bytes read from a file's head for magic-based detection. 512 bytes is one tar
# block, enough to inspect the "ustar" magic at offset 257.
_MAGIC_SNIFF_BYTES = 512


def archive_type_from_extension(path: Path) -> str | None:
    """Return the archive format implied by *path*'s extension, or None.

    Matches only *true* archive extensions (see _EXTENSION_TO_FORMAT); ZIP-based
    document extensions (.docx etc.) return None so they route to markitdown.
    """
    name = path.name.lower()
    for suffix, fmt in _EXTENSION_TO_FORMAT:
        if name.endswith(suffix):
            return fmt
    return None


def is_zip_based_document(path: Path) -> bool:
    """Return True if *path* has a ZIP-based *document* extension (.docx, .odt,
    .epub, .jar, …) — a container that carries ZIP magic but should be handled
    by the normal binary-extraction path, not unpacked as an archive."""
    name = path.name.lower()
    return any(name.endswith(ext) for ext in _ZIP_BASED_DOCUMENT_EXTENSIONS)


def detect_archive_type(path: Path) -> str | None:
    """Return the archive format detected from *path*'s magic bytes, or None.

    Content is the source of truth — the extension is never consulted here.
    Returns one of ALL_FORMATS, or None if the content isn't a recognized
    archive. Only formats with stdlib magic signatures (plus 7z/rar signatures)
    are recognized; the actual expandability (optional backend installed) is
    checked later, at extraction time.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(_MAGIC_SNIFF_BYTES)
    except OSError:
        return None

    # ZIP first: PK signature, confirmed against the central directory so we
    # don't misclassify arbitrary "PK…" data as a zip.
    if head[:2] == b"PK" and zipfile.is_zipfile(path):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"Rar!":
        return "rar"
    # POSIX/GNU tar carries the "ustar" magic at offset 257.
    if head[257:262] == b"ustar":
        return "tar"
    # Old-style (v7) tar has no magic — fall back to the stdlib checksum probe.
    try:
        if tarfile.is_tarfile(path):
            return "tar"
    except (OSError, tarfile.TarError):
        return None
    return None


# ---------------------------------------------------------------------------
# Member extraction
# ---------------------------------------------------------------------------


def iter_archive_members(
    path: Path,
    archive_type: str,
    *,
    max_total_bytes: int,
    max_entries: int,
) -> Iterator[tuple[str, bytes]]:
    """Yield ``(member_name, member_bytes)`` for each file member of *path*.

    *archive_type* must be one of ALL_FORMATS (the value returned by
    detect_archive_type). Directory entries are skipped. Extraction is bounded:
    once the cumulative uncompressed size passes *max_total_bytes*, or the entry
    count passes *max_entries*, :class:`ArchiveError` is raised — an archive that
    expands past its budget is surfaced loudly rather than partially scanned.

    Raises:
        ArchiveToolUnavailable: format needs an optional backend that isn't
            installed (7z, rar).
        ArchiveError: archive is corrupt/unreadable, or exceeds its budget.
    """
    if archive_type == "zip":
        yield from _iter_zip(path, max_total_bytes, max_entries)
    elif archive_type == "tar":
        yield from _iter_tar(path, max_total_bytes, max_entries)
    elif archive_type in ("gz", "bz2", "xz"):
        yield from _iter_compressed_stream(path, archive_type, max_total_bytes)
    elif archive_type == "7z":
        yield from _iter_7z(path, max_total_bytes, max_entries)
    elif archive_type == "rar":
        yield from _iter_rar(path, max_total_bytes, max_entries)
    else:  # pragma: no cover - guarded by caller
        raise ArchiveToolUnavailable(
            f"no tool available to expand '{archive_type}' archives"
        )


def _iter_zip(
    path: Path, max_total_bytes: int, max_entries: int
) -> Iterator[tuple[str, bytes]]:
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            if len(infos) > max_entries:
                raise ArchiveError(
                    f"zip archive has {len(infos)} entries, exceeding the "
                    f"{max_entries}-entry limit"
                )
            total = 0
            for info in infos:
                try:
                    data = zf.read(info)
                except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                    # Encrypted or corrupt member — fail closed.
                    raise ArchiveError(
                        f"could not read zip member '{info.filename}': {exc}"
                    ) from exc
                total += len(data)
                if total > max_total_bytes:
                    raise ArchiveError(
                        f"zip archive expands beyond the {max_total_bytes}-byte "
                        "cumulative limit"
                    )
                yield info.filename, data
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"corrupt zip archive: {exc}") from exc


def _iter_tar(
    path: Path, max_total_bytes: int, max_entries: int
) -> Iterator[tuple[str, bytes]]:
    try:
        # Only ever opened read-only; the "r:" literal lets mypy resolve the
        # tarfile.open overload (a plain str mode variable can't be matched).
        tf = tarfile.open(path, "r:")
    except tarfile.TarError as exc:
        raise ArchiveError(f"corrupt tar archive: {exc}") from exc
    try:
        total = 0
        count = 0
        for member in tf:
            if not member.isfile():
                continue
            count += 1
            if count > max_entries:
                raise ArchiveError(
                    f"tar archive has more than {max_entries} entries"
                )
            try:
                extracted = tf.extractfile(member)
                data = extracted.read() if extracted is not None else b""
            except (tarfile.TarError, OSError) as exc:
                raise ArchiveError(
                    f"could not read tar member '{member.name}': {exc}"
                ) from exc
            total += len(data)
            if total > max_total_bytes:
                raise ArchiveError(
                    f"tar archive expands beyond the {max_total_bytes}-byte "
                    "cumulative limit"
                )
            yield member.name, data
    finally:
        tf.close()


def _iter_compressed_stream(
    path: Path, archive_type: str, max_total_bytes: int
) -> Iterator[tuple[str, bytes]]:
    """Decompress a single-stream wrapper (gz/bz2/xz) into one member.

    The decompressed bytes are read in bounded chunks; if the stream expands
    past *max_total_bytes* it's treated as a bomb and raised as ArchiveError.
    A ``.tar.gz`` decompresses to a bare tar here, which the caller then
    re-detects and expands on the next recursion level.
    """
    opener = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[archive_type]
    # Member name = the file name with its outermost compression suffix removed.
    inner_name = path.name
    for suffix in (".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".tbz", ".txz"):
        if inner_name.lower().endswith(suffix):
            inner_name = inner_name[: -len(suffix)]
            # A ".tgz"-style suffix implies an inner tar; give it a .tar name so
            # the next recursion level detects it by extension too.
            if suffix in (".tgz", ".tbz2", ".tbz", ".txz"):
                inner_name += ".tar"
            break
    else:
        inner_name = inner_name + ".decompressed"

    chunk_size = 1024 * 1024
    buffer = bytearray()
    try:
        with opener(path, "rb") as stream:  # type: ignore[operator]
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > max_total_bytes:
                    raise ArchiveError(
                        f"{archive_type} stream expands beyond the "
                        f"{max_total_bytes}-byte limit"
                    )
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ArchiveError(f"corrupt {archive_type} stream: {exc}") from exc
    yield inner_name, bytes(buffer)


def _iter_7z(
    path: Path, max_total_bytes: int, max_entries: int
) -> Iterator[tuple[str, bytes]]:
    try:
        import py7zr
    except ImportError as exc:
        raise ArchiveToolUnavailable(
            "7z archive support requires the '7z' extra: "
            "pip install llm-sanitizer[7z]"
        ) from exc
    try:
        with py7zr.SevenZipFile(path, mode="r") as archive:
            contents = archive.readall()
    except Exception as exc:  # py7zr raises a variety of internal errors
        raise ArchiveError(f"corrupt or unreadable 7z archive: {exc}") from exc

    total = 0
    count = 0
    for name, bio in contents.items():
        count += 1
        if count > max_entries:
            raise ArchiveError(f"7z archive has more than {max_entries} entries")
        data = bio.read()
        total += len(data)
        if total > max_total_bytes:
            raise ArchiveError(
                f"7z archive expands beyond the {max_total_bytes}-byte limit"
            )
        yield name, data


def _iter_rar(
    path: Path, max_total_bytes: int, max_entries: int
) -> Iterator[tuple[str, bytes]]:
    try:
        import libarchive  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ArchiveToolUnavailable(
            "RAR archive support requires the 'rar' extra: "
            "pip install llm-sanitizer[rar]"
        ) from exc
    try:
        total = 0
        count = 0
        with libarchive.file_reader(str(path)) as archive:
            for entry in archive:
                if entry.isdir:
                    continue
                count += 1
                if count > max_entries:
                    raise ArchiveError(
                        f"rar archive has more than {max_entries} entries"
                    )
                data = b"".join(entry.get_blocks())
                total += len(data)
                if total > max_total_bytes:
                    raise ArchiveError(
                        f"rar archive expands beyond the {max_total_bytes}-byte "
                        "limit"
                    )
                yield entry.pathname, data
    except ArchiveError:
        raise
    except Exception as exc:  # libarchive raises its own error hierarchy
        raise ArchiveError(f"corrupt or unreadable rar archive: {exc}") from exc

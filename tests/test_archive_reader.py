# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for llm_sanitizer.readers.archive_reader — 7z/rar API-compatibility
and bomb-guard regressions.

Context: SevenZipFile.readall() was removed in py7zr 1.0, and the old
_iter_7z called it unconditionally, so every valid .7z reported CRITICAL
corrupt_file instead of expanding. These tests exercise the real py7zr /
libarchive-c APIs (skipped, not mocked, when the optional extra isn't
installed) so a future backend API change is caught here instead of shipping.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from llm_sanitizer.readers.archive_reader import ArchiveError, iter_archive_members


class TestSevenZipExtraction:
    def test_content_is_recovered(self, tmp_path: Path) -> None:
        py7zr = pytest.importorskip("py7zr")
        payload = tmp_path / "inner.md"
        payload.write_text("hello from inside the archive", encoding="utf-8")
        archive = tmp_path / "probe.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.write(payload, "inner.md")

        members = list(
            iter_archive_members(
                archive, "7z", max_total_bytes=10_000_000, max_entries=100
            )
        )
        assert members == [("inner.md", b"hello from inside the archive")]

    def test_directories_are_not_yielded(self, tmp_path: Path) -> None:
        py7zr = pytest.importorskip("py7zr")
        src = tmp_path / "tree"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "nested.txt").write_text("nested payload")
        (src / "top.txt").write_text("top payload")
        archive = tmp_path / "tree.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.writeall(src, arcname=".")

        members = dict(
            iter_archive_members(
                archive, "7z", max_total_bytes=10_000_000, max_entries=100
            )
        )
        assert members == {
            "sub/nested.txt": b"nested payload",
            "top.txt": b"top payload",
        }

    def test_declared_size_over_budget_is_archive_error(self, tmp_path: Path) -> None:
        py7zr = pytest.importorskip("py7zr")
        payload = tmp_path / "big.bin"
        payload.write_bytes(b"A" * 5000)
        archive = tmp_path / "big.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.write(payload, "big.bin")

        with pytest.raises(ArchiveError, match="5000.*beyond the 100-byte limit"):
            list(
                iter_archive_members(
                    archive, "7z", max_total_bytes=100, max_entries=100
                )
            )

    def test_entry_count_over_budget_is_archive_error(self, tmp_path: Path) -> None:
        py7zr = pytest.importorskip("py7zr")
        a = tmp_path / "a.txt"
        a.write_text("a")
        b = tmp_path / "b.txt"
        b.write_text("b")
        archive = tmp_path / "two.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.write(a, "a.txt")
            z.write(b, "b.txt")

        with pytest.raises(ArchiveError, match="more than 1 entries"):
            list(
                iter_archive_members(
                    archive, "7z", max_total_bytes=10_000_000, max_entries=1
                )
            )

    def test_mid_extraction_budget_abort_is_archive_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Defense-in-depth backstop: even if the header-declared size passed
        # the pre-check (e.g. a header that under-reports true output), the
        # shared per-extraction byte budget must still abort mid-stream rather
        # than silently yielding truncated content. Simulated by lying about
        # the declared size so the pre-check is fooled but real bytes are not.
        py7zr = pytest.importorskip("py7zr")
        payload = tmp_path / "real.bin"
        payload.write_bytes(b"X" * 5000)
        archive = tmp_path / "real.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.write(payload, "real.bin")

        real_list = py7zr.SevenZipFile.list

        def lying_list(self: object) -> list[object]:
            infos = real_list(self)  # type: ignore[operator]
            for fi in infos:
                if not fi.is_directory:
                    fi.uncompressed = 1  # lie: header says ~nothing
            return infos

        monkeypatch.setattr(py7zr.SevenZipFile, "list", lying_list)
        with pytest.raises(ArchiveError, match="beyond the 100-byte limit"):
            list(
                iter_archive_members(
                    archive, "7z", max_total_bytes=100, max_entries=100
                )
            )

    def test_backend_api_mismatch_is_distinguished_from_corruption(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The exact failure mode this module regresses: an AttributeError from
        # calling a py7zr method that no longer exists must be reported as an
        # internal/backend defect, not as evidence the archive is corrupt —
        # both still fail closed as ArchiveError, only the message differs.
        py7zr = pytest.importorskip("py7zr")
        payload = tmp_path / "inner.md"
        payload.write_text("hello", encoding="utf-8")
        archive = tmp_path / "probe.7z"
        with py7zr.SevenZipFile(archive, "w") as z:
            z.write(payload, "inner.md")

        def boom(self: object, *args: object, **kwargs: object) -> None:
            raise AttributeError(
                "'SevenZipFile' object has no attribute 'readall'"
            )

        monkeypatch.setattr(py7zr.SevenZipFile, "extract", boom)
        with pytest.raises(ArchiveError, match="not necessarily a corrupt file"):
            list(
                iter_archive_members(
                    archive, "7z", max_total_bytes=10_000_000, max_entries=100
                )
            )

    def test_genuine_corruption_is_reported_as_corrupt(self, tmp_path: Path) -> None:
        pytest.importorskip("py7zr")
        archive = tmp_path / "truncated.7z"
        # Valid 7z magic, garbage/truncated body.
        archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 4)

        with pytest.raises(ArchiveError, match="corrupt or unreadable 7z archive"):
            list(
                iter_archive_members(
                    archive, "7z", max_total_bytes=10_000_000, max_entries=100
                )
            )


class TestRarExtraction:
    """libarchive-c's reader API (file_reader / entry.isdir / entry.pathname /
    entry.get_blocks()) is format-agnostic: the same code path in _iter_rar
    runs regardless of which archive format libarchive detects inside the
    file. No RAR-writing tool is available in this environment or via
    libarchive itself (RAR compression is patent-encumbered; libarchive can
    only *read* it), so these tests read a real tar archive through
    _iter_rar directly — bypassing the magic-byte format gate that normally
    restricts this function to .rar content — to exercise the exact
    extraction API surface that would run for genuine RAR input.
    """

    def test_content_is_recovered(self, tmp_path: Path) -> None:
        pytest.importorskip("libarchive")
        from llm_sanitizer.readers.archive_reader import _iter_rar

        payload = tmp_path / "inner.txt"
        payload.write_text("hello from inside the archive")
        archive = tmp_path / "probe.tar"
        with tarfile.open(archive, "w") as tf:
            tf.add(payload, arcname="inner.txt")

        members = list(_iter_rar(archive, max_total_bytes=10_000_000, max_entries=100))
        assert members == [("inner.txt", b"hello from inside the archive")]

    def test_backend_api_mismatch_is_distinguished_from_corruption(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        libarchive = pytest.importorskip("libarchive")
        from llm_sanitizer.readers.archive_reader import _iter_rar

        payload = tmp_path / "inner.txt"
        payload.write_text("hello")
        archive = tmp_path / "probe.tar"
        with tarfile.open(archive, "w") as tf:
            tf.add(payload, arcname="inner.txt")

        def boom(*args: object, **kwargs: object) -> object:
            raise AttributeError("'module' object has no attribute 'file_reader'")

        monkeypatch.setattr(libarchive, "file_reader", boom)
        with pytest.raises(ArchiveError, match="not necessarily a corrupt file"):
            list(_iter_rar(archive, max_total_bytes=10_000_000, max_entries=100))

    def test_genuine_corruption_is_reported_as_corrupt(self, tmp_path: Path) -> None:
        pytest.importorskip("libarchive")
        from llm_sanitizer.readers.archive_reader import _iter_rar

        archive = tmp_path / "corrupt.rar"
        archive.write_bytes(b"Rar!" + b"\x00" * 20)

        with pytest.raises(ArchiveError, match="corrupt or unreadable rar archive"):
            list(_iter_rar(archive, max_total_bytes=10_000_000, max_entries=100))

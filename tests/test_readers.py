# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for readers."""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_sanitizer.readers import read_file
from llm_sanitizer.readers.text_reader import read_text


class TestTextReader:
    def test_reads_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("Hello World")
        content = read_text(str(f))
        assert content == "Hello World"

    def test_reads_markdown(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.md"
        f.write_text("# Title\n\nBody text.")
        content = read_text(str(f))
        assert "# Title" in content

    def test_nonexistent_file_raises_os_error(self) -> None:
        with pytest.raises(OSError):
            read_text("/nonexistent/path/file.txt")

    def test_read_file_dispatches_to_text_reader(self, tmp_path: Path) -> None:
        f = tmp_path / "test.md"
        f.write_text("content")
        content = read_file(str(f))
        assert content == "content"


class TestBinaryReader:
    def test_markitdown_not_available_raises_import_error(self) -> None:
        """If markitdown is not available, should raise ImportError."""
        import sys
        # Temporarily hide markitdown
        original = sys.modules.get("markitdown")
        sys.modules["markitdown"] = None  # type: ignore[assignment]
        try:
            from llm_sanitizer.readers.binary_reader import read_binary
            with pytest.raises((ImportError, Exception)):
                read_binary("/some/file.pdf")
        finally:
            if original is None:
                del sys.modules["markitdown"]
            else:
                sys.modules["markitdown"] = original

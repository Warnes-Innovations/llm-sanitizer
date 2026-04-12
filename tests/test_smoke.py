# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Smoke tests for llm-sanitizer package."""

from __future__ import annotations


def test_version_is_set() -> None:
    from llm_sanitizer import __version__

    assert __version__ == "0.1.0"


def test_cli_help(capsys: object) -> None:
    """CLI --help exits 0."""
    import pytest

    from llm_sanitizer.cli import main

    with pytest.raises(SystemExit) as exc_info:
        import sys

        sys.argv = ["llm-sanitize", "--help"]
        main()
    assert exc_info.value.code == 0

# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Smoke tests for llm-sanitizer package."""

from __future__ import annotations


def test_version_is_set() -> None:
    """`__version__` must be set and stay in sync with the packaged metadata
    (i.e. pyproject.toml). Asserting against importlib.metadata rather than a
    hardcoded string means this never needs a manual bump AND it catches the
    two-places-out-of-sync drift that previously pinned __version__ to 0.1.0."""
    from importlib.metadata import version

    from llm_sanitizer import __version__

    assert __version__
    assert __version__ == version("llm-sanitizer")


def test_cli_help(capsys: object) -> None:
    """CLI --help exits 0."""
    import pytest

    from llm_sanitizer.cli import main

    with pytest.raises(SystemExit) as exc_info:
        import sys

        sys.argv = ["llm-sanitize", "--help"]
        main()
    assert exc_info.value.code == 0

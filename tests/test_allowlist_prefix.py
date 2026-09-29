# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""`is_legitimate_file` must not accept an undotted lookalike (0.7.1 defect).

It used `lstrip("./")`, which strips the CHARACTERS "." and "/", so the
lookalike `cursorrules` normalised to the same string as the allowlisted
`.cursorrules` and passed as a legitimate agent-instruction file — fail-open on
an allowlist. Fixed in 0.7.2 by removing only leading "./" segments.
"""

from __future__ import annotations

import pytest

from llm_sanitizer.rules import is_legitimate_file


@pytest.mark.parametrize("path", [".cursorrules", "./.cursorrules"])
def test_dotted_allowlist_entries_still_match(path: str) -> None:
    assert is_legitimate_file(path)


@pytest.mark.parametrize("path", ["cursorrules", "x/cursorrules", "..cursorrules"])
def test_undotted_lookalike_is_not_legitimate(path: str) -> None:
    assert not is_legitimate_file(path)

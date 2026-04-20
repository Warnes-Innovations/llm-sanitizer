# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Plain text, markdown, and source code reader."""

from __future__ import annotations

import sys


def read_text(path: str) -> str:
    """Read a text file and return its content.

    Args:
        path: File path, or '-' to read from stdin.
    """
    if path == "-":
        return sys.stdin.read()

    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()

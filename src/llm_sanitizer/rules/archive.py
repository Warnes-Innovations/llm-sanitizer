# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deprecated shim — archive-integrity rules moved to :mod:`llm_sanitizer.rules.integrity`.

The archive-specific integrity rules were generalized to cover *all* files (one
``type_mismatch`` concept, one ``corrupt_file`` concept). This module re-exports
the new names so any lingering ``rules.archive`` import keeps working. Prefer
importing from :mod:`llm_sanitizer.rules.integrity` directly.
"""

from __future__ import annotations

from llm_sanitizer.rules.integrity import (  # noqa: F401
    ARCHIVE_UNSUPPORTED,
    CORRUPT_FILE,
    TYPE_MISMATCH,
    UNSCANNABLE_BINARY,
    make_integrity_finding,
)

# Legacy aliases for the pre-generalization identifiers.
ARCHIVE_TYPE_MISMATCH = TYPE_MISMATCH
ARCHIVE_CORRUPT = CORRUPT_FILE
make_archive_finding = make_integrity_finding

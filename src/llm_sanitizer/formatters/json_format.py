# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""JSON output formatter."""

from __future__ import annotations

import json

from llm_sanitizer.models import DirScanResult, ScanResult


def format_json(result: ScanResult | DirScanResult) -> str:
    """Format a ScanResult or DirScanResult as a JSON string."""
    return json.dumps(result.model_dump_json_friendly(), indent=2, ensure_ascii=False)

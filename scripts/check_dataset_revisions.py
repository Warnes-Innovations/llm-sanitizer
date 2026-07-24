#!/usr/bin/env python3
# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Check whether the training-data sources have new revisions upstream.

Compares the Hugging Face dataset revisions pinned in
``data-raw/pinned-revisions.json`` (what the vendored ``model.json`` was trained
against) to the live revisions on the Hub. Used by
``.github/workflows/dataset-monitor.yml`` to open an issue when a source updates,
and runnable locally:

    python scripts/check_dataset_revisions.py

Exit code is always 0 (a detected change is a normal result, not a failure). When
run in GitHub Actions, writes ``changed`` / ``summary`` to ``$GITHUB_OUTPUT``.
Dependency-free (stdlib urllib).
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

_PINS = Path(__file__).resolve().parent.parent / "data-raw" / "pinned-revisions.json"


def _live_sha(repo_id: str) -> str | None:
    url = f"https://huggingface.co/api/datasets/{repo_id}"
    headers = {}
    token = os.environ.get("HF_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            sha = json.loads(resp.read()).get("sha")
            return sha if isinstance(sha, str) else None
    except Exception:  # noqa: BLE001 — any failure = "couldn't check", reported below
        return None


def main() -> int:
    pins: dict[str, str] = json.loads(_PINS.read_text(encoding="utf-8"))["datasets"]
    changed: list[str] = []
    unknown: list[str] = []
    lines: list[str] = []

    for repo_id, pinned in pins.items():
        live = _live_sha(repo_id)
        if live is None:
            unknown.append(repo_id)
            lines.append(f"- ⚠️ `{repo_id}`: could not read live revision (gated/network).")
        elif live != pinned:
            changed.append(repo_id)
            lines.append(
                f"- 🔔 `{repo_id}`: pinned `{pinned[:12]}` → live `{live[:12]}` "
                f"(<https://huggingface.co/datasets/{repo_id}/commits/main>)"
            )
        else:
            lines.append(f"- ✅ `{repo_id}`: up to date (`{pinned[:12]}`).")

    summary = "\n".join(lines)
    print(summary)

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"changed={'true' if changed else 'false'}\n")
            # Multi-line output via heredoc-style delimiter.
            fh.write("summary<<__EOF__\n")
            fh.write(summary + "\n")
            if changed:
                fh.write(
                    "\nRetrain the `semantic_intent` classifier against the new "
                    "revision(s) and bump `data-raw/pinned-revisions.json`. See #9.\n"
                )
            fh.write("__EOF__\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

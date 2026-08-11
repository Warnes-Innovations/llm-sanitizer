#!/usr/bin/env python3
# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Check the training-data source pins — internally, then against the Hub.

Two checks, in this order:

1. **Internal consistency (offline, authoritative).** ``data-raw/SOURCES.md``
   restates each dataset's pinned revision in prose, and ``pinned-revisions.json``
   holds the machine-readable copy. Only the JSON is ever *read* by tooling, so
   the prose can drift out of date without anything noticing — and the prose is
   what a human reads to learn which revision the model was trained against. This
   check asserts the two agree, and **fails the run** if they do not. Run it
   offline with ``--check``.

2. **Upstream currency (network).** Compares the pinned revisions to the live
   revisions on the Hugging Face Hub. Used by
   ``.github/workflows/dataset-monitor.yml`` to open an issue when a source
   updates.

Runnable locally:

    python scripts/check_dataset_revisions.py            # both checks
    python scripts/check_dataset_revisions.py --check    # consistency only, no network

Exit codes: ``0`` success (a detected *upstream* change is a normal result, not a
failure); ``2`` the pins disagree between SOURCES.md and pinned-revisions.json.
When run in GitHub Actions, writes ``changed`` / ``summary`` to ``$GITHUB_OUTPUT``.
Dependency-free (stdlib urllib).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

_DATA_RAW = Path(__file__).resolve().parent.parent / "data-raw"
_PINS = _DATA_RAW / "pinned-revisions.json"
_SOURCES = _DATA_RAW / "SOURCES.md"

# "### prodnull/prompt-injection-repo-dataset  *(primary — domain-matched)*"
_HEADING = re.compile(r"^###\s+(?P<repo>[\w.-]+/[\w.-]+)")
# "- **Pinned revision:** `6c56b897ee4a328fb4f41f4b0d334f5d2db4482a`"
_REVISION = re.compile(r"\*\*Pinned revision:\*\*\s*`(?P<sha>[0-9a-fA-F]{7,64})`")


def sources_md_pins(text: str) -> dict[str, str]:
    """Extract {repo_id: sha} from SOURCES.md's per-dataset sections.

    A revision line is attributed to the most recent ``### owner/name`` heading
    above it. Sections without a revision line are simply absent from the result
    — :func:`consistency_errors` reports them as missing rather than guessing.
    """
    pins: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = _HEADING.match(line)
        if heading:
            current = heading.group("repo")
            continue
        revision = _REVISION.search(line)
        if revision and current is not None:
            pins[current] = revision.group("sha")
    return pins


def consistency_errors(json_pins: dict[str, str], md_pins: dict[str, str]) -> list[str]:
    """Return human-readable errors where the two pin sources disagree.

    Checked in both directions: a dataset present in one file and not the other
    is an error, not just a mismatched sha. A dataset silently missing from
    SOURCES.md is exactly the drift this guard exists to catch.
    """
    errors: list[str] = []
    for repo_id, sha in sorted(json_pins.items()):
        if repo_id not in md_pins:
            errors.append(
                f"{repo_id}: pinned in pinned-revisions.json ({sha[:12]}) but has no "
                f"'**Pinned revision:**' line under a '### {repo_id}' heading in SOURCES.md"
            )
        elif md_pins[repo_id] != sha:
            errors.append(
                f"{repo_id}: SOURCES.md says {md_pins[repo_id][:12]} but "
                f"pinned-revisions.json says {sha[:12]} — the JSON is authoritative; "
                f"update SOURCES.md to match"
            )
    for repo_id in sorted(md_pins.keys() - json_pins.keys()):
        errors.append(
            f"{repo_id}: documented in SOURCES.md ({md_pins[repo_id][:12]}) but absent "
            f"from pinned-revisions.json, so no tooling checks it"
        )
    return errors


def check_consistency() -> list[str]:
    """Load both files and return any disagreement between them."""
    json_pins: dict[str, str] = json.loads(_PINS.read_text(encoding="utf-8"))["datasets"]
    md_pins = sources_md_pins(_SOURCES.read_text(encoding="utf-8"))
    return consistency_errors(json_pins, md_pins)


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
    consistency_only = "--check" in sys.argv[1:]

    # Run the offline invariant FIRST and fail closed on it. A disagreement
    # between the prose and the JSON is a defect in this repository, not a
    # normal result like an upstream update — and checking it before any
    # network call means it is reported even when the Hub is unreachable.
    errors = check_consistency()
    if errors:
        print("Dataset pin mismatch between data-raw/SOURCES.md and pinned-revisions.json:")
        for err in errors:
            print(f"  - {err}")
        return 2
    if consistency_only:
        print("✅ SOURCES.md and pinned-revisions.json agree on every dataset revision.")
        return 0

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

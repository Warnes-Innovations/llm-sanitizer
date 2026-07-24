#!/usr/bin/env python3
# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fetch the third-party training datasets into ``data-raw/`` (not committed).

Downloads the labeled corpora used to train the ``semantic_intent`` classifier,
at the revisions pinned in ``pinned-revisions.json``. Only the trained weights
(``model.json``) are ever redistributed — this helper just populates the local,
git-ignored ``data-raw/`` for a retrain.

Usage::

    export HF_TOKEN=...            # read-scope token; required for gated sets
    python data-raw/fetch_datasets.py [--only deepset/prompt-injections]

Security: ``HF_TOKEN`` is read from the environment and is NEVER printed or
written to disk. See ``README.md`` for how to obtain access (the gated primary
dataset also needs a one-time "Agree and access" click on its HF page).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PINS = _HERE / "pinned-revisions.json"

# dataset repo id -> (filename on HF, local filename, gated?)
_DATASETS: dict[str, tuple[str, str, bool]] = {
    "prodnull/prompt-injection-repo-dataset": (
        "train.jsonl", "prompt-injection-repo-dataset.train.jsonl", True,
    ),
    # deepset is stored as parquet on HF; pull its rows as JSONL via the
    # datasets-server so no parquet dependency is needed. Handled specially below.
    "deepset/prompt-injections": (
        "", "deepset-prompt-injections.train.jsonl", False,
    ),
}


def _pinned_revision(repo_id: str) -> str:
    pins = json.loads(_PINS.read_text(encoding="utf-8"))["datasets"]
    rev = pins.get(repo_id, "main")
    return rev if isinstance(rev, str) else "main"


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("HF_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _download(url: str, dest: Path, headers: dict[str, str]) -> None:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (https only)
        dest.write_bytes(resp.read())


def _fetch_resolve(repo_id: str, filename: str, local: str, gated: bool) -> None:
    rev = _pinned_revision(repo_id)
    url = f"https://huggingface.co/datasets/{repo_id}/resolve/{rev}/{filename}"
    headers = _auth_headers()
    if gated and "Authorization" not in headers:
        raise SystemExit(
            f"{repo_id} is gated: set HF_TOKEN (read scope) AND accept the dataset "
            "terms on its HF page first — see data-raw/README.md."
        )
    dest = _HERE / local
    try:
        _download(url, dest, headers)
    except urllib.error.HTTPError as exc:
        body = exc.read()[:200].decode("utf-8", "replace")
        raise SystemExit(f"{repo_id}: HTTP {exc.code} — {body}") from exc
    _validate_jsonl(dest, repo_id)


def _fetch_deepset(repo_id: str, local: str) -> None:
    """deepset is parquet-backed; page its rows out of the HF datasets-server as
    JSONL so we need no parquet reader."""
    dest = _HERE / local
    rows: list[dict[str, object]] = []
    offset = 0
    while True:
        url = (
            "https://datasets-server.huggingface.co/rows"
            f"?dataset={repo_id.replace('/', '%2F')}&config=default&split=train"
            f"&offset={offset}&length=100"
        )
        req = urllib.request.Request(url, headers=_auth_headers())
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            page = json.loads(resp.read())
        batch = page.get("rows", [])
        if not batch:
            break
        rows.extend(r["row"] for r in batch)
        offset += len(batch)
        if offset >= page.get("num_rows_total", offset):
            break
    dest.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
        encoding="utf-8",
    )
    _validate_jsonl(dest, repo_id)


def _validate_jsonl(path: Path, repo_id: str) -> None:
    with path.open(encoding="utf-8") as fh:
        first = fh.readline().strip()
    try:
        obj = json.loads(first)
    except ValueError as exc:
        raise SystemExit(
            f"{repo_id}: downloaded file is not JSONL (got: {first[:120]!r}). "
            "If gated, the token/gate acceptance is likely missing."
        ) from exc
    n = sum(1 for _ in path.open(encoding="utf-8"))
    print(f"  {repo_id}: {n} rows -> {path.name} (keys: {sorted(obj)})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", help="fetch just this dataset repo id")
    args = ap.parse_args()

    targets = (
        {args.only: _DATASETS[args.only]} if args.only else _DATASETS
    )
    if args.only and args.only not in _DATASETS:
        raise SystemExit(f"unknown dataset {args.only!r}; known: {list(_DATASETS)}")

    for repo_id, (filename, local, gated) in targets.items():
        print(f"fetching {repo_id} @ {_pinned_revision(repo_id)} ...")
        if repo_id == "deepset/prompt-injections":
            _fetch_deepset(repo_id, local)
        else:
            _fetch_resolve(repo_id, filename, local, gated)
    print("done. (data-raw/*.jsonl is git-ignored and not redistributed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

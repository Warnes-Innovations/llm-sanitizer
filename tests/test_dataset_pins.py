# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the dataset-pin consistency guard (scripts/check_dataset_revisions.py).

`data-raw/SOURCES.md` restates each dataset's pinned revision in prose, while
`data-raw/pinned-revisions.json` holds the machine-readable copy. Only the JSON
is ever read by tooling — `check_dataset_revisions.py` loads it and nothing
else, and the scheduled `dataset-monitor.yml` workflow watches *those* values,
not the prose. So the prose could drift to a stale sha with nothing failing,
while remaining the thing a human reads to learn what the shipped `model.json`
was trained against.

These tests pin that invariant, and — importantly — also test the checker
itself against synthetic drift, so the guard is known to fire rather than
merely known to pass.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "check_dataset_revisions.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_dataset_revisions", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


class TestRepoPinsAgree:
    """The invariant itself: the two files must not disagree."""

    def test_sources_md_and_json_agree(self) -> None:
        assert checker.check_consistency() == []

    def test_every_json_dataset_is_documented_in_sources_md(self) -> None:
        import json

        json_pins = json.loads(checker._PINS.read_text(encoding="utf-8"))["datasets"]
        md_pins = checker.sources_md_pins(checker._SOURCES.read_text(encoding="utf-8"))
        assert set(json_pins) == set(md_pins)
        assert json_pins  # guard against a vacuous pass on an empty pin set

    def test_check_flag_exits_zero_without_network(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT), "--check"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


class TestCheckerDetectsDrift:
    """Negative controls — a guard never shown to fire is decoration.

    Each case feeds the comparison synthetic inputs, so these fail if the
    checker is ever weakened into always returning "no errors".
    """

    def test_mismatched_sha_is_reported(self) -> None:
        errors = checker.consistency_errors({"a/b": "a" * 40}, {"a/b": "b" * 40})
        assert len(errors) == 1
        assert "a/b" in errors[0]

    def test_dataset_missing_from_sources_md_is_reported(self) -> None:
        errors = checker.consistency_errors({"a/b": "a" * 40}, {})
        assert len(errors) == 1
        assert "SOURCES.md" in errors[0]

    def test_dataset_missing_from_json_is_reported(self) -> None:
        errors = checker.consistency_errors({}, {"a/b": "a" * 40})
        assert len(errors) == 1
        assert "pinned-revisions.json" in errors[0]

    def test_agreement_reports_nothing(self) -> None:
        assert checker.consistency_errors({"a/b": "a" * 40}, {"a/b": "a" * 40}) == []

    @pytest.mark.parametrize("bad_sha", ["c" * 40, "d" * 7])
    def test_script_exits_2_on_real_drift(self, tmp_path: Path, bad_sha: str) -> None:
        # End-to-end: corrupt a COPY of SOURCES.md and confirm the script exits 2.
        import json

        data_raw = tmp_path / "data-raw"
        data_raw.mkdir()
        (tmp_path / "scripts").mkdir()
        script_copy = tmp_path / "scripts" / "check_dataset_revisions.py"
        script_copy.write_text(_SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")

        original = checker._SOURCES.read_text(encoding="utf-8")
        json_pins = json.loads(checker._PINS.read_text(encoding="utf-8"))["datasets"]
        stale_sha = next(iter(json_pins.values()))
        (data_raw / "SOURCES.md").write_text(
            original.replace(stale_sha, bad_sha), encoding="utf-8"
        )
        (data_raw / "pinned-revisions.json").write_text(
            checker._PINS.read_text(encoding="utf-8"), encoding="utf-8"
        )

        proc = subprocess.run(
            [sys.executable, str(script_copy), "--check"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 2, proc.stdout + proc.stderr
        assert "mismatch" in proc.stdout.lower()


class TestSourcesMdParsing:
    def test_revision_is_attributed_to_its_heading(self) -> None:
        text = (
            "### owner/first\n"
            "- **Pinned revision:** `" + "1" * 40 + "`\n"
            "### owner/second\n"
            "- **Pinned revision:** `" + "2" * 40 + "`\n"
        )
        assert checker.sources_md_pins(text) == {
            "owner/first": "1" * 40,
            "owner/second": "2" * 40,
        }

    def test_revision_before_any_heading_is_ignored(self) -> None:
        assert checker.sources_md_pins("- **Pinned revision:** `" + "1" * 40 + "`\n") == {}

# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M0 — the directory-exclusion list reports its SIZE, not only its effect.

This scanner IS a trust boundary: an excluded directory is never examined for
injections. So the set of places it does not look has to be visible in its own output,
not only in its source. Reporting the effect alone makes a 7-name list and a 70-name one
render identically whenever both prune one directory.

Every guard here has a control, and the controls are the load-bearing half — a
"report" that always prints the same thing satisfies every positive assertion.
"""

from __future__ import annotations

from pathlib import Path

from llm_sanitizer.formatters.markdown_format import format_markdown
from llm_sanitizer.scanner import (
    _EXCLUDED_DIR_NAMES,
    Scanner,
    iter_scannable_files,
    walk_scannable,
)


def _tree(root: Path) -> None:
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("x", encoding="utf-8")
    (root / "venv").mkdir()
    (root / "venv" / "lib.py").write_text("y", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "a.md").write_text("hello", encoding="utf-8")


def test_the_wrapper_returns_exactly_what_it_always_did(tmp_path):
    """CONTROL for the refactor. `iter_scannable_files` is imported by cli.py,
    server.py, scanner.py and existing tests in a RELEASED package; adding the stats
    companion must not change its behaviour by one path."""
    _tree(tmp_path)
    files, _ = walk_scannable(tmp_path)
    assert iter_scannable_files(tmp_path) == files


def test_three_numbers_with_distinct_units(tmp_path):
    _tree(tmp_path)
    _, stats = walk_scannable(tmp_path)
    assert stats.specified == len(_EXCLUDED_DIR_NAMES)
    assert stats.matched == frozenset({".git", "venv"})
    assert stats.pruned_dirs == 2


def test_a_run_that_prunes_NOTHING_still_reports_the_list_size(tmp_path):
    """THE CASE THE RULE EXISTS FOR, and the one an implementation naturally omits.

    A list that never fires is exactly the list nobody re-derives. If the size appeared
    only when something was pruned, the exclusion set could grow for months while every
    clean run looked identical."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.md").write_text("hello", encoding="utf-8")

    _, stats = walk_scannable(tmp_path)
    assert stats.pruned_dirs == 0
    assert stats.matched == frozenset()
    assert stats.specified == len(_EXCLUDED_DIR_NAMES), (
        "the specified count must be reported even when nothing matched")


def test_matched_names_are_names_and_pruned_is_a_DIRECTORY_count(tmp_path):
    """Units, pinned. Two directories with the SAME excluded name must count as one
    matched NAME and two pruned DIRECTORIES — the distinction agent-config's first M0
    attempt got wrong by printing a file count under a pattern label."""
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "__pycache__").mkdir()
    (tmp_path / "a" / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "__pycache__").mkdir()
    (tmp_path / "b" / "__pycache__" / "y.pyc").write_bytes(b"\x00")

    _, stats = walk_scannable(tmp_path)
    assert stats.matched == frozenset({"__pycache__"}), "one NAME matched"
    assert stats.pruned_dirs == 2, "two DIRECTORIES pruned"


def test_scan_dir_carries_the_report_into_its_result(tmp_path):
    _tree(tmp_path)
    result = Scanner().scan_dir(str(tmp_path))
    assert result.exclusions_specified == len(_EXCLUDED_DIR_NAMES)
    assert sorted(result.exclusion_names_matched) == [".git", "venv"]
    assert result.dirs_pruned == 2
    assert result.files_scanned == 1


def test_the_markdown_report_states_where_the_scanner_did_not_look(tmp_path):
    """A report nobody sees is the thing M0 exists to prevent, so the human-readable
    path is asserted separately from the structured one."""
    _tree(tmp_path)
    md = format_markdown(Scanner().scan_dir(str(tmp_path)))
    assert "Directory exclusions:" in md
    assert f"2 of {len(_EXCLUDED_DIR_NAMES)} name(s) matched" in md
    assert "pruning 2 director(ies)" in md
    assert "never enumerated or scanned" in md


def test_the_markdown_report_appears_on_a_CLEAN_run_too(tmp_path):
    """Control for the test above: the line must not be conditional on something having
    been pruned, or the size vanishes exactly when the list is quietly growing."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.md").write_text("hello", encoding="utf-8")
    md = format_markdown(Scanner().scan_dir(str(tmp_path)))
    assert "Directory exclusions:" in md
    assert f"0 of {len(_EXCLUDED_DIR_NAMES)} name(s) matched" in md

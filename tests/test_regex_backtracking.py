# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Every compiled pattern in the rules and readers, fuzzed for catastrophic
backtracking.

A pattern with a nested repeat before a lookahead (`(?:\\*{1,3})+(?=...)`) ran
170 s on a 46-byte input, and the scan deadline could not interrupt it: it ran
over the whole content before any deadline check (0.7.2 review, pass 9). The
deadline bounds rule loops; it cannot bound a single `re` call, so each
pattern must be linear on its own.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time

import pytest

import llm_sanitizer.readers as readers_pkg
import llm_sanitizer.rules as rules_pkg

_CHARS = "*`~_[]()!<>&#;/=\"' .-:\n\t\u200b"


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    out: list[tuple[str, re.Pattern[str]]] = []
    for pkg in (rules_pkg, readers_pkg):
        for mod in pkgutil.iter_modules(pkg.__path__):
            try:
                module = importlib.import_module(f"{pkg.__name__}.{mod.name}")
            except ImportError:
                continue  # an optional extra's reader
            for name, value in vars(module).items():
                for label, pat in _found(f"{mod.name}.{name}", value, depth=0):
                    out.append((label, pat))
    # One entry per distinct pattern.
    seen: set[tuple[str, int]] = set()
    unique = []
    for label, pat in out:
        key = (pat.pattern, pat.flags)
        if key not in seen:
            seen.add(key)
            unique.append((label, pat))
    return unique


def _found(label: str, value: object, depth: int) -> list[tuple[str, re.Pattern[str]]]:
    """Patterns held directly, or in lists, tuples, dicts and classes (an
    earlier version saw only module-level patterns: 42 of 109, pass 10)."""
    if isinstance(value, re.Pattern) and isinstance(value.pattern, str):
        return [(label, value)]
    if depth > 2:
        return []
    out: list[tuple[str, re.Pattern[str]]] = []
    if isinstance(value, (list, tuple, set, frozenset)):
        for i, v in enumerate(value):
            out += _found(f"{label}[{i}]", v, depth + 1)
    elif isinstance(value, dict):
        for k, v in value.items():
            out += _found(f"{label}[{k!r}]", v, depth + 1)
    elif isinstance(value, type) and value.__module__.startswith("llm_sanitizer"):
        for k, v in vars(value).items():
            out += _found(f"{label}.{k}", v, depth + 1)
    return out


@pytest.mark.parametrize(("name", "pattern"), _patterns(), ids=lambda x: x if isinstance(x, str) else "")
def test_pattern_is_linear_on_repeated_characters(name: str, pattern: re.Pattern[str]) -> None:
    slow = []
    for ch in _CHARS:
        for shape in ("a" + ch * 40, "a" + ch * 40 + "b", ("a" + ch) * 2000, "a" + ch * 4000):
            t0 = time.perf_counter()
            for _ in pattern.finditer(shape):
                pass
            dt = time.perf_counter() - t0
            if dt > 0.25:
                slow.append((repr(shape[:6]), len(shape), round(dt, 2)))
    assert not slow, f"{name}: {slow[:3]}"

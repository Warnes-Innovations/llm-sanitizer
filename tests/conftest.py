# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared pytest fixtures for the llm-sanitizer test suite."""

from __future__ import annotations

import pytest

from llm_sanitizer.rules import _rescan
from tests.helpers.mock_llm import MockProtectedLLM, SandboxIOAdapter


@pytest.fixture(autouse=True)
def _fresh_rescan_budget() -> None:
    """Reset the de-obfuscation re-scan work budget before every test. Tests
    that call rule.detect() directly (no scanner) otherwise accumulate the
    ContextVar budget across the session; this gives each test a clean slate."""
    _rescan._scanned_bytes.set(0)
    _rescan._scanner_managed.set(False)


@pytest.fixture()
def sandbox_io() -> SandboxIOAdapter:
    """A fresh SandboxIOAdapter for each test -- blocks and records all I/O."""
    return SandboxIOAdapter()


@pytest.fixture()
def canary(sandbox_io: SandboxIOAdapter) -> MockProtectedLLM:
    """A fresh MockProtectedLLM wired to the sandbox for each test."""
    return MockProtectedLLM(io_adapter=sandbox_io)

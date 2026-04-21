# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared pytest fixtures for the llm-sanitizer test suite."""

from __future__ import annotations

import pytest

from tests.helpers.mock_llm import MockProtectedLLM, SandboxIOAdapter


@pytest.fixture()
def sandbox_io() -> SandboxIOAdapter:
    """A fresh SandboxIOAdapter for each test -- blocks and records all I/O."""
    return SandboxIOAdapter()


@pytest.fixture()
def canary(sandbox_io: SandboxIOAdapter) -> MockProtectedLLM:
    """A fresh MockProtectedLLM wired to the sandbox for each test."""
    return MockProtectedLLM(io_adapter=sandbox_io)

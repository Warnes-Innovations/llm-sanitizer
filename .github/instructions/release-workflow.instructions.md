<!--
Copyright (C) 2026 Gregory R. Warnes
SPDX-License-Identifier: AGPL-3.0-or-later
-->
---
description: "Use when testing, preparing, tagging, releasing, or publishing llm-sanitizer package versions. Covers repo-specific release commands, verification steps, and confirmation boundaries for push, tags, GitHub releases, and PyPI publication."
name: "llm-sanitizer Release Workflow"
---
# llm-sanitizer Release Workflow

- Treat release work in this repository as a staged workflow: inspect repo state, run tests, complete release-prep edits, validate packaging, then handle remote release steps.
- Preferred test command: `cd /Users/warnes/src/llm-sanitizer && uv run pytest tests/ -q --tb=short`
- Keep release edits minimal and targeted. Do not revert unrelated dirty-worktree files unless the user explicitly asks.
- Before any irreversible action, pause for confirmation even if the user's initial request already said to publish.
- The required confirmation boundary includes each of these actions: `git push` (to `devel`), merging the `devel → main` promotion PR, and GitHub Release creation (which triggers PyPI publication via Trusted Publishing). There is no separate manual PyPI upload step.
- When asking for confirmation, summarize the exact action, the version, and the branch or tag involved.
- After a live publish, verify the result end to end: PyPI visibility and at least one package resolution or install check.
- If clarification, triage, or blocker handling is needed, prefer creating or resuming an OBO session rather than handling it as an unstructured side conversation.

## Repo-specific notes

- Working directory: `/Users/warnes/src/llm-sanitizer`
- Default branch: `devel` (not `main`)
- Version is dual-sourced across **two files that must stay in sync**: `pyproject.toml` (`version`) and `src/llm_sanitizer/__init__.py` (`__version__`)
- **`main` is protected**: releases reach `main` **only via a merged pull request** from `devel` (`gh pr create --base main --head devel` → `gh pr merge <PR#> --merge`, never `--delete-branch` — `devel` is the permanent trunk). Never merge or push to `main` locally, and never force.
- Build backend: `hatchling` (via `uv build`)
- Entry points: `llm-sanitizer` (MCP server) and `llm-sanitize` (CLI)
- Two distributions: base package + optional `[binary]` extra for `markitdown`
- PyPI package name: `llm-sanitizer`
- PyPI wheel artifact name: `llm_sanitizer-X.Y.Z-py3-none-any.whl`
- Test command: `uv run pytest tests/ -q --tb=short`
- Local build (smoke test only): `uv build --wheel --out-dir dist/` — the published artifact is built in CI, not locally
- **Publication is automated via Trusted Publishing (OIDC)**: cutting a GitHub Release on `main` (`gh release create vX.Y.Z --target main`) triggers `.github/workflows/publish.yml`, which builds and uploads to PyPI. There is **no** `uv publish` step and **no** `UV_PUBLISH_TOKEN` — do not attempt a manual token upload.
- CHANGELOG format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with Semantic Versioning

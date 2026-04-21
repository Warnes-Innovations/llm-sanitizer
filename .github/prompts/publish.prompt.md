<!--
Copyright (C) 2026 Gregory R. Warnes
SPDX-License-Identifier: AGPL-3.0-or-later
-->
---
name: publish
description: Publish the llm-sanitizer package to PyPI — runs tests, updates changelog, builds, tags, and publishes with confirmation gates at each irreversible step
argument-hint: Optional version bump type (patch | minor | major) or explicit version number (e.g. 0.2.0)
---

# Publish Workflow — llm-sanitizer

Use this prompt to release a new version of `llm-sanitizer` to PyPI.
Every irreversible action (git push, tag creation, GitHub release, PyPI upload) requires
explicit user confirmation before proceeding.

Read `.github/instructions/release-workflow.instructions.md` before starting
to pick up any repo-specific rules not covered here.

## Step 1: Establish Repo State

- Confirm the working directory is `/Users/warnes/src/llm-sanitizer`
- Run `git status` and `git log --oneline -8` to summarize uncommitted changes and recent commits
- If there are uncommitted changes, list them and ask whether to commit, stash, or abort before continuing
- Read `pyproject.toml` to determine the current version
- Identify the version bump to apply: use the argument if one was supplied, otherwise ask the user
  (choices: `patch`, `minor`, `major`, or an explicit version string)

## Step 2: Run the Full Test Suite

Run:
```bash
cd /Users/warnes/src/llm-sanitizer
uv run pytest tests/ -q --tb=short > /tmp/llm_san_publish_tests.txt 2>&1
tail -20 /tmp/llm_san_publish_tests.txt
```

- Report the exact counts (passed / failed / errors)
- If any tests fail, stop and do not proceed to version bump or publish
- If all tests pass, state the count explicitly and continue

## Step 3: Bump the Version

- Compute the new version from the current version in `pyproject.toml` and the bump type
- Show the user: current version → proposed new version
- **STOP and ask for confirmation before editing any file**
- After confirmation, update `version` in `pyproject.toml`

## Step 4: Update CHANGELOG.md

- Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` (using today's date)
- Add a new empty `## [Unreleased]` section above it
- Populate the new versioned section with a summary of changes since the last release:
  ```bash
  git log --oneline $(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD
  ```
- **STOP and ask for confirmation before saving CHANGELOG.md**

## Step 5: Validate the Package Build

Run:
```bash
cd /Users/warnes/src/llm-sanitizer
uv build --wheel --out-dir dist/
```

- Confirm the `.whl` file is created with the expected version in its filename
- Run a quick smoke check:
  ```bash
  uv run --with dist/llm_sanitizer-X.Y.Z-py3-none-any.whl llm-sanitize --help 2>&1 | head -5
  ```
- If the build fails, stop and report the error

## Step 6: Commit the Version Bump

- Stage `pyproject.toml` and `CHANGELOG.md`
- Propose a commit message: `release: bump version to X.Y.Z`
- **STOP and ask for confirmation before running `git commit`**
- After confirmation, commit

## Step 7: Merge devel → main

> **Rule**: releases must be cut from `main`. Development happens on `devel`;
> merge it to `main` before tagging so the tag lands on `main`.

- Confirm the current branch is `devel` and the working tree is clean
- **STOP and ask for confirmation before merging**
- After confirmation:
  ```bash
  git checkout main
  git merge --ff-only devel
  ```
- If `--ff-only` fails (histories have diverged), stop and report the conflict — do not force-merge
- After a successful merge, confirm `main` and `devel` point to the same commit:
  ```bash
  git log --oneline -1 main && git log --oneline -1 devel
  ```

## Step 8: Tag the Release

- Propose the tag name: `vX.Y.Z`
- **STOP and ask for confirmation before creating the tag**
- After confirmation (while on `main`): `git tag -a vX.Y.Z -m "Release X.Y.Z"`

## Step 9: Push Commits and Tag

- Summarize: branch `main`, tag `vX.Y.Z`, and branch `devel` will be pushed to `origin`
- **STOP and ask for confirmation before running `git push`**
- After confirmation:
  ```bash
  git push origin main
  git push origin vX.Y.Z
  git push origin devel
  ```

## Step 10: Create GitHub Release

- Create a GitHub release from tag `vX.Y.Z`:
  ```bash
  gh release create vX.Y.Z dist/llm_sanitizer-X.Y.Z-py3-none-any.whl \
    --title "llm-sanitizer X.Y.Z" \
    --notes "$(sed -n '/^## \[X.Y.Z\]/,/^## \[/p' CHANGELOG.md | head -n -1)"
  ```
  (or use the GitHub web UI from the new tag)
- **STOP and ask for confirmation before creating the release**

## Step 11: Publish to PyPI

- Summarize: package `llm-sanitizer X.Y.Z` will be uploaded to PyPI
- **STOP and ask for confirmation before uploading**
- After confirmation:
  ```bash
  uv publish dist/llm_sanitizer-X.Y.Z-py3-none-any.whl
  ```
  (requires `UV_PUBLISH_TOKEN` env var set to your PyPI API token,
  or pass `--token <token>` explicitly)

## Step 12: Verify the Release

After publishing, verify end to end:

1. Check that the package resolves from PyPI:
   ```bash
   pip index versions llm-sanitizer 2>&1 | head -5
   ```
2. Optionally install and confirm entry points:
   ```bash
   uvx llm-sanitize --help 2>&1 | head -5
   ```
3. Visit `https://pypi.org/project/llm-sanitizer/` and confirm the new version is listed

Report the final result: version published, PyPI URL, and any follow-up items.

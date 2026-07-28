<!--
Copyright (C) 2026 Gregory R. Warnes
SPDX-License-Identifier: AGPL-3.0-or-later
-->
---
name: publish
description: Release a new llm-sanitizer version — runs tests, bumps both version files, updates the changelog, and promotes devel → main via PR so a GitHub Release publishes to PyPI through Trusted Publishing, with confirmation gates at each irreversible step
argument-hint: Optional version bump type (patch | minor | major) or explicit version number (e.g. 0.4.0)
---

# Publish Workflow — llm-sanitizer

Use this prompt to release a new version of `llm-sanitizer` to PyPI.

**How releases actually work here (read before starting):**
- `devel` is the working trunk; **`main` is protected** — no direct pushes, even for
  admins. Changes reach `main` **only via a pull request** from `devel`.
- **PyPI publication is automated via Trusted Publishing (OIDC).** Cutting a GitHub
  **Release** on `main` triggers `.github/workflows/publish.yml`, which builds and
  uploads to PyPI. There is **no local `uv publish`** and **no `UV_PUBLISH_TOKEN`**.
- The version lives in **two files that must stay in sync**: `pyproject.toml` and
  `src/llm_sanitizer/__init__.py`.
- Every irreversible action (push, PR merge, GitHub Release → PyPI) requires explicit
  user confirmation before proceeding. A PyPI version is **permanent even if yanked**.

Also read `.github/instructions/release-workflow.instructions.md` for repo-specific rules.

## Step 1: Establish Repo State

- Confirm the working directory is `/Users/warnes/src/llm-sanitizer` and the current branch is `devel`
- Run `git status` and `git log --oneline -8` to summarize uncommitted changes and recent commits
- If there are uncommitted changes, list them and ask whether to commit, stash, or abort before continuing
- Read the current version from `pyproject.toml` **and** `src/llm_sanitizer/__init__.py`; if they
  disagree, stop and flag it (they have drifted before)
- Identify the version bump to apply: use the argument if supplied, otherwise ask the user
  (`patch`, `minor`, `major`, or an explicit version). **SemVer on the 0.x line:** feature additions
  bump the minor (`0.3.x → 0.4.0`); reserve `1.0.0` for a committed-stable API

## Step 2: Run the Full Test Suite

Run:
```bash
cd /Users/warnes/src/llm-sanitizer
uv run pytest tests/ -q --tb=short > tmp/llm_san_publish_tests.txt 2>&1
tail -20 tmp/llm_san_publish_tests.txt
```

- Report the exact counts (passed / failed / errors)
- If any tests fail, stop and do not proceed
- Also run `uv run mypy src/` and confirm it is clean
- If all pass, state the counts explicitly and continue

## Step 3: Bump the Version (BOTH files)

- Compute the new version from the current version and the bump type
- Show the user: current version → proposed new version
- **STOP and ask for confirmation before editing any file**
- After confirmation, update **both**:
  - `version` in `pyproject.toml`
  - `__version__` in `src/llm_sanitizer/__init__.py`
- Keep them identical

## Step 4: Update CHANGELOG.md

- Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` (today's date)
- Add a new empty `## [Unreleased]` section above it
- Ensure the versioned section summarizes the changes since the last release; if it's thin, draft
  from `git log --oneline $(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD`
- Mark any **breaking** changes in a clearly-labelled subsection (consumers such as flow-guard gate on this)
- **STOP and ask for confirmation before saving CHANGELOG.md**

## Step 5: Validate the Package Build (local smoke test)

The published artifact is built by `publish.yml` in CI; this local build is only a pre-flight check.
```bash
cd /Users/warnes/src/llm-sanitizer
uv build --wheel --out-dir dist/
uv run --with dist/llm_sanitizer-X.Y.Z-py3-none-any.whl llm-sanitize --help 2>&1 | head -5
```
- Confirm the `.whl` filename carries the expected version and the CLI entry point runs
- If the build fails, stop and report the error

## Step 6: Commit the Release Prep on devel

- Stage `pyproject.toml`, `src/llm_sanitizer/__init__.py`, and `CHANGELOG.md`
- Propose a commit message: `chore(release): bump version to X.Y.Z`
- **STOP and ask for confirmation before running `git commit`**
- After confirmation, commit, then **STOP and ask for confirmation before `git push origin devel`**

## Step 7: Promote devel → main via Pull Request

> **`main` is protected — promotion is ALWAYS via PR.** Never `git checkout main` and merge locally;
> never force. `main` accepts changes only through a merged PR from `devel`.

- Confirm `devel` is pushed and its tree is clean
- **STOP and ask for confirmation before opening the PR**, then:
  ```bash
  gh pr create --base main --head devel \
    --title "chore(release): promote devel → main (vX.Y.Z)" \
    --body "Summarize what consumers gain in this release."
  ```
- **STOP and ask for confirmation before merging**, then merge (0 required approvals, so the
  maintainer can self-merge):
  ```bash
  gh pr merge <PR#> --merge      # do NOT pass --delete-branch — devel is the permanent trunk
  ```
- Confirm the bump is now on `main`:
  ```bash
  gh api repos/Warnes-Innovations/llm-sanitizer/contents/pyproject.toml --jq '.content' \
    | base64 -d | grep '^version'
  ```

## Step 8: Cut the GitHub Release (this publishes to PyPI)

Creating the Release on `main` triggers `publish.yml` → Trusted Publishing → PyPI. **This is the
point of no return: a PyPI version is permanent even if yanked.**

- Summarize: tag `vX.Y.Z`, target `main`, will publish `llm-sanitizer X.Y.Z` to PyPI
- **STOP and get explicit confirmation**, then:
  ```bash
  gh release create vX.Y.Z --target main --title "vX.Y.Z" \
    --notes "See CHANGELOG.md for the full list."
  ```
  (The tag is created by this command; no separate `git tag`/`git push` step.)

## Step 9: Watch the Publish Workflow

- Watch the run to success:
  ```bash
  gh run watch "$(gh run list --workflow=publish.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
  ```
- If it fails, stop and report — do NOT attempt a manual `uv publish` (Trusted Publishing is the
  only supported path; a token upload is not configured)

## Step 10: Verify the Release

1. Confirm the version is live on PyPI:
   ```bash
   curl -s https://pypi.org/pypi/llm-sanitizer/json | python -c 'import sys,json;print(json.load(sys.stdin)["info"]["version"])'
   ```
2. Optionally resolve the entry point:
   ```bash
   uvx --refresh llm-sanitizer==X.Y.Z --help 2>&1 | head -5
   ```
3. Visit `https://pypi.org/project/llm-sanitizer/` and confirm the new version

## Step 11: Tell Consumers to Refresh

Consumers that pin the moving `@main` git ref (e.g. flow-guard's `.mcp.json`) may keep serving a
**cached** `uvx` build after the promotion. Tell the maintainer that to pick up the new `main`
immediately they can run:
```bash
uvx --refresh --from git+https://github.com/Warnes-Innovations/llm-sanitizer.git@main llm-sanitizer
# or clear the cache:  uv cache clean llm-sanitizer
```
Consumers pinned to a **PyPI version** (`uvx llm-sanitizer==X.Y.Z`) pick up the new version by
bumping that pin.

Report the final result: version published, PyPI URL, workflow run status, and any follow-up items.

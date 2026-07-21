# llm-sanitizer — agent guide

## Branch model & release ritual

This repo uses a two-branch model:

- **`devel`** — the working trunk. All day-to-day commits land here (default branch).
- **`main`** — the **released** branch. Downstream consumers pin this, e.g. flow-guard's
  `.mcp.json` runs the server via
  `uvx --from git+https://github.com/Warnes-Innovations/llm-sanitizer.git@main llm-sanitizer`.
  Consumers only see a change **after it reaches `main`**.

`main` is **protected**: no direct pushes (enforced for admins too). Changes reach `main`
**only via a pull request** from `devel` (0 required approvals, so the maintainer can self-merge).

### Promote `devel → main` at appropriate intervals

**Agent instruction:** When `devel` has accumulated stable changes that consumers should pick
up — especially security/correctness fixes to the scanner — **proactively prompt the maintainer
to promote `devel → main`**. Do not let released consumers drift far behind `devel`.

Good moments to prompt:

- After merging security or content-integrity hardening.
- After a fix to a user-reported scanning bug.
- Before asking a consumer (e.g. flow-guard) to rely on new behavior.

A promotion is also a **release**: it should cut a versioned GitHub Release so
the new code reaches PyPI (consumers pin a PyPI version, e.g.
`uvx llm-sanitizer==X.Y.Z`). Full procedure (`main` is protected, so promotion
is always via PR):

```bash
# 1. On devel, clean tree: bump the version in BOTH pyproject.toml AND
#    src/llm_sanitizer/__init__.py (keep them in sync — they have drifted
#    before), and move CHANGELOG [Unreleased] -> [X.Y.Z] - <date>. Commit + push.

# 2. Open the promotion PR and merge it (brings the bump onto main):
gh pr create --base main --head devel \
  --title "chore(release): promote devel → main (vX.Y.Z)" \
  --body "Summarize what consumers gain."
gh pr merge <PR#> --merge      # do NOT pass --delete-branch (devel is the trunk)

# 3. Tag main and cut the Release — triggers publish.yml (Trusted Publishing)
#    and publishes to PyPI. IRREVERSIBLE: a PyPI version is permanent even if
#    yanked. Confirm with the maintainer before running this step.
gh release create vX.Y.Z --target main --title "vX.Y.Z" --notes "See CHANGELOG.md."
```

Never delete `devel` when merging — it is the permanent working trunk.

**Versioning (SemVer):** on the `0.x` line, feature additions bump the minor
(`0.1.x → 0.2.0`); reserve `1.0.0` for a committed-stable API. Don't inflate the
minor for signalling. The version currently lives in two files — single-sourcing
it (e.g. `importlib.metadata`) is a good follow-up.

### Consumers may need `--refresh` after a promotion

Consumers pin a **moving branch ref** (`@main`), and `uvx` caches built environments. After a
`devel → main` promotion, a consumer running `uvx --from git+…@main llm-sanitizer` may keep
serving the **previously cached** build until its cache refreshes — so the new `main` code does
not always take effect immediately on the next session.

To force a consumer to pick up the just-promoted `main`:

```bash
uvx --refresh --from git+https://github.com/Warnes-Innovations/llm-sanitizer.git@main llm-sanitizer
# or clear the uv cache:  uv cache clean llm-sanitizer
```

**Agent instruction:** when you promote `devel → main` for a change a consumer needs *now*
(e.g. a security fix flow-guard must use immediately), tell the maintainer that consumers may
need a `uvx --refresh` (or a uv cache clean) before the new build is live.

## Local development vs. released consumption

- **This repo's own `.mcp.json`** runs the server from local files (`uv run llm-sanitizer`) so it
  reflects your working tree instantly — correct for developing the server.
- **Consumers** (flow-guard) default to the released `@main` build. A developer who wants a
  consumer to exercise *local* llm-sanitizer edits adds a machine-local override that silently
  wins over the committed default:

  ```bash
  claude mcp add --transport stdio llm-sanitizer -s local -- \
    uv run --directory ~/src/llm-sanitizer llm-sanitizer
  ```

  Remove it to return to the released build: `claude mcp remove llm-sanitizer -s local`.

## Detection-rule design principles

**An obfuscation rule should only fire if de-obfuscating reveals problematic
text.** Obfuscation — base64, homoglyph/confusable substitution, zero-width
characters, hidden/CSS-invisible text, and the like — is a *transport*, not a
threat in itself. Such a rule must de-obfuscate the content (decode, normalize,
strip, un-hide) and then decide based on whether the *recovered* text is
actually problematic — i.e. whether it trips another detection rule — never on
the mere presence of the obfuscation.

- ✅ CORRECT: base64 decodes each blob and re-scans the decoded text with the
  full ruleset (`rules/_rescan.py::scan_deobfuscated`); homoglyph normalizes
  lookalikes and flags only when the normalized text is a known
  instruction-override term or trips a rule. Innocent base64 (keys, hashes, an
  encoded innocuous sentence) and innocent mixed-script (`Aβ`, `5µm`, `10kΩ`)
  stay clean.
- ❌ INCORRECT: flagging base64 merely because it decodes to prose, or a word
  merely because it mixes scripts — this floods consumers with false positives
  on scientific / internationalized / encoded-but-benign text and trains users
  to ignore the scanner.
- **Why:** the value of an obfuscation rule is catching a *hidden injection*,
  not penalizing encoding. De-obfuscate-then-re-scan keeps precision high and
  reuses the real detection rules as the single source of truth for "is this
  problematic".
- **Whole class.** When adding or reviewing any obfuscation rule, route through
  the shared `scan_deobfuscated` helper (depth-guarded, so obfuscation rules can
  safely recurse into one another). `zero_width` and `hidden_content` still flag
  on presence and should be migrated to this pattern.

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
- **Whole class.** Route de-obfuscation through the shared `scan_deobfuscated`
  helper (depth-guarded, so obfuscation rules can safely recurse into one
  another). `base64`, `homoglyph`, and `zero_width` all follow this — they
  decode / normalize / strip and re-scan, flagging only what the *recovered*
  text trips.
- **Transport vs. steganography.** The de-obfuscate-then-re-scan rule above is
  for *transport* obfuscation, where the hidden text is recoverable (decode
  base64, normalize homoglyphs, strip zero-width splitters). *Camouflage* rules
  (`hidden_content`) need a further distinction:
  - **Structural hiding** — `display:none`, `visibility:hidden`, the `hidden`
    attribute, off-screen `.sr-only`, hidden spreadsheet rows/sheets — is
    ubiquitous, legitimate responsive/accessibility/document formatting and is
    **NOT flagged**. Any injection inside it is already caught by the injection
    rules scanning the raw markup, so flagging the mechanism only floods false
    positives.
  - **Perceptual camouflage** — text rendered but made imperceptible with no
    legitimate purpose: `color` ≈ `background`, near-zero `opacity` (not a
    transition start-state), `font-size:0`, sub-legible fonts, invisible tag
    characters (U+E0000). This **is** flagged: MEDIUM on its own, escalated to
    CRITICAL when the camouflaged text also trips an injection rule.
  The durable tell is `perceived-by-human` vs `emitted-by-extractor`: flag the
  delta, not the specific CSS trick.

## LLM Wiki

This project maintains an LLM-curated wiki at `wiki/` following Andrej Karpathy's "LLM Wiki" pattern (https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).

Before answering questions that rely on knowledge accumulated in this project, read `wiki/index.md` (or the relevant shard under `wiki/indexes/` if the wiki has been sharded) and use its one-line summaries to find the pages you need. Cite with `[[wikilinks]]`. If the index does not surface good candidates, fall back to `wiki_search.py` from the `llm-wiki` skill for BM25-ranked retrieval.

To add a new source, follow the `llm-wiki` skill's ingest workflow: decide placement under `wiki/sources/`, `wiki/entities/`, `wiki/concepts/`, or `wiki/synthesis/`; identify touched pages and make surgical `str_replace` updates rather than rewrites; update the index; append a one-line entry to `wiki/log.md`.

Scaling discipline: atomic pages (400-line soft cap, 800-line hard cap), sharded indexes past ~150 pages or 300 index lines, required YAML frontmatter on every page, `[[wikilinks]]` for every cross-reference.

Full conventions live in `wiki/SCHEMA.md`. Treat it as authoritative when it disagrees with this summary.

# BEGIN managed-by-agent-config
## MANDATORY: Read project instructions first

At the start of every task, read `.github/copilot-instructions.md` in full.

## Answer Self-Test (MANDATORY — run before sending every response)

1. If the reader sees only my first sentence, do they do the right next thing?
2. Which claims did I verify, which did I infer, which did I assume — and can the reader tell the difference?
3. What single claim, if wrong, sinks this answer — and did I re-derive it, or just recognize it?
4. What did I do because the words said so that the person wouldn't actually want?
5. If this is wrong, do they find out from me, now — or from the failure, later?

If any answer is uncomfortable, the response isn't ready.
Full rationale and procedures: `~/src/agent-config/docs/OPERATING_MANUAL.md`

## Available Skills

User-level shared skills live in `~/src/agent-config/.github/skills/`.
Examples include review workflows such as `duckflow` and Codex bridge skills such as `flush-codex`.

To read a skill: `read_file` on `SKILL.md` inside the relevant directory.

## Available Slash Command Prompts

Prompt files live in `~/src/agent-config/prompts/`.
Examples include workflow prompts such as `/duckflow` and `/flush`.
When the user invokes a slash command, read the corresponding `.prompt.md` file.

## MCP Tools available in Cline

- Prefer the 'oboe-mcp' MCP tools for OBO session state.
- Do not edit .github/obo_sessions/*.json directly or use 'obo_helper.py' when 'oboe-mcp' can perform the operation. Fall back to 'oboe-cli' when the MCP server is unavailable.
- **oboe-mcp**: `obo_list_sessions`, `obo_create`, `obo_session_status`, `obo_next`, `obo_list_items`, `obo_get_item`, `obo_mark_blocked`, `obo_mark_complete`, `obo_mark_in_progress`, `obo_mark_skip`, `obo_set_approval`, `obo_complete_session`, `obo_create_child_session`, `obo_complete_child_session`, `obo_merge_items`, `obo_update_field`
- **oboe-cli fallback** (when MCP unavailable): all session-scoped commands take `--session SESSION [--base-dir DIR]`
  - sessions/status/next/complete-session/list/show/in-progress/block/complete/skip/approve/update/merge/create-child/complete-child
  - `create` and `merge` require `--input-file items.json` (items as a JSON array)
  - Example: `oboe-cli --base-dir . --session SESSION.json complete ITEM_ID "resolution text"`
- **markitdown**: Convert documents/URLs to Markdown for reading.
# END managed-by-agent-config

# Committee Review — `bastion` extraction plan

**Artifact reviewed:** `/Users/warnes/.claude/plans/the-current-agent-security-nifty-beaver.md`
(the plan to extract flow-guard's agent-security harness into a standalone project, `bastion`).
**Reviewers:** security-engineer, red-teamer, llm-software-developer, mcp-tool-designer,
performance-reliability-engineer, compliance-risk-officer, secrets-pattern-reviewer (7 personas,
run in parallel).
**Outcome:** 6 Critical + 11 Major + ~10 Minor findings. Plan was **not approved as written**;
all Critical + Major findings were folded into a revised plan after this review.

## Executive summary

The plan's instincts are strong — llm-sanitizer kept as an explicit trust boundary, a golden
byte-equality gate, a "never drop a deny" merge, honest Docker caveats carried forward. But three
reviewers independently converged on one **root cause**: the plan repeatedly **collapses
independent security layers into a single tamperable/deletable thing** —

- two hook signals (`basename==flow-guard` OR `-f fg-sandbox.sh`) → one deletable marker
- two independently-maintained pins (native `.mcp.json` + hash-locked docker lockfile) → one field
- hardened sandbox scalars → user-preserved keys under an additive merge
- policy **and** its own drift-check baseline → one manifest (`.bastion.yml`)

Each collapse violates the maintainer's own belt-and-suspenders rule. The single most load-bearing
fix is a **hardcoded security floor + union-style, fail-toward-safe logic** across the hook, the
merge, and the manifest validator.

**Cross-cutting caveat:** several fixes depend on **Claude Code's actual precedence** (allow-vs-deny,
`allowRead`-vs-`denyRead`, behavior on a missing sandbox path, and whether the sandbox covers the
MCP subprocess so `scan_url` can even reach the web). These are **unverified** and must be confirmed
on the running Claude Code version before implementation — they gate Criticals 1, 2, and 5.

## Critical findings

1. **The merge weakens the sandbox it exists to preserve.** (llm-software-dev C1, red-teamer RT-3,
   secrets F2/F3, security-eng F1) "Additive union, never drop a deny" is right for deny-lists but
   backwards for allow-side fields: it preserves a hostile pre-existing `permissions.allow`
   (`WebFetch(domain:*)`, `Read(~/.ssh/**)`), preserves weakening sandbox scalars (`enabled:false`,
   `allowUnsandboxedCommands:true`, `failIfUnavailable:false` → fail-**open**), never covers the
   credential object-lists (`sandbox.credentials.files[]`/`envVars[]`), and has no mode-downgrade
   protection (`deny`→`ask`). Fix: polarity-aware merge; template wins for security scalars + a
   hardcoded deny floor; strip pre-existing allows intersecting a harness deny; most-restrictive-
   mode-wins; extend adversarial tests to the object-lists.

2. **The manifest is an unbounded privilege-widener, invisible to its own drift-check.**
   (security-eng F1, red-teamer RT-2) `extra_allow_read`/`network_allow` can name `~/.ssh`,
   `/Users/warnes` (the path `denyRead` blocks), or an exfil domain; `profile: high-risk→standard`
   drops the sole isolation control under `--dangerously-skip-permissions`. Because `bastion check`
   compares rendered files **against the manifest**, a poisoned manifest reports zero drift. Fix:
   hardcoded non-overridable deny floor; schema-validate and reject allow-entries intersecting it;
   diff the manifest against git history for security-downgrading deltas.

3. **The generalized hook collapses to a single deletable marker (fail-open).** (red-teamer RT-1,
   security-eng F3) `-f .bastion.yml` alone — `rm`/rename/old-branch-checkout drops the hard-block
   while `CLAUDE.md` still claims enforcement is active. Fix: keep detection a union that fails
   toward hard-block (marker OR settings.json has a `sandbox` block OR a legacy launcher); flag
   "settings present, marker missing" as tampering.

4. **The cross-machine render/commit model is self-contradictory for a two-OS user.**
   (performance C1/M1/M2/M3, llm-software-dev M2) macOS + Linux: committing the rendered
   `settings.json` makes the two checkouts fight over `/Users/warnes` vs `/home/warnes`;
   gitignoring it leaves a fresh clone with the marker (→ new hard-block) but no enforcement →
   bricked. Golden byte-equality can't pass in Linux CI; `~/Library` vs XDG is structural, not a
   prefix-swap; a missing sibling path + `failIfUnavailable:true` bricks the session. Fix: pick one
   model (recommended: gitignore rendered files, `.bastion.yml` as the sole committed source,
   render required post-clone, hook keys on marker **and** enforcement-present); OS-aware
   `context.py`; frozen synthetic fixture + parsed-structure (not byte) equality.

5. **The trust-boundary's fail-posture is undefined — it can be silently absent.**
   (performance C2, red-teamer RT-7, mcp-designer F5) If `uvx` can't build/reach the scanner
   (network, deleted tag, cold cache under a sandbox denying the cache path, build failure), the
   MCP server never starts and the plan doesn't say the agent fails closed. Default `network_allow`
   omits PyPI, so a clean machine may never resolve the scanner; `doctor` checks tag-existence, not
   "does the server answer." Fix: injected protocol states server-unavailable = refuse untrusted
   content; `doctor` + session-start gate call `list_rules`; `network_allow` permits `uvx`
   resolution + `scan_url` egress; prefer a published PyPI pin.

6. **Secret-scanning configs shipped "verbatim" carry flow-guard's allowlist into every repo.**
   (secrets F1) Live `.gitleaks.toml` allowlists `business-plan/People/*.html` (disabling scanning
   there) and `.gitleaksignore` holds flow-guard fingerprints → every harnessed repo inherits a
   silent, repo-wide leak hole. Fix: genericize — ship an empty allowlist and empty baseline;
   per-repo tuning is never inherited.

## Major findings

7. **`init` is not transactional** — manifest-written-first is the worst order; a partial install
   leaves marker-without-enforcement → bricked repo. Stage-verify-commit, write `.bastion.yml`
   last, roll back on failure, `.bak` the existing settings. (performance C3, llm-sw m7)
8. **Single-source pin can't render the hash-locked docker lockfile** (`requirements-docker.txt` is
   sha256-pinned), removes the independent native-vs-docker cross-check, and doesn't reject
   branch/sha pins on the trust boundary. Own a `pip-compile` regen step (golden-tested) or scope
   "single-source" to the standard profile; `pin.py` requires an immutable released tag + `v`-prefix
   normalization. (mcp F1/F2/F4, red-teamer RT-4)
9. **Frozen 7-of-9 tool allow-list** (`scan_dir`/`redact_dir` omitted) with no drift check vs the
   pinned server's tool surface → a pin bump that renames/adds a tool causes a silent
   permission-prompt hang. `doctor` asserts allow-list ⊆ pinned-server tools; document the
   least-privilege subset. (mcp F3)
10. **Credential env-var exposure under `--dangerously-skip-permissions`** — the `envVars` deny is
    void in high-risk mode; verify `agent-sandbox.sh` doesn't pass `-e ANTHROPIC_API_KEY`/tokens.
    Risk 7 wrongly implies mount isolation covers env vars. (security-eng F4, secrets F4)
11. **The security header is load-bearing runtime instruction text, not copyedit fodder** — a
    genericizing pass can soften a fail-closed branch. Content-assert the rendered header keeps
    every error/fail-closed branch + confirmation format; bake "what this does NOT protect" into the
    injected header so caveats travel into the adopter repo. (llm-sw M3, compliance F6)
12. **Verification lacks negative/adversarial tests**; golden proves only flow-guard reproduction,
    not that a fresh `init` gets the full credential baseline in both layers. Add: hostile-manifest-
    can't-widen-to-creds, marker-removal-detected, incoming-allow-can't-override-baseline-deny,
    init-twice-idempotent, fresh-repo-credential-completeness. (security-eng F6, secrets F6,
    llm-sw M1, red-teamer RT-8)
13. **AGPL "user not distributor" is overbroad and asserted as fact** — Phase 1 copies AGPL
    personas/scripts/docs verbatim into adopter repos; an adopter who conveys that repo is
    distributing AGPL material. Also a likely B2B procurement blocker. Split the claim, label
    not-legal-advice, get counsel review; consider a permissive license for emitted templates;
    ensure SPDX headers survive rendering. (compliance F1/F2/F3)
14. **Phase-5 cutover has a protection-lapse window** — a marker-only global hook leaves pre-marker
    flow-guard branches/worktrees unprotected; `sync.py` must be green in pre-commit before
    `check_sync.py` is removed; rollback is a state not a runbook and is coupled to the global-hook
    swap; the `FLOW_GUARD_ALLOW_SUBDIR` escape hatch is dropped (rename `BASTION_ALLOW_SUBDIR`).
    (red-teamer RT-5/RT-6, performance M6)
15. **No `SECURITY.md` / disclosure / fix-propagation** for a security tool whose consumers pin +
    `uvx`-cache builds — a fix may never reach them. Add advisory workflow + `--refresh`
    propagation guidance + a `doctor` advisory-floor warning. (compliance F7)
16. **Thin audit provenance** — `.bastion.yml` records intent, not when/who/what-digest, and lists
    personas by name only (self-inconsistent for a supply-chain-audit tool). Add a `.bastion.lock`
    with timestamps/actor/per-file digests and per-persona `source`+`sha256`. (compliance F4/F5)
17. **bastion is itself a supply-chain fan-out point** — `update` re-render could silently weaken
    every harnessed repo. `update` must show a security-relevant diff and confirm; refuse silent
    profile upgrades on version skew. (security-eng F2)

## Minor findings (collapsed)

`update` command unassigned to any phase and untested · idempotency/dedup untested · load package
data via `importlib.resources` not `__file__` · declared `llm-sanitizer` dep may be unused/dual-
version (verify) · gitleaks version needs its own pin/currency check (`gitleaks_pin`) · host
`CLAUDE.md` vs injected-header precedence · `redact` returns text while others return JSON (document
in header) · SARIF outputs must be gitignored and `sarif_review.py`'s escape-sanitization test
preserved · global-hook install needs a confirm+diff gate · `doctor` should assert the CC-version
subdir-loading quirk still holds · pin bastion's own deps / verify image tags are not floating.

## Per-persona status

| Persona | Findings (C/M/m) | Notable red flags triggered |
|---|---|---|
| security-engineer | 1 / 6 / 3 | env-var exposure under skip-perms; fail-open marker; SARIF excerpts in VC; floating tags |
| red-teamer | 3 / 4 / 1 | "collapse layers into one deletable/tamperable thing" (×3); scanner-unavailable fail-open |
| llm-software-developer | 1 / 4 / 8 | allow-side merge widening; byte-equality wrong invariant; unused dep |
| mcp-tool-designer | 0 / 3 / 3 | can't render hash-locked docker pin; branch-pin on trust boundary; frozen tool subset |
| performance-reliability | 3 / 6 / 3 | two-OS commit model; undefined MCP fail-posture; partial-install brick |
| compliance-risk-officer | 0 / 6 / 3 | AGPL overreach; no SECURITY.md; thin provenance |
| secrets-pattern-reviewer | 1 / 3 / 3 | verbatim gitleaks allowlist inherited; credential object-lists in merge |

## Recommended action order

1. **Verify Claude Code precedence** (allow/deny, allowRead/denyRead, missing-path behavior,
   MCP-subprocess sandbox coverage) — gates Criticals 1, 2, 5.
2. Redesign **merge (C1)**, **manifest security floor (C2)**, **union hook (C3)** — the root-cause
   cluster.
3. Resolve the **two-OS render/commit model (C4)** and **fail-closed scanner posture (C5)**.
4. Genericize **secret-scanning configs (C6)**; make **`init` transactional (M7)**.
5. Fold the remaining Majors; add the negative-test matrix (M12).

## Persona gap analysis

The set covered security, red-team, architecture, MCP, reliability, compliance, and secrets. Two
perspectives were missing and have since been added to `.personas/`:

1. **Harness Adopter / Developer Experience** (`harness-adopter-dx.md`) — the person running
   `bastion init` cold. Would sharpen the onboarding-brick, cross-OS, and truth-in-representation
   findings from the adopter's seat rather than the author's.
2. **Release Engineer** (`release-engineer.md`) — version single-sourcing, immutable-vs-moving
   pins, cross-carrier lockfile parity, and fix propagation to pinned + cached consumers.

Outlines were proposed in `proposed-personas.md`; both were accepted and written as full persona
files by the maintainer's direction.

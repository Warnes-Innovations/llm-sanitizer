# Red-Teamer — bastion plan review

Scope note: this is a *plan/design* review, not a running system. Several persona checklist items
(rule evasion, unicode, output gate, agent-to-agent) are **N/A** — the plan is infrastructure
extraction, not a change to detection rules/agents/output gate. Verified against
`check-project-root.sh`, `flow-guard/.claude/settings.json`.

## RT-1 — CRITICAL — Generalized hook collapses defense-in-depth into a single deletable marker
Replacing `basename==flow-guard || -f fg-sandbox.sh` (union) with `-f "$TOP/.bastion.yml"` means
delete/rename/`.gitignore` the marker, or `git checkout` a branch/worktree/old commit predating it,
and the hard-block silently downgrades while CLAUDE.md still claims the sandbox/deny-rules/credential
guards are active — the exact "instructions without enforcement" hole the hook closes. Violates the
belt-and-suspenders rule.
**Fix:** union that fails toward hard-block — fire if marker present OR `.claude/settings.json` has a
`sandbox` block OR a legacy launcher exists. Key the block on *enforcement presence*, not solely the
marker. Test: repo with a sandbox settings.json but no marker must still hard-block.

## RT-2 — CRITICAL — Manifest is both policy and the thing checked, so tampering is invisible; no floor
`.bastion.yml` is hook trigger, re-render source, and pin source; `bastion check` verifies rendered
files *against the manifest*. A one-line edit weakens the harness and `check` reports **zero drift**
because the rendered config faithfully matches the poisoned manifest:
- `profile: high-risk→standard` removes the Docker sandbox launcher (the sole isolation control).
- `network_allow: [ …, evil.example.com ]` opens egress.
- `extra_allow_read` (documented "symbolic ~-based") can name `~/.ssh`, `~/.aws`, or `/Users/warnes`
  (the path `denyRead` blocks).
- merge "never drops a deny" but these are **allow-side** levers with no deny floor.
**Fix:** hardcoded, non-overridable deny floor (credential paths, home root, secret env vars,
`WebFetch(domain:*)`) that manifest allow-fields cannot pierce; refuse to render an allow
intersecting the floor; `check` diffs the manifest against git history and flags security-downgrading
deltas. Verify whether `extra_allow_read` can override `denyRead` before shipping.

## RT-3 — CRITICAL — Merge preserves hostile pre-existing *allows* and weakening sandbox scalars
Merge is "additive-union … existing user keys preserved"; the adversarial test asserts only
*deny-survival*. A pre-existing `allow: ["WebFetch(domain:*)"]` / `Read(~/.ssh/**)` / `Bash(*)` is
preserved; whether that defeats the harness depends on Claude Code's allow-vs-deny precedence (never
pinned down). Worse, an additive merge preserving "existing user keys" would preserve a pre-existing
`failIfUnavailable:false` / `allowUnsandboxedCommands:true` / `enabled:false`, making the sandbox
fail **open**.
**Fix:** define precedence explicitly and strip pre-existing allows intersecting any harness deny
(or prove deny-wins and document it); treat security-critical sandbox scalars as non-negotiable
(template value always wins); test a `{enabled:false, allowUnsandboxedCommands:true,
failIfUnavailable:false}` input forces all three secure.

## RT-4 — MAJOR — Single-sourcing the pin removes the independent native-vs-Docker cross-check
Today `check_mcp_pin.py` cross-checks the native pin against an independently-maintained docker pin.
Collapsing both to one manifest field eliminates that check — both derive from the same field, so a
poisoned pin (older tag, or a branch/sha to attacker code) passes `pin.py` cleanly.
**Fix:** `pin.py` verifies the manifest pin against an independent signal, flags a branch/sha vs a
released tag, and warns when the pin moved without a release. Preserve cross-run-mode independence.

## RT-5 — MAJOR — Phase-5 marker-only hook swap opens a lapse window on marker-less branches/worktrees
The old hook protects flow-guard by name, branch-independently. The instant the global hook becomes
marker-only, every flow-guard branch/worktree predating the `.bastion.yml` commit gets neither the
name special-case nor the marker → unprotected while CLAUDE.md asserts protection. Contradicts the
plan's "protection never lapsed."
**Fix:** don't make the global hook marker-only (RT-1 union); retire the name special-case only after
the marker is on all live branches/worktrees, or keep the name/legacy signal in the union as a
permanent backstop.

## RT-6 — MAJOR — Cutover sequencing can drop drift enforcement between old and new mechanisms
If pre-commit stops running `check_sync.py` before `sync.py` is installed and enforcing, there's a
window with no drift enforcement. "Dormant one release" protects reversibility, not continuous
enforcement.
**Fix:** `sync.py`+`pin.py` must be in flow-guard's pre-commit and green **before** the old scripts
are removed; assert overlap, never a gap.

## RT-7 — MAJOR — Fail-open when the scanner MCP server won't launch; default network_allow omits PyPI
Rendered `.mcp.json` runs `uvx --from git+…@<pin>`. Default `network_allow` is
`[api.anthropic.com, github.com]` — narrower than flow-guard's live `*.anthropic.com`, no PyPI. On a
fresh init (standard profile), if `uvx` can't resolve deps (needs pypi.org/files.pythonhosted.org),
the server never starts and the agent has no scanner tool. `doctor`'s "resolvable at pin" is
one-time, not per-session.
**Fix:** the generated protocol states server-unavailable = refuse untrusted content (fail-closed);
confirm the minimal `network_allow` lets `uvx` resolve the scanner on a clean machine (add the index
domain if so); doctor/session-start asserts the scanner tool is *present*.

## RT-8 — MINOR — Golden-equality proves reproduction of flow-guard only
For any other target (fresh init, different `extra_*`, standard profile) there's no golden reference;
safety rests on merge/adversarial tests specified only for deny-survival.
**Fix:** add golden/adversarial fixtures for the general case (fresh repo, hostile pre-existing
settings, both profiles).

## Cross-cutting theme
Three of four Criticals share one root cause — **collapsing independent layers into one
tamperable/deletable thing** (two hook signals → one marker; two pin sources → one field; hardened
scalars → user-preserved keys). The single most load-bearing fix is a **hardcoded security floor +
union-style fail-toward-safe** across the hook, merge, and manifest validator. Verify Claude Code
allow/deny and allowRead/denyRead precedence before relying on any of it.

Recommended new red-teamer category: **"config-as-both-policy-and-check" / manifest-tampering** —
when a generated-config tool makes one committed manifest the source-of-truth AND the drift-check
baseline, tampering the manifest is invisible to the tool's own verification.

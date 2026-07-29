# Performance & Reliability Engineer — bastion plan review

Lens: reliability, failure modes, idempotency, rollback, operational robustness. Verified
`check-project-root.sh`, `check_sync.py`, `check_mcp_pin.py`, flow-guard `settings.json` sandbox
block, `fg-sandbox.sh`. Platform: macOS confirmed; Dr. Greg also uses Linux.

Scope note: most persona red flags target the **scanner runtime** (ReDoS, archive bombs, re-scan
depth), which the plan keeps out of scope. bastion only *wires* the scanner. The reliability surface
bastion owns is install idempotency, partial-install safety, cross-machine render/drift, hook
blast-radius, MCP-launch fail-posture, doctor fidelity, and rollback.

## C1 — CRITICAL — Cross-machine rendered-file commit model is self-contradictory (macOS + Linux)
Paths live "only in generated files"; `context.py` derives them per-machine; `check`/`doctor`
"detect when a repo was moved and the rendered paths no longer match" — which only makes sense if the
rendered `settings.json` is **committed** (flow-guard commits it with `/Users/warnes/...` literals).
Machine A (macOS) commits `/Users/warnes/...`; Machine B (Linux, `/home/warnes/...`) clones →
re-render → drift flagged → re-render overwrites → now A drifts. The two checkouts fight forever. If
instead the rendered file is git-ignored, a fresh clone has no enforcement but the committed marker
is present → (post-Phase-4) hard-blocks every prompt while the sandbox is absent.
**Fix:** decide + document one model. Recommended: **git-ignore the rendered settings.json/.mcp.json;
`.bastion.yml` is the only committed source; render is a required post-clone step** (post-checkout
hook or doctor-gated bootstrap). The hard-block keys on marker present **AND** rendered enforcement
present, so an un-rendered clone fails closed with a clear "run `bastion init`" message.

## C2 — CRITICAL — MCP scanner-launch fail-posture is undefined; the trust boundary can be silently absent
Rendered `.mcp.json` runs `uvx --from git+…@<pin>`. Mid-session or on a fresh machine, if github is
unreachable, the tag was deleted/retagged, the uv cache is cold under a sandbox denying the cache
path, or the build fails, the server does not start. The plan never states whether Claude Code then
proceeds fail-open (agent runs on untrusted content, trust boundary down) or fail-closed. For a
security harness this is *the* load-bearing question.
**Fix:** specify + test the launch-failure posture. `doctor` actively probes that the server answers
(call `list_rules`), not merely that `uvx` resolves. Document required CC behavior when a mandatory
MCP server fails to start; add a startup/UserPromptSubmit gate that fails closed if the sanitizer
isn't reachable. Prefer a published PyPI pin over `git+…@tag` to shrink the cold-build/network
surface.

## C3 — CRITICAL — Partial/interrupted install + Phase-4 hook escalation = self-inflicted brick, no atomicity
`init` does many steps; the plan lists **manifest-write first**. Interrupt after `.bastion.yml` is
written but before the settings merge completes → marker present, enforcement absent → recreates the
"instructions without enforcement" hazard, and once the global hook is marker-based, **every prompt
hard-blocks** → the repo is unusable, from a partial install. No transaction/rollback described.
**Fix:** make `init` transactional — render+merge into staging, verify (re-parse settings.json,
confirm mandated denies present), **write `.bastion.yml` last**; roll back all partial writes on
failure. The hook gates the hard-block on marker **AND** verifiable enforcement, degrading to a loud
"incomplete bastion install — run `bastion init`" message otherwise.

## M1 — MAJOR — Golden byte-equality test is non-portable; cannot pass in Linux CI
The "key gate" renders flow-guard's context against the committed macOS `settings.json` (with
`/Users/warnes/...` and `~/Library/...`). In GitHub Actions (Linux, `/home/runner`, no `~/Library`,
no siblings) the render can never byte-match → permanently red, or weakened to skip.
**Fix:** drive the golden test from a **frozen synthetic context fixture** (fixed `$HOME`, OS,
siblings) → fixed expected output. Keep "reproduces flow-guard exactly" as a separate macOS-only
local assertion.

## M2 — MAJOR — `context.py` macOS `~/Library` vs Linux XDG is structural, not a prefix swap
The sandbox references `~/Library/Application Support/quarto` *and* `~/.cache/uv`. On Linux the
`~/Library/...` paths don't exist (XDG `~/.cache`/`~/.local/share`); a naive prefix-swap points at
nonexistent dirs. With `failIfUnavailable:true`, an invalid sandbox path can fail the whole session
closed.
**Fix:** OS-aware cache/config resolution (branch on `sys.platform`; honor `XDG_*`); templates
express semantic slots ("quarto cache dir") resolved per-OS.

## M3 — MAJOR — Missing sibling repos / credential files + `failIfUnavailable:true` → session bricks; no pre-flight
allowRead lists siblings (`llm-wiki-plugin`, `warnes-brand`); on a machine where a declared sibling
is absent, the rendered sandbox references a nonexistent path and sandbox init may hard-fail → every
session dies before any work.
**Fix:** `context.py` filters declared paths to those that exist (recording which were dropped);
`doctor` pre-flights every rendered sandbox path for existence and reports before a hard-fail. Verify
CC's actual behavior on a missing path.

## M4 — MAJOR — `doctor` must *probe* a degraded sandbox, and be run-mode-aware
Reading `enabled:true` is not evidence the sandbox works — bubblewrap silently fails where user
namespaces are unavailable (fg-sandbox.sh documents `bwrap: No permissions to create new namespace`);
Docker mode intentionally sets `enabled:false` with mount isolation as the sole control, so a naive
doctor false-alarms.
**Fix:** concrete adversarial probe — attempt a read that must be denied (`~/.ssh`) and confirm
denial; confirm a write outside allowWrite fails; make doctor run-mode aware (native vs Docker).

## M5 — MAJOR — Merge idempotency / dedup untested; additive-only can never retract a stale mandated entry
Union without dedup grows arrays on each run → drift-check never stabilizes; additive-only can't
**remove** a later-corrected mandated deny, so a stale entry persists forever. `update` has no
retract semantics.
**Fix:** merge-idempotency test (render into an already-hardened file → byte-identical); dedup on
union; define `update` semantics for removing previously-mandated entries via a tracked
"bastion-managed" key set, without touching user-added keys.

## M6 — MAJOR — Phase-5 rollback is a state, not a runbook; coupled to an irreversible global-hook swap; escape hatch dropped
"Dormant" is not a procedure; the reversible per-repo change is coupled to shared global state (once
the global hook is marker-based, rolling flow-guard back doesn't restore the old block); the current
`FLOW_GUARD_ALLOW_SUBDIR=1` escape hatch isn't carried forward.
**Fix:** explicit rollback runbook with verification ("after rollback, launch from subdir → confirm
old block fires"); decouple the global-hook swap from the per-repo cutover, or make the generalized
hook recognize both the flow-guard special case and the marker during transition; carry forward
`BASTION_ALLOW_SUBDIR=1`.

## Minor
- **m1** Cold-start latency: `uvx` building the scanner env from git on a fresh session far exceeds
  1s and gates the trust boundary coming up. Prefer PyPI pin; warm the cache in `doctor`.
- **m2** Re-run clobbering user edits: overwrite-vs-skip for personas/docs/scripts unspecified;
  define skip-if-modified or a managed-vs-local boundary.
- **m3** Double hook registration (project + `~/.claude`): ensure exactly one hook path fires per
  event; make `hook_install.py` idempotent.

## Bottom line
The plan is thoughtful about security-preserving merge and golden-equality, but its **reliability
model for a two-OS, multi-machine user is unresolved** (C1), the **fail-posture when the
trust-boundary MCP server can't start is undefined** (C2), and **`init` has no atomicity while the
new marker-keyed hard-block makes a partial install brick the repo** (C3). These three are
release-blocking; the Majors are fixable within the current architecture but must be specified before
Phase 3–5.

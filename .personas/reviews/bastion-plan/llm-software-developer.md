# LLM Software Developer — bastion plan review

Lens: software architecture, maintainability, packaging, testing. Verdict: architecture is
fundamentally sound and phasing well-ordered, but the two most load-bearing modules (`merge.py` and
the golden gate) are under-specified in ways that could silently weaken the "never lapse flow-guard's
protection" guarantee.

## C1 — CRITICAL — `merge.py`'s single invariant is wrong for allow-type security fields
"Additive, never drops a deny" is safe for deny lists but **backwards** for allow-type fields. A
hostile/careless pre-existing settings.json can carry `permissions.allow: ["WebFetch(domain:*)"]`
or extra `sandbox.network_allow`/filesystem entries. Claude Code's deny-precedence rescues the
*permissions* case, but the **sandbox block is a pure allow-list with no deny-precedence** —
additively unioning a pre-existing sandbox entry directly widens what the sandboxed process can
reach.
**Fix:** split the merge contract by field polarity — union deny-type fields; for allow-type fields
(`permissions.allow`, `sandbox.network_allow`, sandbox filesystem read/write), a pre-existing entry
broader than the harness baseline must not be silently merged (drop it, or surface for explicit
review — never auto-widen). Add adversarial tests for allow-widening, not just deny-survival.

## M1 — MAJOR — Golden gate is render-only and omits the Docker variants
Phase 2 renders and byte-compares `settings.json`/`.mcp.json`/`.llm-sanitizer.yml`, but (a)
`bastion init` on flow-guard runs render **then merge**, and the merge step is never golden-validated
against the live file — so Phase 5's "near-empty diff" isn't actually guaranteed by the gate; and
(b) the gate omits `settings.docker.json`/`.mcp.docker.json`, exactly where the "docker permissions
== host permissions" invariant (`sync_docker_permissions`) lives.
**Fix:** golden-test the full `init` pipeline (render + merge); extend equivalence to the rendered
`.docker.json` outputs; assert rendered `settings.docker.json.permissions == settings.json
.permissions`.

## M2 — MAJOR — Byte-equality is the wrong invariant for JSON/YAML
Key ordering, indentation, trailing newline, and Jinja whitespace shift bytes without semantic
change; the "modulo the pin" carve-out already concedes bytes aren't equal. Text-templating
structured JSON with injected machine paths risks emitting invalid JSON a text-diff characterizes
poorly.
**Fix:** for JSON/YAML, render to data structures and compare **parsed-structure equality** (pin
normalized); reserve byte-equality for line-oriented artifacts (shell, markdown).

## M3 — MAJOR — The security header is load-bearing instructions, treated as a mechanical copyedit
`CLAUDE.security-header.md.j2` contains the actual runtime instructions an LLM follows —
scan-before-act, the fail-closed branch, the output gate, the confirmation format, scan-result
field-path handling. A prose "genericizing" pass can soften a fail-closed directive or drop an error
branch, and no test verifies the *rendered* header preserves them.
**Fix:** treat as security-critical text; content-assert the rendered header contains the
confirmation format and each error/fail-closed branch (scan error, empty response, missing field);
diff the genericized header against the original for *instruction* changes before Phase 5.

## M4 — MAJOR — bastion's declared `llm-sanitizer` runtime dependency appears unused (dual-version story)
bastion is a config generator; `context/render/merge/sync/pin/manifest` don't obviously import the
`Scanner` API — scanning is delegated to the pinned `uvx` process. So `llm-sanitizer>=0.4` as a wheel
dep looks like dead weight and creates a confusing two-version model (installed wheel vs `.bastion
.yml` git pin).
**Fix:** drop `llm-sanitizer` from `dependencies` if never imported, or state exactly what imports
it and document why the wheel and git pin coexist.

## Minor
- **m1** `update` command is unassigned to any phase and untested. Assign to Phase 4 (shares
  render+merge+drift machinery) with an idempotency/stability test, or drop from v0.1.0.
- **m2** No idempotency/re-run test ("init twice == init once" for the header block and settings
  merge).
- **m3** `context.py` credential/sibling auto-discovery has no oracle for fresh repos; make paths
  **declarative** via `.bastion.yml`, fail-closed when a path can't be resolved.
- **m4** Templates bake a CC-version-specific settings schema; record target CC version in
  `.bastion.yml`; doctor warns on schema skew.
- **m5** Version single-sourcing not addressed (repeats llm-sanitizer's known drift); use
  `importlib.metadata`; define what `.bastion.yml bastion_version` means and that `update` rewrites
  it.
- **m6** Load package data via `jinja2.PackageLoader`/`importlib.resources`, not
  `Path(__file__).parent`; verify inclusion in both wheel and sdist.
- **m7** No uninstall / backup-before-merge; write a timestamped `.bak` before mutating settings;
  consider `bastion uninstall`.
- **m8** Injected header vs host CLAUDE.md precedence unaddressed; header should state it overrides
  conflicting host instructions; `init` notes potential conflict in the "next steps" report.

## Red-flag checklist
- Wrong response field path — NOT FOUND (but M3: preservation untested)
- Vague "flag for human review" / missing error branch — folded into M3
- CLAUDE.md loaded from symlinked paths — **RESOLVED (strength):** plan moves from symlink workaround
  to marker-delimited injection — the correct fix
- Instruction ordering conflicts — **FOUND (minor, m8)**
- Hook stdin envelope version-dependency — N/A for the cwd-keyed launch hook; the analogous
  settings-schema version-dependency IS found (m4)
- `--dangerously-skip-permissions` scope — **FOUND & handled (strength)** (Risk 7 verbatim)

## Verified strengths
Tool count "9 tools" correct; `mcp__llm-sanitizer__scan_text` name correct; single-sourcing the pin
is a genuine improvement over separate surfaces; phase ordering has real dependencies and is
correctly sequenced; flow-guard stays live until the Phase-5 zero-drift gate.

Note: M4 is inferred (bastion source doesn't exist yet) — treat as "verify during Phase 3."

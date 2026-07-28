# Secrets & Pattern Coverage Reviewer — bastion plan review

Lens: secret handling, credential-guard correctness, secret-scanning coverage. Verified live
`flow-guard/.gitleaks.toml`, `.gitleaksignore`, `.pre-commit-config.yaml`, `settings.json`,
`sarif_review.py`. Verdict: directionally sound (golden gate, additive-merge intent, verbatim
audit-suite port are right instincts) but one Critical and three Major gaps where the plan's own
generalization language ships or permits a credential-protection regression.

## F1 — CRITICAL — Verbatim secret-scanning templates carry flow-guard's allowlist + baseline into every repo
`secret-scanning/{gitleaks.toml, gitleaksignore}` are classified "Reuse verbatim," but live
`.gitleaks.toml` contains:
```toml
[allowlist]
paths = ['''business-plan/People/.*\.html$''']
```
and `.gitleaksignore` holds flow-guard-specific fingerprints. Shipped as templates, every harnessed
repo inherits an allowlist that silently disables secret scanning under `business-plan/People/*.html`
— a repo-wide leak hole in repos that have nothing to do with LinkedIn captures. Contradicts the
plan's own "strip hotel/flow-guard references," which is applied only to personas/audit.
**Fix:** reclassify secret-scanning configs from "Reuse verbatim" to "Genericize." Ship
`.gitleaks.toml` → `useDefault = true`, **no `[allowlist]` paths**; `.gitleaksignore` → **empty**,
header comment only. Per-repo allowlist paths and confirmed-false-positive fingerprints are repo-local
tuning each consumer adds itself — never inherited. Test that a fresh init produces an empty
allowlist/baseline.

## F2 — MAJOR — `merge.py`'s deny-preservation doesn't cover the credential object-lists where the real denials live
Risk 4 scopes merge safety to "allow/deny lists" (the string arrays). But the credential file/env-var
denials live in `sandbox.credentials.files[]` and `sandbox.credentials.envVars[]` — lists of
**objects** `{path|name, mode:"deny"}`, not string arrays. A merge routine that unions string arrays
won't necessarily preserve object-list denies, so `.ssh`/`.aws`/`.gnupg`/`.netrc` files and
`ANTHROPIC_API_KEY`/`GITHUB_TOKEN`/`AWS_*` env vars could be silently dropped.
**Fix:** extend the merge contract + adversarial tests explicitly to
`sandbox.credentials.files[]`/`envVars[]`: every mandated credential entry present in the merged
output regardless of pre-existing content. Add cases feeding a hostile settings.json that omits or
reorders these object-lists.

## F3 — MAJOR — No protection against credential-deny *mode downgrade* on merge
Credential entries carry a `mode`. "Never drops a deny" says nothing about a pre-existing entry with
the same path/name and a **weaker** mode (`{name:"ANTHROPIC_API_KEY", mode:"ask"}` or
`{path:".ssh", mode:"allow"}`). An additive union keyed on identity could retain the weaker entry,
demoting a mandated `deny` to `ask`/`allow`.
**Fix:** credential/permission merges resolve mode conflicts to **most restrictive**
(`deny` > `ask` > `allow`), keyed on path/name; a pre-existing weaker mode can never override a
harness `deny`. Test a pre-existing weaker-mode entry stays `deny`.

## F4 — MAJOR — Env-var secret protection is single-layer, and no single source spans the two credential layers
The guard is two mechanisms: (a) `permissions.deny` globs (files only, already `~`-based) and (b)
`sandbox.credentials`. The **env-var denials exist only in the sandbox layer**. High-risk Docker runs
`--dangerously-skip-permissions`, disabling settings.json enforcement. So (1) env-var masking has no
second layer, and (2) the two layers are populated from different forms of the same secret set
(`~`-glob vs absolute), so `context.py` can render one and drift the other.
**Fix:** declare the canonical protected-credential set **once** in `.bastion.yml` and render into
*both* layers so they can't drift; document that env-var masking depends on the sandbox being active;
`doctor` probes an env-var denial (not only a file read) and warns in the high-risk path.

## F5 — MINOR — Shipped gitleaks version has no currency/drift management
flow-guard pins `rev: v8.30.0`. The plan gives the gitleaks pin none of the single-source/drift
treatment it gives `llm_sanitizer_pin`, so every harnessed repo freezes at the shipped `rev` and new
upstream secret patterns never arrive.
**Fix:** add `gitleaks_pin` to `.bastion.yml`, render into pre-commit + CI, and have `check`/`doctor`
flag drift vs upstream — mirroring `llm_sanitizer_pin`.

## F6 — MINOR — Golden test proves flow-guard reproduction but not fresh-repo credential completeness
The gate uses flow-guard's context, validating reproduction, not that a *new* repo's rendered
settings.json contains all credential file+envVar denies with `mode:deny`. "modulo the pin"
normalization, if broad, could mask diffs in the credentials block.
**Fix:** add a flow-guard-independent assertion that `init`/`new` output contains every mandated
credential deny (files + envVars, mode:deny) in both layers; pin-out normalization targets only the
pin token.

## F7 — MINOR — SARIF terminal-escape sanitization must not be lost in the "de-flow-guard" edit
`sarif_review.py` already sanitizes control/ANSI escapes from untrusted SARIF fields at display time
(`_CONTROL_CHARS_RE`, `_sanitize`) — so the audit suite does *not* currently leak adversarial content
to the terminal. The verbatim port is correct; a careless de-flow-guard edit near the display path
could regress it.
**Fix:** state that the ported `test_sarif_review.py` must retain its control-char/ANSI-escape
sanitization assertions as a required gate, and that display-time sanitization is a preserved
security invariant.

## Red-flag checklist
- Pattern too broad (alert fatigue) — **inverse FOUND** (F1: an *allowlist* too broad, suppressing
  real secrets in inherited paths)
- Pattern too narrow — N/A (`useDefault=true` retained)
- Obfuscation bypass / re-scan depth — N/A (owned by llm-sanitizer)
- Redaction loses information — N/A (owned by llm-sanitizer)
- Ruleset drifts from upstream — **FOUND** (F5)
- No false-positive feedback loop — **PARTIAL** (F1 breaks the empty-baseline discipline)
- Missing common secrets — N/A (`useDefault=true` preserves AKIA/ghp_/sk-ant-/PEM)

## Direct answers
- **Templated settings.json reliably reproduces ALL credential denials per-machine?** For a fresh
  render, plausibly — but NOT guaranteed (F4 no single source spanning both layers; F6 no fresh-repo
  completeness assertion).
- **Could `merge.py` drop a credential deny?** **Yes** — F2 (guarantee scoped to string arrays) and
  F3 (no mode-downgrade protection).
- **Risk of carrying flow-guard's allowlist/baseline into other repos?** **Yes — F1, the Critical.**
- **Audit-suite SARIF avoids leaking adversarial content?** **Yes, currently** (verified); F7 is a
  preserve-through-port caution.

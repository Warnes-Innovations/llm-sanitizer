<!--
Copyright (C) 2026 Gregory R. Warnes
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# llm-sanitizer Committee Review Personas

Expert reviewers for evaluating the LLM injection detection and secret redaction scanner.

All personas in this directory follow [REVIEW-STANDARD.md](REVIEW-STANDARD.md) —
the shared persona/review contract (structure, and the required §2 exploration
mandate that makes each checklist a floor rather than a ceiling).

> **Note:** `REVIEW-STANDARD.md` and the four personas common to both repos are
> maintained as parallel copies with flow-guard's `.personas/`, pending a shared
> upstream. **They are not byte-for-byte identical, and describing them that way
> hid a real gap:** every one of the five differs by its SPDX identifier by
> design (AGPL-3.0-or-later here, proprietary there), and as of 2026-08-11 three
> had also drifted in *content*, with this repo's copies missing checklist items
> the other side had gained. Those items have been ported back here.
>
> Treat the copies as **independently editable and periodically reconciled**, not
> as mirrors. Before relying on either side, diff them — ignoring the SPDX line,
> which is an intentional difference, not drift:
>
> ```bash
> for f in REVIEW-STANDARD.md red-teamer.md llm-software-developer.md \
>          security-engineer.md compliance-risk-officer.md; do
>   diff <(grep -v SPDX-License-Identifier ".personas/$f") \
>        <(grep -v SPDX-License-Identifier "<other-repo>/.personas/$f") \
>     >/dev/null || echo "CONTENT DRIFT: $f"
> done
> ```
>
> Two divergences in that output are **intentional and should not be
> "reconciled" away**, in `llm-software-developer.md` and `security-engineer.md`:
> the ported items carry the same substance but say *"a consumer protocol doc"*
> where the other copy says *"this project's CLAUDE.md"*, because that sentence
> describes a defect in the consumer's protocol document, not in this repo's
> (here `CLAUDE.md` is a symlink to `AGENTS.md` and never had those sections).
> The `Sensitivity parameter on redact` item also intentionally differs: the
> other copy still asserts that `redact`/`redact_file` take no `sensitivity`,
> which is false — all four redact tools accept it.

## Security & Compliance

- [Security Engineer](security-engineer.md) — threat modeling, fail-closed design, control effectiveness, credential handling
- [Compliance & Risk Officer](compliance-risk-officer.md) — GDPR/SOC2, audit trails, vendor risk, data handling compliance
- [Red Teamer](red-teamer.md) — adversarial attack simulation, evasion techniques, resilience under attack

## LLM & Tool Integration

- [LLM Software Developer](llm-software-developer.md) — MCP server semantics, prompt instruction reliability, agent orchestration
- [MCP Tool Designer](mcp-tool-designer.md) — tool usability, consumer integration, parameter clarity, error handling, version stability

## Domain-Specific

- [Secrets & Pattern Coverage Reviewer](secrets-pattern-reviewer.md) — secret pattern completeness, accuracy, obfuscation bypass, alignment with gitleaks/Betterleaks standards
- [Performance & Reliability Engineer](performance-reliability-engineer.md) — resource constraints, memory/CPU bounds, fail-closed limits, operational safety in MCP server deployments

## Adoption & Release

- [Harness Adopter / Developer Experience](harness-adopter-dx.md) — cold first-run success, failure recoverability, honest value proposition, cross-environment portability (added after the bastion-plan committee review to cover the adopter's-seat perspective)
- [Release Engineer](release-engineer.md) — version single-sourcing, immutable-vs-moving pins, cross-carrier parity, fix propagation to pinned+cached consumers, publish integrity (added after the bastion-plan committee review)

## Usage

Run `/committee-review` to have all personas review the llm-sanitizer codebase and documentation in parallel.

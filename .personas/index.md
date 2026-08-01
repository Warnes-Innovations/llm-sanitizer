<!--
Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# llm-sanitizer Committee Review Personas

Expert reviewers for evaluating the LLM injection detection and secret redaction scanner.

All personas in this directory follow [REVIEW-STANDARD.md](REVIEW-STANDARD.md) —
the shared persona/review contract (structure, and the required §2 exploration
mandate that makes each checklist a floor rather than a ceiling).

> **Note:** `REVIEW-STANDARD.md` is currently duplicated byte-for-byte with
> `flow-guard/.personas/REVIEW-STANDARD.md`, as are the four personas common to
> both repos. That duplication is a known drift risk pending a shared upstream —
> see the persona-set findings in flow-guard's `docs/agent-ops/execution-routing.md`.

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

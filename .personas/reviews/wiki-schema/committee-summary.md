# Committee Review — LLM Wiki schema design (llm-sanitizer)

**Date:** 2026-07-29
**Scope:** design question, not a defect review — should the freshly-bootstrapped `wiki/` schema (`wiki/SCHEMA.md`, `wiki/graph/ontology.yaml`) be extended with custom page types or graph predicates before first ingest?
**Personas:** all 9 from `.personas/index.md`, run in parallel, each reading `wiki/SCHEMA.md` and `wiki/graph/ontology.yaml` plus `CLAUDE.md` for project context.

## Executive summary

Four personas proposed schema extensions; five said the defaults already suffice. Two of the four — Security Engineer and Performance/Reliability Engineer — independently arrived at the same `incident` page type from different angles, both citing the same real evidence (the CHANGELOG's recurring "same bug class as..." language). That convergence, plus the concrete grounding on the other two proposals, is why all three proposed page types and five of six proposed predicates were adopted. Nothing was invented speculatively — every accepted item traces to a specific, already-documented recurring pattern in this project.

## Adopted

| Addition | Type | Proposed by | Grounding |
|---|---|---|---|
| `incident` page type (`wiki/incidents/`) | page type | Security Engineer + Performance/Reliability Engineer (independently) | CHANGELOG already narrates "same bug class as..." (py7zr 0.4.0→0.5.1) in prose with no structured home |
| `interface` page type (`wiki/interfaces/`) | page type | MCP Tool Designer | Per-tool contract drift (scan_text/scan_file/scan_dir/scan_url/redact*/list_rules) currently only lives in CHANGELOG.md, invisible to consumers |
| `release` page type (`wiki/releases/`) | page type | Release Engineer | Operationalizes the devel→main promotion ritual + consumer refresh caveat already documented in CLAUDE.md |
| `same_bug_class_as` (incident↔incident) | predicate | Security Engineer | Makes CLAUDE.md's "Bug Class Propagation" rule queryable |
| `guards_against` (concept↔concept) | predicate | Performance/Reliability Engineer | Bound↔hazard edge; lets a query find hazards with zero guards |
| `evades` (concept↔concept) | predicate | Red Teamer | "Technique X currently defeats control Y"; status/supersedes fields handle staleness |
| `breaks_compatibility_with` (decision/source→product) | predicate | MCP Tool Designer | Links a fix/decision to a named consumer it broke (e.g. flow-guard) |
| `fixed_in` (concept/claim→release) | predicate | Release Engineer | Fix-propagation tracking to pinned/cached consumers |

## Declined / not adopted this round

- **Compliance/Risk Officer, LLM Software Developer, Secrets Pattern Reviewer, Harness Adopter DX** — all recommended no schema changes. Notably Secrets Pattern Reviewer verified by grepping the actual ruleset that llm-sanitizer has no literal secret-*value* patterns to track coverage against (it's a prompt-injection scanner, not a gitleaks-class tool) — a good example of a persona checking before recommending.
- Release Engineer's secondary suggestion of a `pinned_to` predicate (product→release) was noted as "secondary" by its own author and not included in this round — revisit if release-page usage shows it's needed.

## Per-persona status

| Persona | Recommendation | Adopted |
|---|---|---|
| Security Engineer | `incident` type, `same_bug_class_as` predicate | ✅ |
| Compliance/Risk Officer | No changes | — |
| Red Teamer | `evades` predicate | ✅ (predicate only) |
| LLM Software Developer | No changes | — |
| MCP Tool Designer | `interface` type, `breaks_compatibility_with` predicate | ✅ |
| Secrets Pattern Reviewer | No changes (verified: no secret-value ruleset exists) | — |
| Performance/Reliability Engineer | `incident` type, `guards_against` predicate | ✅ |
| Harness Adopter DX | No changes | — |
| Release Engineer | `release` type, `fixed_in` predicate | ✅ |

## Process note

This is an adapted use of the `/committee-review` pattern for a design decision rather than a defect-finding pass — deliverable was a compact recommendation per persona (page type / predicate / none + justification), not the usual Critical/Major/Minor findings table. Full per-persona transcripts were not preserved as separate files (unlike a standard committee review) to keep this run's cost proportionate to a schema-design question; the consolidated recommendations above are complete.

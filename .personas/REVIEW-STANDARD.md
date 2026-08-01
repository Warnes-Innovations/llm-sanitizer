<!--
Copyright (C) 2026 Gregory R. Warnes
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Persona & Review Standard

The convention every persona in this directory must follow. Written down here
because it was previously an unstated expectation (see the committee review that
prompted this file). It governs how persona definitions are authored so that a
reviewing agent is *guided* by the checklist without being *confined* to it.

## 1. Structure (thoroughness)

Each persona SHOULD have:

- `## Role` — one-paragraph identity and focus.
- `## When to use` / `## When NOT to use` — routing, so the right lens is applied.
- `## Background` — the expertise that makes the lens credible.
- `## What this persona evaluates` — the checklist of things to work through.
- `## Red flags` — named failure patterns to check explicitly (FOUND / NOT
  FOUND / N/A).

This heading is deliberately **"persona"**, not "reviewer". Not every persona is a
reviewer: some model a *decision-maker* — a buyer, an approver, a counterparty — whose
job is to evaluate a proposal against their own interests rather than to audit an
artifact. They evaluate just as concretely, so they get the same section. Naming it
"reviewer" pushed those personas into an ad-hoc *Focus Areas / Goals / Needs* shape and
left the set structurally inconsistent for no good reason.

## 2. Exploration mandate (the floor-not-ceiling rule) — REQUIRED

Every persona MUST include, verbatim or in close paraphrase, an
**exploration clause** so the checklist is a *floor*, not a *ceiling*:

> **The lists above are a floor, not a ceiling.** Work through every item, but
> do not stop there:
>
> 1. **Surface unstated-but-relevant findings.** Actively report any relevant
>    issue you find — including ones this persona does not name — and flag
>    emergent risks and cross-cutting concerns explicitly. A finding outside the
>    checklist is a feature of the review, not a deviation from it.
> 2. **Surface gaps in THIS checklist.** If you had to go outside the listed
>    "What this persona evaluates" / "Red flags" to catch something, name the
>    missing item explicitly and recommend it be **added to this persona's
>    definition** so the next review catches it by default.
> 3. **Surface gaps in the PERSONA SET.** If you notice a risk or perspective
>    that is outside your own scope and that **no persona is positioned to
>    cover**, flag it as a persona-set gap and recommend a new persona (or an
>    expansion of an existing one) to own it. Reviewing your own blind spots and
>    the committee's blind spots is part of the job.

Rationale: a pure checklist trains a reviewing agent to answer only the listed
questions and to treat "all red flags NOT FOUND" as "clean." Real defects
routinely fall between named categories (this project's own committee review
surfaced several "additional red flags outside the listed set"). Clauses 2 and 3
make the review **self-improving**: each pass feeds back gaps into the persona
definitions and the persona roster, so coverage compounds over time instead of
being frozen at authoring time.

## 3. Precision (don't dilute)

The exploration mandate is not license to speculate. Findings must still be
evidence-based (cite the location), and the reviewer must distinguish an
intentional, bounded simplification from an actual defect. Surface *more*, but
hold each finding to the same evidentiary bar.

## 4. Severity (say which, always) — REQUIRED

Every finding MUST carry a severity, and every persona MUST use this scale unless
it defines its own `## Severity rule (persona-specific)` section specialising it.

- **CRITICAL** — invalidates a design decision, ships a broken or defeated control,
  or causes irreversible loss.
- **MAJOR** — a control fails *silently*, or a gap would force a restart or a wrong
  decision partway through execution.
- **MODERATE** — a real defect with a bounded workaround; or a condition that
  produces an alarm nobody can act on.
- **MINOR** — hygiene, clarity, consistency. No operational consequence.

A persona MAY redefine these, and several do — the Data Custody Reviewer, for
instance, deliberately rates *recoverable but unreported* as MAJOR, because an
adopter who is not told cannot recover in time. **What a persona may not do is
leave the scale unstated.**

Rationale: this section was added after a ten-persona committee review in which the
invoking instruction told every reviewer to "apply the severity conventions in
`REVIEW-STANDARD.md`" — and this file defined none. Six of the ten noticed
independently, each invented a scale, and each said so. The result was that two
reviewers' "High" were not comparable, and consolidating ten parallel reviews
required re-ranking every finding by hand instead of merging by declared severity.
A scale that is *specialised* is useful; a scale that is *absent* silently
defeats consolidation, which is the whole point of running personas in parallel.

## 5. Verify what the document admits it did not — REQUIRED

Where a document marks a claim **unverified**, and verification is available
**read-only**, the reviewer SHOULD attempt it and report the result.

Rationale: in the same review, the single highest-value finding came from probing
a claim the document itself had flagged as unverified and deferred ("verify before
building anything"). One API call settled it — and the answer invalidated an entire
phase of the rollout plan and one of the three enforcement layers. It surfaced only
because that reviewer happened to have read-only access and chose to use it. Make
that the expectation rather than the accident.

The corollary matters as much: **a caveat explaining *why* something is unknown is
itself a checkable claim.** In that review the document said "no available tool
exposes this endpoint" — which was false, and the false explanation is precisely
what kept the question open, because it instructed the reader not to try. A caveat
that misattributes the cause of uncertainty is worse than a bare "not checked".

---

*This standard is project-local. It is also proposed for the user-level agent
instructions so it governs every persona/agent/review definition across
projects — see the committee review's recommendation.*

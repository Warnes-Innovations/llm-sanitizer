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

---

*This standard is project-local. It is also proposed for the user-level agent
instructions so it governs every persona/agent/review definition across
projects — see the committee review's recommendation.*

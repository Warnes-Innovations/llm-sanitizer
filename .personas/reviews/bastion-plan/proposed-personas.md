# Proposed personas — from the bastion-plan committee review

The bastion-plan review surfaced two reviewer perspectives that no existing persona fully covered.
Both were **accepted** and written as full persona files; this file is retained as the record of
why they were added.

## 1. Harness Adopter / Developer Experience — ACCEPTED → `harness-adopter-dx.md`

**Gap:** every existing persona reviewed from the *author's* seat. None represented the developer
adopting the harness **cold** — running `bastion init`/`new` on their own repo, on a clean machine,
with only the shipped docs.

**What it catches that the others miss:** cold first-run failure on a machine without the author's
sibling repos/credentials/warm cache; partial-install brick with no recovery; re-run clobbering the
adopter's own edits; a marketing verb ("hardens in one command") that outruns the caveats; caveats
that live only in the project README and never travel into the artifact provisioned into the
adopter's repo; CI-hostile assumptions. Several plan findings (C4 two-OS, C3/M7 brick,
truth-in-representation) were seen only partially by reliability/compliance and would be sharpened
by this dedicated lens.

## 2. Release Engineer — ACCEPTED → `release-engineer.md`

**Gap:** no persona owned versioning, pinning, publish integrity, and — crucially — **fix
propagation** to consumers who pin a version and whose `uvx` build is cached.

**What it catches that the others miss:** duplicated version identifiers that drift (the project's
own CLAUDE.md notes this has happened); a single pin field that cannot generate a hash-locked
container lockfile so native/container silently diverge; a moving-branch pin on the trust boundary
serving stale cached code; a merged security fix that pinned+cached consumers never receive with no
advisory/refresh path; package data read via `__file__` that breaks from an installed wheel. The MCP
and compliance personas touched pieces of this (F1/F2 pin, F7 disclosure) but no persona owned the
release train end-to-end.

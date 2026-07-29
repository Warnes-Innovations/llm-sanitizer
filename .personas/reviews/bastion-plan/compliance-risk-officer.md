# Compliance / Risk Officer — bastion plan review

Lens: GRC — licensing, compliance, auditability, governance, third-party/supply-chain risk, gap
disclosure. Verified: llm-sanitizer is genuinely `AGPL-3.0-or-later` with SPDX headers + a Warnes
Innovations copyright line. Verdict: conditionally sound — threat-model honesty and drift-governance
are strong, but the AGPL "user not distributor" reasoning is overbroad and asserted as fact, and
several auditability/governance controls a security-tool vendor needs are missing.

## Direct answers to the charged questions
1. **AGPL posture (Risk 5) sound?** Partially — unsound as *stated*. The narrow claim (scanner as a
   separate `uvx` process = a use) is defensible; the blanket "an adopter is a user, not a
   distributor / generated config is not a derived work," stated as fact in the README, is wrong for
   the verbatim-copied AGPL personas/scripts/docs. (F1–F3)
2. **`.bastion.yml` provenance adequate?** No — thin. Records intent (pin, profile, persona names),
   not when/by-whom/digests/persona-trust. (F4, F5)
3. **Threat-model caveats preserved?** Yes in bastion's docs (a strength) — but not guaranteed to
   travel into the provisioned repo where the adopter reads them. (F6)
4. **Compliance gap shipping security tooling to third parties?** Yes — no disclosure/advisory
   process, no fix-propagation for pinned+cached consumers, top-line over-represents, no
   audit-retention policy. (F6–F9)

## F1 — MAJOR — AGPL "not a distributor" claim is overbroad for verbatim-copied files
Phase 1 copies personas, `REVIEW-STANDARD.md`, the audit suite, and `docs/agent-ops/*` **verbatim**
into adopter repos — substantial AGPL prose/code, not program output. When an adopter conveys their
repo (open-sources it, ships to a partner, hands to a subcontractor) they are **redistributing
AGPL-covered material** and obligations attach (license retention, offer of source, §5 notice
preservation). Telling adopters they are categorically "not distributors" gives false compliance
comfort.
**Fix:** split the claim in the README — (a) running the pinned scanner as a separate process = use;
(b) receiving verbatim bastion-authored files, then conveying the repo = distribution, with AGPL
obligations enumerated. Label "our understanding, not legal advice; consult counsel"; get a one-page
counsel review before v0.1.0.

## F2 — MAJOR — AGPL is a latent procurement blocker for the intended B2B adopters
AGPL was locked solely to match llm-sanitizer, with no adoption-friction analysis. bastion is
designed to be embedded into third-party (possibly proprietary) repos; many corporate
vendor-security programs restrict/prohibit AGPL (network-copyleft) code — making bastion
un-adoptable by the very audience it targets.
**Fix:** reason explicitly about the license for embedded, distributed-to-third-parties material
(differs from llm-sanitizer, a standalone process). Consider a permissive license (Apache-2.0/MIT)
for the **emitted template files** (personas, headers, scripts) while the bastion *tool* stays AGPL —
a "permissive-output, copyleft-tool" split. At minimum, document the AGPL-in-your-repo consequence
prominently.

## F3 — MINOR — Emitted files' AGPL notice/attribution propagation unspecified
AGPL §5 requires notices kept intact on conveyance. If injected files land without SPDX
headers/attribution, adopters silently strip them.
**Fix:** every rendered/injected artifact carries the SPDX + copyright header; golden test asserts
the header survives rendering.

## F4 — MAJOR — `.bastion.yml` is not an adequate audit record
No provisioning/last-verified timestamp, no actor attribution, no content digest/lockfile of what
was actually rendered. For a vendor-security/SOC2 supply-chain review, "what was provisioned, when,
by whom, tamper-evident?" must be answerable. `bastion check` re-renders and compares (good detective
control) but there is no signed/hashed baseline.
**Fix:** extend the manifest (or an adjacent `.bastion.lock`) with `provisioned_at`/`last_checked_at`,
the git-derivable actor, and a **digest of each rendered file**; record bastion's own PyPI
Trusted-Publishing provenance of the version used.

## F5 — MAJOR — Persona/agent provenance not recorded — self-inconsistent for a supply-chain-audit tool
bastion ships 6 personas and makes adding more frictionless, yet `.bastion.yml` lists personas by
name only — no source/version/hash. bastion's entire audit suite exists to treat community agent
definitions as third-party vendors; provisioning agent/persona files with no provenance reproduces
the exact gap it's built to close.
**Fix:** record per-persona `source` + `sha256` (and origin: bundled vs user-added); `bastion audit`
flags any persona on disk without a provenance entry.

## F6 — MAJOR — Threat-model caveats may not travel into the provisioned repo
Caveats live in bastion's README (a strength) but the plan doesn't require them in the **injected
CLAUDE.md security header**. An adopter runs `bastion new`, sees "hardened in one command," may never
read the README, then represents to partners "we run the bastion harness" while the best-effort/
`--dangerously-skip-permissions` caveats never traveled.
**Fix:** bake a concise "what this does and does NOT protect against" block into the injected header
and the generated repo's docs, not only bastion's README.

## F7 — MAJOR — No vulnerability-disclosure / advisory / fix-propagation process for bastion itself
No `SECURITY.md`, no coordinated-disclosure channel, no advisory mechanism. If a defect ships (merge
drops a deny, template renders an over-permissive sandbox), adopters pin by version and `uvx` caches
builds → a fix may never reach them, silently.
**Fix:** add `SECURITY.md` (contact, SLA), a GitHub Security Advisory workflow, and a documented "how
a fix reaches pinned + uvx-cached consumers" procedure (advisory + mandatory `--refresh`/cache-clean,
mirroring the llm-sanitizer note); a `doctor` check warning when the installed version is behind a
known-advisory floor.

## F8 — MINOR — Top-line "harden … in one command" over-represents vs the same doc's caveats
For a compliance audience a claim that outruns disclosed reality is a finding even when the caveat is
elsewhere. **Fix:** scope the headline to a defensible verb ("adds a defense-in-depth harness",
"reduces agent attack surface"), not "hardens/secures."

## F9 — MINOR — Audit-artifact (SARIF) retention unaddressed — risks reproducing flow-guard's gap
If bastion inherits flow-guard's gitignored-SARIF-with-no-retention practice, harnessed repos have no
producible audit trail for supply-chain decisions. **Fix:** define a retention posture (accepted-
report register committed; raw SARIF retained out-of-tree with a documented location) so adopters
can "produce your supply-chain audit trail."

## Strengths worth preserving
Gap disclosure of technical caveats is exemplary (Phase 6 "do not paper over them"); drift governance
is a genuine detective control; the `merge.py` deny-survival invariant is the right posture (also
document it as a stated security invariant); Trusted Publishing gives PyPI provenance out of the box.

## Red-flag checklist
- Audit logs not producible on demand (SARIF retention) — **FOUND** (F9)
- Undocumented data flows — N/A (infra)
- No incident-response procedure — **FOUND** (F7)
- Known gaps with no mitigation timeline/owner — **PARTIAL** (caveats disclosed but Layer-2 tracking
  item + rule-plugin issue lack owner/date)
- Third-party agent defs with no vendor risk record — **FOUND** (F5)
- PII with no access control — N/A to bastion (infra)

## Meta note for the persona owner
Two findings (F2 AGPL-in-embedded-files, F7 fix-propagation-for-a-security-tool) sit slightly outside
the listed evaluation items but are squarely GRC concerns for shipping security tooling to third
parties. Consider adding "license posture of code you distribute into third-party repos" and
"vulnerability-disclosure + fix-propagation for security tooling you ship" to this persona.

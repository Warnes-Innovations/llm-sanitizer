# Security Engineer — bastion plan review

Grounding: read `flow-guard/.claude/settings.json`, `check-project-root.sh`,
`llm-sanitizer/rules/__init__.py`.

Overall: unusually security-conscious for a design doc (trust boundary kept explicit, golden
byte-equality gate, "never drop a deny", generalized-hook default must match flow-guard's,
`--dangerously-skip-permissions`/mount-isolation caveats carried verbatim). Gaps cluster around the
**new attack surface bastion itself introduces**: a committed manifest that widens privilege, and a
tool that renders security config into many repos.

## F1 — CRITICAL — Manifest is an unbounded privilege-widening / injection vector
`.bastion.yml` is committed, is the re-render source-of-truth, and carries additive-widen fields
(`extra_allow_read`, `network_allow`). `merge.py`'s invariant "never drop a deny" does not stop a
hostile *add*: an attacker who lands a manifest change (malicious PR, compromised branch, an agent
tricked by untrusted content) can set `extra_allow_read: [~/.ssh, ~/.aws]` or
`network_allow: [attacker.example]`, and the next render bakes it into the live sandbox.
**Fix:** strict schema validation; treat `extra_allow_read`/`network_allow` as bounded (reject paths
outside repo/declared siblings; reject credential dirs even if listed); apply the credential/deny
baseline *after* manifest widening so a deny always wins; test that a hostile manifest cannot widen
into a credential path.

## F2 — MAJOR — bastion is a new single-point supply-chain compromise; template integrity unaddressed
One tool renders security config into many repos and re-renders on `update`/`check`. A compromised
release or tampered template silently weakens every harnessed repo's profile. Trusted Publishing is
mirrored (good) but nothing addresses template integrity or a silent `update` re-render.
**Fix:** `update`/re-render must show a security-relevant diff (deny/allow/network/credential
changes) and require confirmation — never silently write; `check` detects installed-version vs
manifest `bastion_version` skew and refuses a silent profile upgrade; ship template checksums;
state that the golden test also guards against a template edit changing flow-guard's profile.

## F3 — MAJOR — Marker-only hook detection is a fail-open regression
flow-guard's hook fires on `basename==flow-guard` OR `-f fg-sandbox.sh` (a union; the basename half
can't be removed by editing a file). Collapsing to `-f .bastion.yml` means one `rm`/rename drops the
hard-block while CLAUDE.md still claims enforcement.
**Fix:** keep detection a union (marker OR bastion-provisioned settings.json marker OR user-global
registry of harnessed roots); `check` flags "settings.json present but marker missing" as tampering;
regression test for marker removal.

## F4 — MAJOR — Credential env-var deny is void under high-risk Docker `--dangerously-skip-permissions`
`envVars` denies (ANTHROPIC_API_KEY, GITHUB_TOKEN, GH_TOKEN, AWS_*) only apply while settings.json
enforcement is active. Risk 7 says mount isolation is "the sole control" — but that protects the
filesystem, not process **environment**. If the launcher passes `-e ANTHROPIC_API_KEY` into the
container, secrets are exposed. (Could not read the launcher — must verify.)
**Fix:** verify `agent-sandbox.sh.j2` does not pass credential env vars; if a key is needed, inject a
scoped/short-lived one; correct Risk 7 (env-var exposure is a separate uncovered surface); add a
doctor/test asserting no denied env var is present in the container.

## F5 — MAJOR — Auto credential-path discovery risks an under-covering (fail-open) deny list
If `context.py` derives the deny set by discovery, any location it doesn't know
(`~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `.env`, `~/.config/gh`)
silently ends up readable. The golden test only proves flow-guard's existing set is reproduced, not
that a fresh init gets the full baseline.
**Fix:** credential deny set is a fixed baseline floor in the template, unioned with (never replaced
by) discovery — discovery may only *add*; test that a brand-new init contains the complete
credential baseline.

## F6 — MAJOR — Verification lacks adversarial/negative tests
The listed tests cover the happy path (golden equality, subdir block fires, scan_text flags,
WebFetch denied) but not: hostile manifest can't widen to credentials; marker removal is detected;
a new-repo render contains the full credential baseline; an incoming `allow` can't override a
baseline `deny`.
**Fix:** add those four negative tests explicitly (deny-survival alone is necessary but not
sufficient).

## F7 — MAJOR — Risks section is incomplete from a security standpoint
Omits F1 (manifest widening), F2 (fan-out/update), F3 (deletable marker), F4 (env-var exposure),
F5 (credential under-coverage). **Fix:** fold F1–F5 into Risks with proportionate mitigations.

## F8 — MINOR — SARIF/finding-excerpt artifacts not stated to be uncommitted
The audit suite emits SARIF that can contain the malicious injection text. **Fix:** ship a template
`.gitignore` for audit/SARIF outputs; document that finding artifacts are never committed.

## F9 — MINOR — Global `~/.claude` hook install is an unconfirmed privilege expansion
Writing into user-global `~/.claude` affects every project. **Fix:** `--global-hook` shows the exact
change and confirms; single-source the hook (agent-config symlink to bastion's copy).

## F10 — MINOR — bastion's own deps are floating; verify Docker/base-image tags are pinned
The scanner subprocess is pinned via `uvx --from git+…@<pin>`, but bastion's own
`llm-sanitizer>=0.4`, jinja2, pyyaml are unpinned. **Fix:** pin (ideally hash-pin) bastion's runtime
deps; verify launcher/CI images reference a pinned digest.

## Red-flag checklist
- Secrets in env vars without restriction — **FOUND (verify)** (F4)
- Fail-open paths — **FOUND** (F3, F5)
- Unverified field paths in hook commands — **FOUND (partial)** — subdir-loading premise verified
  only on CC v2.1.207; doctor should assert the quirk still holds on the running version
- Hardcoded IPs in iptables — **NOT FOUND** (domain allowlists used — correct)
- Audit logs with finding excerpts committed — **FOUND** (F8)
- Human review steps optional/vague — **MOSTLY NOT FOUND**; Phase-5.1 "reconcile intentional
  flow-guard settings" is a human-judgment step with no checklist (minor)
- Missing auth on internal services — **N/A** (no API proxy in this plan)
- Floating image tags — **FOUND (verify)** (F10)

## Persona-scope notes
- Risk 5 (AGPL) is a legal claim — defer to Compliance.
- "Scanner fails open if pin unreachable?" resolves **fail-closed** by design: `WebFetch(domain:*)`
  is a static deny, so if the MCP server is down, untrusted web content can't enter. Worth stating
  in the threat model; not a defect. `doctor`'s "resolvable at pin" catches the setup-time case.

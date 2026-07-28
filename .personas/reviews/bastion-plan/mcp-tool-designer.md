# MCP Tool Designer — bastion plan review

Verified against live `flow-guard/.mcp.json`, `flow-guard/.claude/settings.json`,
`agent-config/flow-guard/.mcp.docker.json` + `.mcp.json`, `agent-config/requirements-docker.txt`,
`flow-guard/scripts/check_mcp_pin.py`, `llm-sanitizer/src/llm_sanitizer/server.py`.

## Verified ground truth
The single manifest pin must feed **four** carriers holding **three formats** and, right now, **two
different versions**:

| Carrier | Location | Format | Current |
|---|---|---|---|
| Native MCP | `flow-guard/.mcp.json` | git tag ref | `@v0.4.0` |
| Native MCP (canonical) | `agent-config/flow-guard/.mcp.json` | git **branch** ref | `@main` (floating!) |
| Docker MCP | `agent-config/flow-guard/.mcp.docker.json` | baked binary, no version | `/usr/local/bin/llm-sanitizer` |
| Docker pin (real source) | `agent-config/requirements-docker.txt` | **hash-locked PyPI** | `llm-sanitizer==0.4.0` + sha256 |

Tool allow-lists expose **7 of the server's 9 tools** — `scan_dir` and `redact_dir` omitted.

## F1 — MAJOR — Single-source pin cannot generate the Docker/high-risk pin carrier
The docker version lives in a pip-compile **lockfile with sha256 hashes**. `render.py` cannot produce
that from a bare version string, so bumping the manifest pin updates native `.mcp.json` but leaves
the docker lockfile stale — the exact native-vs-docker drift `check_mcp_pin.py` was built to catch.
flow-guard migrates at `--profile high-risk`, so this bites the first real consumer.
**Fix:** either bastion owns regenerating `requirements-docker.txt` via a real `uv pip
compile`/`pip-compile` step at pin-bump (add to templates + golden test), or explicitly scope the
"single-source pin" claim to the standard profile and document a separate verified lockfile-regen
step. Add `requirements-docker.txt` to the golden-equality set.

## F2 — MAJOR — No guard against a mutable (branch) pin on the trust boundary
The canonical store already pins `@main` (floating). Nothing constrains `llm_sanitizer_pin` to an
immutable ref, and `pin.py`'s parser has a `git-branch` kind. A branch pin means the scanner can
change under the consumer without review, and `uvx` caches by ref, so it also serves **stale** code
until `--refresh`.
**Fix:** `doctor`/`check` WARN (fail under `--strict`) when the pin resolves to a branch rather than
a tag/sha; the schema states the pin should be an immutable released tag.

## F3 — MAJOR — Emitted tool allow-list is a frozen 7-of-9 subset with no drift story
The server exposes 9 tools; the templates allow 7 (`scan_dir`, `redact_dir` omitted). Nothing
cross-checks that the allow-listed names still match the pinned server's surface. A pin bump that
adds/renames/removes a tool drifts silently: a newly-added tool is un-allow-listed → a permission
prompt, which in a sandboxed non-interactive harness is effectively a silent hang.
**Fix:** `doctor` introspects the pinned server's tool list and asserts `emitted-allow-list ⊆
pinned-server-tools`, reporting stale entries and newly-available-but-unlisted tools; document why
`scan_dir`/`redact_dir` are excluded (right now the omission reads as an oversight).

## F4 — MINOR — git-tag → PyPI version translation (`v` prefix) unspecified
Native uses `@v0.4.0` (keeps `v`); PyPI/docker form is `llm-sanitizer==0.4.0` (no `v`). Naive
substitution yields the invalid `==v0.4.0`.
**Fix:** specify normalization in `render.py` (strip leading `v` for `==` forms, keep for git refs);
doctor verifies both the git tag on `main` and the PyPI publish exist for high-risk.

## F5 — MINOR — `doctor` "resolvable at pin" conflates *tag exists* with *builds and runs*
`check_mcp_pin.py` resolves via `git ls-remote` (tag existence only). The server lazy-imports deps
inside each tool, so a broken pin can start the server yet fail on first `scan_text`. First `uvx`
build is heavy and happens at MCP startup → can hang the consumer's first session.
**Fix:** `doctor` invokes `uvx --from …@pin llm-sanitizer --version` (pre-warms cache, proves
buildability) **and** runs a canary `scan_text` on a known-injection sample.

## F6 — MINOR (verify) — Emitted sandbox network policy may block `scan_url`
Sandbox `allowedDomains` = anthropic + github only; `WebFetch(domain:*)` denied so "web content only
enters via `scan_url`." `scan_url` fetches arbitrary vendor URLs inside the server process. If the
MCP subprocess is covered by the sandbox network policy, `scan_url` to a vendor domain is blocked —
defeating the one approved ingress. (Whether the sandbox applies to MCP subprocesses: not verified.)
**Fix:** a doctor/verification step runs `scan_url` against a reachable non-allowlisted domain and
confirms success (or documents the MCP server runs unsandboxed and is itself a network-egress point
the threat model must name).

## F7 — MINOR — Inconsistent tool result shapes not carried into emitted protocol docs
`redact` returns raw cleaned text (or raises → MCP error); `redact_file`/`redact_url`/`redact_dir`
and all `scan_*` return JSON. If the emitted security-header protocol treats all outputs as JSON,
agents mis-handle `redact`'s text return.
**Fix:** the header documents the two result shapes; optionally file an llm-sanitizer issue to
normalize.

## Red-flag checklist
- Tool parameter ambiguity (`high` vs `strict`): NOT FOUND (server uses `low|medium|high`). Adjacent
  gap: `.bastion.yml` has no per-repo default-sensitivity knob.
- Breaking change on rule addition: **FOUND** (F3 tool-surface drift; F2 mutable pin)
- Error messages don't help: N/A (server errors descriptive)
- Performance cliff: **FOUND (minor)** (F5 `uvx` first-build at startup)
- Inconsistent result format: **FOUND** (F7)
- Silent fallback to weak detection: **FOUND** (F2 branch pin + cache staleness; F1 docker lockfile
  drift → different rule set)
- Tight coupling to consumer: NOT FOUND — the plan actively de-couples (done well)

## Net
The emitted-`.mcp.json`/`uvx` pinning is directionally correct and the de-coupling is a genuine
improvement, but the single-source pin design is incomplete (F1) and lacks a mutable-pin guard (F2);
`doctor` verifies too weakly (F3/F5). All addressable by: (1) a lockfile-regen step in the
golden-tested set, (2) constraining+checking the pin to immutable refs, (3) doctor introspecting and
invoking the pinned server.

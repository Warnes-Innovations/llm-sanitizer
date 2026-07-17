# llm-sanitizer — agent guide

## Branch model & release ritual

This repo uses a two-branch model:

- **`devel`** — the working trunk. All day-to-day commits land here (default branch).
- **`main`** — the **released** branch. Downstream consumers pin this, e.g. flow-guard's
  `.mcp.json` runs the server via
  `uvx --from git+https://github.com/Warnes-Innovations/llm-sanitizer.git@main llm-sanitizer`.
  Consumers only see a change **after it reaches `main`**.

`main` is **protected**: no direct pushes (enforced for admins too). Changes reach `main`
**only via a pull request** from `devel` (0 required approvals, so the maintainer can self-merge).

### Promote `devel → main` at appropriate intervals

**Agent instruction:** When `devel` has accumulated stable changes that consumers should pick
up — especially security/correctness fixes to the scanner — **proactively prompt the maintainer
to promote `devel → main`**. Do not let released consumers drift far behind `devel`.

Good moments to prompt:
- After merging security or content-integrity hardening.
- After a fix to a user-reported scanning bug.
- Before asking a consumer (e.g. flow-guard) to rely on new behavior.

To promote (requires the PR path, since `main` is protected):

```bash
# from the repo root, with devel checked out and pushed
gh pr create --base main --head devel \
  --title "chore(release): promote devel → main" \
  --body "Summarize what consumers gain."
gh pr merge <PR#> --merge      # do NOT pass --delete-branch (devel is the trunk)
```

Never delete `devel` when merging — it is the permanent working trunk.

## Local development vs. released consumption

- **This repo's own `.mcp.json`** runs the server from local files (`uv run llm-sanitizer`) so it
  reflects your working tree instantly — correct for developing the server.
- **Consumers** (flow-guard) default to the released `@main` build. A developer who wants a
  consumer to exercise *local* llm-sanitizer edits adds a machine-local override that silently
  wins over the committed default:
  ```bash
  claude mcp add --transport stdio llm-sanitizer -s local -- \
    uv run --directory ~/src/llm-sanitizer llm-sanitizer
  ```
  Remove it to return to the released build: `claude mcp remove llm-sanitizer -s local`.

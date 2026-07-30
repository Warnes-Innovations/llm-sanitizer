<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC -->

# Contributing to llm-sanitizer

Thanks for your interest in improving **llm-sanitizer**. This project is offered under a **dual
license** — [AGPL-3.0-or-later](LICENSE) for open-source use, and a separate commercial license
from **Warnes Innovations LLC** for organizations that cannot accept the AGPL's terms. To keep both
offerings possible, every contribution must clear **two independent gates**. Both are required
(belt-and-suspenders); satisfying one does not waive the other.

## Gate 1 — Sign-off on every commit (DCO)

Every commit must carry a `Signed-off-by:` trailer certifying the [Developer Certificate of Origin
1.1](DCO). Add it automatically with:

```bash
git commit -s -m "your message"
```

This appends, using your configured `user.name`/`user.email`:

```text
Signed-off-by: Your Name <you@example.com>
```

The **DCO** attests *provenance* — that you wrote the code (or have the right to submit it). It does
**not**, on its own, grant relicensing rights — that comes from Gate 2 and the license-back clause
below. A CI check rejects any pull request whose commits are not all signed off.

### License-back clause (the grant a bare DCO lacks)

**By signing off a commit under the DCO and submitting it to this project, you additionally grant
Warnes Innovations LLC a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
copyright license to reproduce, prepare derivative works of, publicly display, publicly perform,
sublicense, and distribute your Contribution and such derivative works. You further agree that
Warnes Innovations LLC may license your Contribution, and derivative works thereof, under any
license terms of its choosing, including the AGPL-3.0-or-later, other open-source licenses, and
separate proprietary or commercial license terms.** You retain ownership of the copyright in your
Contribution.

This clause is deliberately identical in substance and wording to [`CLA.md`](CLA.md) Section 2 —
not merely "mirrored" but the same grant stated twice, once here and once in the standalone
agreement, so satisfying one gate does not grant materially different rights than the other. See
"Why both DCO *and* CLA?" below for why the project requires both anyway.

## Gate 2 — Contributor License Agreement (CLA)

On your **first** pull request, our **CLA-assistant bot** will ask you to accept the
[Contributor License Agreement](CLA.md) by leaving a one-line comment on the PR. The bot records
your acceptance and will not ask again for subsequent PRs (unless the CLA changes). A PR cannot be
merged until the CLA check is green.

- Contributing **as an individual** → the Individual CLA (the bot flow) is sufficient.
- Contributing **on behalf of an employer**, or where your employer holds rights in your work →
  the **[Corporate CLA](CLA-CORPORATE.md)** is also required. Email
  <greg@warnes-innovations.com> to arrange one.

The CLA grants the same relicensing rights as the license-back clause, in a standalone, auditable
agreement. We require both so the relicensing grant is unambiguous and recorded per-contributor.

## Why both DCO *and* CLA?

- The **DCO** gives us a lightweight, per-commit provenance record and is enforced automatically.
- The **CLA** (plus the license-back clause) gives us the explicit **relicensing grant** a plain DCO
  does not, which is what makes the commercial license offerable.

Using both is deliberate defense-in-depth: if one mechanism is ever found insufficient for a given
contribution, the other still establishes the rights the project needs.

## Development workflow

- Default/working branch is **`devel`**; `main` is the protected released branch.
- Run the test suite and type checks before opening a PR (`pytest`; `mypy` per the `dev` group).
- Keep the `SPDX-License-Identifier` + copyright header on every new source file.
- Follow Conventional Commit style for messages (`feat:`, `fix:`, `docs:`, `chore:`, …).

## Reporting security issues

Please **do not** open a public issue for a security vulnerability. See
[`.github/SECURITY.md`](.github/SECURITY.md) for the coordinated-disclosure process.

---

> The CLA and this document's license-back clause are **DRAFTs pending legal counsel review** (see
> the project plan, constraint LIC-4). They are not legal advice.

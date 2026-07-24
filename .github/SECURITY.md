<!--
Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately**, not via a public
issue.

- **Preferred:** open a [GitHub private security advisory](https://github.com/Warnes-Innovations/llm-sanitizer/security/advisories/new)
  ("Report a vulnerability").
- **Email:** `security@warnes-innovations.com` (or `greg@warnes-innovations.com`).

Please include:

- a description of the issue and its impact,
- the version / commit affected,
- steps to reproduce or a proof-of-concept (a scanner input that bypasses or
  crashes detection is ideal), and
- any suggested remediation.

## What to expect

- **Acknowledgement:** within **3 business days**.
- **Assessment & triage:** within **10 business days**, including a severity
  judgement and a target fix window.
- **Disclosure:** coordinated. We will agree a disclosure date with you and
  credit you in the advisory and CHANGELOG unless you prefer to remain anonymous.

## Scope

This project is a **defensive** content scanner. Reports we especially want:

- **Detection bypasses** — an injection / obfuscation that reaches the payload
  without producing a finding (false negative), or a benign input that produces
  a high-risk finding (false positive at a rate that trains users to ignore it).
- **Denial of service** — an input that makes the scanner exhaust memory or pin
  CPU beyond its documented bounds (`max_scan_bytes`, the re-scan work budget,
  archive limits).
- **SSRF / egress** — any way to make the URL reader reach a non-public host or
  exfiltrate data.
- **Secret / data exposure** — any path that logs, caches, or transmits scanned
  content or a detected secret.

## Supported versions

The latest release on the `main` branch (published to PyPI) receives security
fixes. Older `0.x` versions are not maintained; upgrade to the latest.

## Handling of scanned content

llm-sanitizer processes content **in memory only** — it retains nothing, emits
no telemetry, and opens no network listener. See
[`docs/DATA_HANDLING.md`](../docs/DATA_HANDLING.md) for the full data-handling
and privacy posture.

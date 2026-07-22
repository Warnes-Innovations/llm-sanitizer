<!--
Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Data Handling & Privacy

llm-sanitizer is a **library / CLI / stdio-MCP server** that scans content for
embedded LLM-agent instructions and optionally redacts them. This document
states, so a reviewer can cite it, exactly what the tool does with the content
it is given.

## Summary

- **In-memory only.** Content is read, scanned, and (for redaction) rewritten in
  process memory. The tool keeps no database and writes no copy of scanned
  content except the redaction output file you explicitly ask for.
- **No retention.** Nothing is persisted between runs. There is no cache of
  scanned content, no history, no analytics store.
- **No telemetry.** The tool emits no usage analytics and "phones home" to no
  service. (Verified: the `src/llm_sanitizer` package contains no
  logging/telemetry/analytics egress.)
- **No network listener.** The MCP server runs over **stdio** — a single local
  client per process. It opens no socket and accepts no remote connections.
- **Single, guarded egress.** The only outbound network access is the explicit
  `scan_url` / `redact_url` path, which fetches a URL you supply. That path is
  SSRF-guarded: every hop (initial URL and each redirect) must resolve to a
  public IP — loopback, private, link-local, and cloud-metadata addresses are
  refused — and the response body is size-capped.

## Where the data-processor duties sit

Because the tool retains nothing and calls out to no third party, the
data-controller / data-processor obligations under GDPR/CCPA/SOC 2/HIPAA fall on
**the deployer** (the application embedding llm-sanitizer), not on this package.
A deployer handling regulated data should still:

- run the tool inside their own trust boundary,
- add their own audit logging around scan/redact calls if they need an
  attributable record (the tool deliberately does not log content), and
- treat scanner **findings** as sensitive: a finding's `matched` / `matched_raw`
  fields quote the offending span, which may include the very content that was
  flagged. Do not forward raw findings to an untrusted destination.

## Bounds that protect availability

- `max_scan_bytes` (default 25 MiB) caps the size of any single unit scanned;
  oversized input fails closed with a CRITICAL `input_too_large` finding rather
  than being read into memory.
- A cumulative re-scan **work budget** bounds the de-obfuscation fan-out.
- Archive extraction is bounded by entry count, compression ratio, uncompressed
  size, and nesting depth (zip-bomb protection).
- The URL reader caps response size and total time.

## Reporting a concern

See [`.github/SECURITY.md`](../.github/SECURITY.md) for how to report a
vulnerability or a data-handling concern.

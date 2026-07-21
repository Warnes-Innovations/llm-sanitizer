# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-20

### Added
- **Obfuscation rules now de-obfuscate, then re-scan.** base64 and homoglyph
  detection share a new depth-guarded helper (`scan_deobfuscated`) that runs the
  full detection ruleset over the *de-obfuscated* text — decoded base64, or
  homoglyph-normalized text — and surfaces whatever the other rules find, rather
  than matching a hardcoded keyword list. This catches keyword-less / rephrased
  injections and nested obfuscation (base64-in-base64, a homoglyph phrase inside
  base64), while leaving innocent base64 and innocent mixed-script text clean.
- SSRF trust boundary **and** a response size cap in the URL reader: every hop
  (the initial URL and each redirect, followed manually) must be an `http(s)`
  URL whose host resolves only to public addresses — blocking loopback, private,
  link-local, and cloud-metadata (`169.254.169.254`) targets — and the response
  body is read as a bounded stream, aborted past a 10 MiB cap, so an untrusted
  endpoint cannot exhaust memory.
- Recursive archive scanning. Under the default `binary_mode="extract"`, files
  that are archives — detected by **content magic bytes, not extension** — are
  expanded and each member scanned through the normal pipeline, recursively for
  nested archives. Supported out of the box via the stdlib: ZIP, TAR, and
  TAR.GZ / TAR.BZ2 / TAR.XZ (plus bare GZ/BZ2/XZ streams). Optional backends add
  `7z` (`pip install llm-sanitizer[7z]`, py7zr — LGPL-3.0, AGPL-compatible) and
  `rar`/general libarchive support (`pip install llm-sanitizer[rar]`,
  libarchive-c — wraps BSD-licensed libarchive). Optional backends are imported
  lazily, so the package works unchanged when they aren't installed.
- Content-integrity findings, emitted (fail-closed) instead of silently
  mis-scanning a file that can't be trusted to be what it claims. One unified
  set covering **all** files (not just archives):
  - `type_mismatch` (CRITICAL) — the extension and the content magic disagree
    (a disguised archive, a `.png` whose bytes are an executable, a text-named
    file whose bytes are unidentified binary, …).
  - `corrupt_file` (CRITICAL) — a recognized archive, PDF, or Office document
    that fails a bounded structural check (corrupt/truncated/over-budget).
  - `unscannable_binary` (CRITICAL) — a non-archive binary whose extraction
    failed, or (under the `fail` policy) produced no text.
  - `archive_unsupported` (CRITICAL) — an archive format disabled by config.
- Tier-1 content-type detection generalized to ALL files via the pure-Python
  `filetype` library (MIT, new core dep). It matches only known *binary*
  signatures and returns None for text/source, so Markdown-with-HTML, fenced
  code blocks, and scripts are treated as text and never produce false-positive
  `type_mismatch` findings; only a concrete binary type (or unidentified binary
  with NUL bytes) contradicting the extension is flagged.
- Tier-2 bounded structural validation for the formats flow-guard ingests: PDF
  (via `pypdf`, BSD, new core dep — trailer/page-tree parse, no rendering) and
  OOXML/ODF office documents (stdlib only — ZIP opens, required parts present,
  primary XML part well-formed). Structural failure → `corrupt_file`. All reads
  are resource-bounded by the archive limits; untrusted input is never fully
  decoded/rendered.
- `unprocessable_binary_policy` config option + `--unprocessable-binary-policy`
  CLI flag, governing a non-archive binary that is processed but yields no
  extractable text: `fail` (default, fail-closed — CRITICAL `unscannable_binary`),
  `scan-text` (scan the raw bytes as text for injection patterns), or `ignore`
  (skip it, counted as skipped).
- Fail-fast on a missing extractor/backend: when content in the scan needs
  markitdown (absent) or an archive backend (py7zr/libarchive-c absent for a
  format actually present), the run halts with `ExtractorUnavailableError`
  carrying the install hint — the CLI exits non-zero, the MCP tools return
  `status:"error"` with the hint. A systemic coverage gap is surfaced loudly,
  not degraded per file.
- `Scanner.scan_file(path, …)` — an archive-aware, integrity-checking single-file
  entry point used by the CLI `scan`, the MCP `scan_file` tool, and directory
  scans.
- Archive limits are configurable: an `archive:` section in `.llm-sanitizer.yml`
  (`max_depth`, `max_cumulative_bytes`, `max_entries`, `max_uncompressed_bytes`,
  `max_compression_ratio`, `min_ratio_check_bytes`, `formats`) and CLI flags
  `--archive-max-depth`, `--archive-max-bytes`, `--archive-formats`. The existing
  module-level constants remain the ultimate fallback defaults, so behavior is
  unchanged when nothing is configured.
- `--binary-mode {skip,extract,text}` on `scan`/`redact` (CLI) and the
  corresponding `binary_mode` parameter on all relevant MCP tools, controlling
  how content sniffed as binary (by content, not extension) is handled:
  extract embedded text via `markitdown` (default), force raw bytes to be
  scanned as literal text, or skip entirely
- Zip-bomb guard: cheap central-directory inspection (entry count, total
  uncompressed size, compression ratio) rejects malicious archives before
  `binary_mode="extract"` decompresses anything
- `llm-sanitize merge` CLI subcommand: assembles a directory-level report
  from previously-saved per-file `scan --format json` results without
  re-scanning, for callers that already cache scan results keyed by content
  hash

### Changed
- **base64 rule** no longer flags on a keyword sub-list or on "decodes to
  prose"; it flags only when the decoded text trips another detection rule (the
  re-scan above). Innocent base64 (keys, hashes, an encoded innocuous sentence)
  is no longer flagged.
- **homoglyph rule** no longer flags mixed-script text merely for mixing
  scripts. It flags only when normalizing the lookalikes yields a known
  instruction-override term or trips a detection rule — removing false positives
  on scientific / internationalized text (e.g. `Aβ`, `5µm`, `10kΩ`, and
  `filesystem` written with a Cyrillic `с`).
- **Archive bomb guard now fails loud, not silent.** An archive that trips the
  bomb guard — over a depth/size/ratio budget, undecompressable, or nested beyond
  `archive.max_depth` — now yields a CRITICAL `corrupt_file` integrity finding
  instead of being silently skipped (which a caller read as "scanned clean").
- The raw-text fallback for unextractable binaries was **removed**. Previously,
  when markitdown was absent or failed, `binary_mode="extract"` decoded the raw
  bytes as UTF-8 and scanned that — which produced spurious findings on binary
  garbage and never saw an archive's real contents. Now: a missing extractor
  fails the run fast (see fail-fast above), a failed extraction is a CRITICAL
  `unscannable_binary` finding, and `read_scannable_content`'s docstring no
  longer documents any raw-text fallback.

### Fixed
- `__version__` was pinned at `0.1.0` while the packaged version had moved on
  (0.1.3); it is now kept in sync with the packaged metadata, and the smoke test
  asserts the two match via `importlib.metadata` so they cannot drift again.
- The base64 decoded-text re-scan previously called `detect()` on rule *classes*
  (passing the text as `self`), so every call raised and was silently swallowed —
  the re-scan never actually ran. Rules are now instantiated correctly.
- `redact_dir` (CLI and MCP server) no longer silently drops binary files
  from the output directory when they aren't scanned (`binary_mode="skip"`,
  or `"extract"` with extraction unavailable/failed) — they're now copied
  through unchanged, matching the documented behavior
- `redact` (CLI, single-file) and `redact_file` (MCP) no longer overwrite a
  genuinely-extractable binary file (e.g. a real PDF) with its extracted,
  redacted *text* — binary sources are now copied through unchanged, matching
  `redact_dir`'s existing behavior for the same case
- The zip-bomb compression-ratio check no longer misclassifies small,
  highly-compressible legitimate documents (e.g. small DOCX/PPTX) as bombs —
  the ratio heuristic now only applies to entries large enough to matter
- `merge` no longer reports the sensitivity of whichever manifest entry
  happened to be processed last as the aggregate value — it now reports the
  shared sensitivity, or `"mixed"` when entries were scanned under different
  `--sensitivity` settings

### Known Limitations / Unsupported File Types
- **Tier-2 structural validation is scoped to PDF and OOXML/ODF.** Other binary
  types (images, audio, video, fonts, executables) are covered by Tier-1
  magic/type-mismatch detection only — their internal structure is not
  validated. This is deliberate: never fully decode/render untrusted media.
- **Default `unprocessable_binary_policy="fail"` flags every binary that yields
  no extractable text as CRITICAL `unscannable_binary`** — including legitimate
  images and other media markitdown can't turn into text. This is the
  fail-closed default for untrusted-upload threat models; set the policy to
  `scan-text` or `ignore` if unscannable media is expected and acceptable.
- **Tier-1 (`filetype`) and Tier-2 PDF (`pypdf`) are core deps but degrade
  gracefully if a partial install lacks them** — the affected tier becomes
  inactive (returns "no problem") rather than crashing. In a complete install
  both are always active. (Tier-2 Office validation is stdlib-only and always
  active.) A *missing extractor for content actually present* (markitdown, or a
  7z/rar backend) is the separate fail-fast case and does halt the run.
- **Type-mismatch never flags text/source.** `filetype` matches only known
  binary signatures, so a script or Markdown file under a "wrong" *text*
  extension is treated as text and scanned normally, not flagged — only a
  concrete binary type (or NUL-containing unidentified binary) contradicting the
  extension is a `type_mismatch`. A malicious *text* payload under a mislabeled
  text extension is still caught by the ordinary detection rules, just not as a
  mismatch.
- **Archive member findings are attributed to the archive file** in the
  aggregated result (the `Finding` model carries no per-member source field);
  the member path is used during scanning but not surfaced per finding.
- **A single-stream `gz`/`bz2`/`xz` bomb** (not a nested zip) is bounded by
  `max_uncompressed_bytes` during decompression and surfaced as CRITICAL
  (`corrupt_file`) when it exceeds that budget, rather than silently skipped
  like an over-budget zip — an intentional fail-closed asymmetry, since a bare
  compressed stream has no cheap central directory to pre-screen.

## [0.1.0] — 2026-04-20

### Added
- Scanner engine with rule-based detection and classification of embedded LLM agent instructions
- Detection rules: hidden-text, HTML/Markdown formatting tricks, Unicode homoglyphs, zero-width character interleaving, and control-character injection
- CLI entry point (`llm-sanitize`) with scan, report, and redact sub-commands
- MCP server entry point (`llm-sanitizer`) exposing scan/redact tools via the Model Context Protocol
- Document readers for plain text, HTML, Markdown, and source code files
- Optional binary reader via `markitdown` (`[binary]` extra)
- Output formatters: plain text, JSON, and SARIF
- Initial design specification (`docs/DESIGN_SPEC.md`)
- Full test suite (275 tests)

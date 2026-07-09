# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Fixed
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

### Known Limitations
- The zip-bomb guard only inspects the outer archive's central directory; a
  zip containing a nested zip ("zip-of-zips") can bypass all three
  heuristics, since markitdown recurses into nested archives with no
  depth/size limit of its own. A real fix needs either recursive
  central-directory inspection with a depth+budget cap, or running
  extraction under an external resource ceiling.
- `scan_dir`'s default `binary_mode="extract"` silently skips a file from
  scanning entirely when markitdown extraction fails, rather than falling
  back to raw-text scanning. This is an intentional tradeoff (it avoids
  spurious findings on raw binary garbage), but it means content markitdown
  can't parse is never scanned for injected instructions.

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

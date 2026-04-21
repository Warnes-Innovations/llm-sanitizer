# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

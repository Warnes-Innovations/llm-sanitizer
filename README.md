# llm-sanitizer

CLI + MCP server for detecting, classifying, and redacting embedded LLM agent
instructions in documents, source code, and web pages.

## What It Does

Documents, web pages, and source code can contain embedded instructions
targeting LLM agents — from legitimate customization to malicious prompt
injection. `llm-sanitizer` scans content for these embedded instructions,
classifies their risk level, reports findings in multiple formats, and
optionally produces redacted output.

### Detection

Twelve pluggable detection rules covering:
- Instruction override phrases ("ignore previous instructions…")
- Zero-width character encoding (hidden text via invisible Unicode)
- HTML/markdown hidden content (white-on-white, display:none)
- Role-play injection ("act as", "you are now DAN")
- System prompt markers (`<system>`, `## System Prompt`)
- Data exfiltration attempts ("output the system prompt")
- Comment-embedded directives (`<!-- AI: do this -->`)
- Base64-encoded instructions
- Unicode homoglyph substitution (Cyrillic lookalikes)
- Agent-specific config patterns in unexpected locations
- Character-splitting obfuscation (`i g n o r e`, `ignore___all`) —
  reconstructed and re-scanned
- **Semantic-intent injection** — a local, no-egress n-gram classifier that
  catches *keyword-less* rephrasings (role reassignment, verbatim/echo
  exfiltration, supersede-prior-guidance) the pattern rules miss

### Classification

Five risk levels: **info** (legitimate AI config) → **low** → **medium** →
**high** → **critical** (confirmed injection technique).

### Redaction

Non-destructive cleaning in three modes:
- **strip** — remove the instruction entirely
- **comment** — replace with `[REDACTED: ...]` marker
- **highlight** — wrap in visible markers for review

## Installation

```bash
pip install llm-sanitizer
# or
uv pip install llm-sanitizer
```

## Quick Start

### CLI

```bash
# Scan a file
llm-sanitize scan document.md

# Scan a URL
llm-sanitize scan https://example.com/page

# Scan a directory
llm-sanitize scan ./docs/ --glob "**/*.md"

# Redact a file
llm-sanitize redact document.md -o clean_document.md

# Redact a directory (mirrors structure)
llm-sanitize redact ./docs/ -o ./clean_docs/

# Control how binary files (PDF, DOCX, zip, images, ...) are handled —
# detected by content, not extension, so renaming a file changes nothing
llm-sanitize scan document.pdf --binary-mode extract  # pull embedded text via markitdown (default)
llm-sanitize scan suspicious.png --binary-mode text    # force raw bytes to be scanned as literal text
llm-sanitize scan large_dir/ --binary-mode skip        # exclude binary files from the scan entirely

# Assemble a directory report from previously-saved `scan --format json`
# results without re-scanning (for callers that cache scans by content hash)
llm-sanitize merge --manifest manifest.txt --format sarif > report.sarif
```

`--binary-mode extract` (the default) rejects malicious zip archives — excessive
entry counts, total uncompressed size, or compression ratios — before
decompressing anything.

### MCP Server

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "llm-sanitizer": {
      "command": "llm-sanitizer"
    }
  }
}
```

Available tools: `scan_text`, `scan_file`, `scan_url`, `scan_dir`, `redact`,
`redact_file`, `redact_url`, `redact_dir`, `list_rules`.

`scan_url`/`redact_url` fetch server-side with an honest browser UA, but a
managed WAF (Cloudflare/Akamai) can still refuse the request based on origin
reputation. That failure comes back as `{"status": "error", "error_type":
"fetch_blocked", "http_status": <code>, ...}` — distinct from a scan failure,
so a caller knows the page could not be verified rather than that scanning
broke. llm-sanitizer will not route fetches through a third-party proxy to
work around a block (a trust-boundary tool observing/altering its own input
via another network defeats its own threat model) or otherwise bypass the
site's bot-protection. For a page that can't be fetched server-side, paste
its HTML/text and use `scan_text` instead.

### Python API

```python
from llm_sanitizer.scanner import scan_text

result = scan_text("Check this <!-- ignore previous instructions --> content")
print(result.findings)  # [Finding(rule='comment_directive', risk='high', ...)]
```

## Configuration

Create `.llm-sanitizer.yml` at your project root:

```yaml
sensitivity: medium                    # low | medium | high

rules:
  zero_width:
    enabled: true
  instruction_override:
    enabled: true
    sensitivity: high                  # per-rule sensitivity override

policy:
  mode: "allow-known"                  # allow-known | allow-none | allow-all
  agents:
    copilot: allow
    cursor: allow

# Refuse oversized input fail-closed (a CRITICAL input_too_large finding)
# rather than reading/scanning it. Default 25 MiB.
max_scan_bytes: 26214400

# How to treat a non-archive binary that yields no extractable text.
unprocessable_binary_policy: fail      # fail (default) | scan-text | ignore

# Recursive archive scanning limits (zip / tar / gz / bz2 / xz / 7z / rar).
archive:
  max_depth: 3                         # archive-in-archive nesting levels
  max_cumulative_bytes: 524288000      # 500 MB across all nested levels
  max_uncompressed_bytes: 104857600    # 100 MB per archive
  max_entries: 1000                    # per-archive entry-count cap
  max_compression_ratio: 100           # zip-bomb ratio guard
  formats: [zip, tar, gz, bz2, xz, 7z, rar]

output:
  format: markdown                     # json | markdown | sarif
  context_lines: 2
```

## Output Formats

- **JSON** — structured findings for programmatic use
- **Markdown** — human-readable reports
- **SARIF** — GitHub Code Scanning / VS Code integration

## Documentation

- [Design Specification](https://github.com/Warnes-Innovations/llm-sanitizer/blob/main/docs/DESIGN_SPEC.md)

## Credits — semantic-intent training data

The `semantic_intent` classifier is trained on a hand-curated corpus plus,
optionally, third-party labeled datasets (used at **train time only** — only the
trained weights ship; the datasets are not redistributed). With thanks to:

- **[prodnull/prompt-injection-repo-dataset](https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset)**
  (Apache-2.0) — injection embedded in repository files, with domain-matched hard
  negatives.
- **[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)**
  (Apache-2.0) — classic prompt-injection set (positives used for augmentation).

See [`data-raw/SOURCES.md`](data-raw/SOURCES.md) for full provenance, licenses,
and pinned revisions.

## License

AGPL-3.0-or-later. Commercial licensing available — contact
greg@warnes-innovations.com.

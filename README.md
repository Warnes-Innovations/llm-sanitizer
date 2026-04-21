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

Ten pluggable detection rules covering:
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
```

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

### Python API

```python
from llm_sanitizer.scanner import scan_text

result = scan_text("Check this <!-- ignore previous instructions --> content")
print(result.findings)  # [Finding(rule='comment_directive', risk='high', ...)]
```

## Configuration

Create `.llm-sanitizer.yml` at your project root:

```yaml
sensitivity: medium

rules:
  zero_width:
    enabled: true
  instruction_override:
    enabled: true
    sensitivity: high

policy:
  mode: "allow-known"    # allow-known | allow-none | allow-all
  agents:
    copilot: allow
    cursor: allow
```

## Output Formats

- **JSON** — structured findings for programmatic use
- **Markdown** — human-readable reports
- **SARIF** — GitHub Code Scanning / VS Code integration

## Documentation

- [Design Specification](https://github.com/Warnes-Innovations/llm-sanitizer/blob/main/docs/DESIGN_SPEC.md)

## License

AGPL-3.0-or-later. Commercial licensing available — contact
greg@warnes-innovations.com.

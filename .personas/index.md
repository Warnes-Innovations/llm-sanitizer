# llm-sanitizer Committee Review Personas

Expert reviewers for evaluating the LLM injection detection and secret redaction scanner.

## Security & Compliance

- [Security Engineer](security-engineer.md) — threat modeling, fail-closed design, control effectiveness, credential handling
- [Compliance & Risk Officer](compliance-risk-officer.md) — GDPR/SOC2, audit trails, vendor risk, data handling compliance
- [Red Teamer](red-teamer.md) — adversarial attack simulation, evasion techniques, resilience under attack

## LLM & Tool Integration

- [LLM Software Developer](llm-software-developer.md) — MCP server semantics, prompt instruction reliability, agent orchestration
- [MCP Tool Designer](mcp-tool-designer.md) — tool usability, consumer integration, parameter clarity, error handling, version stability

## Domain-Specific

- [Secrets & Pattern Coverage Reviewer](secrets-pattern-reviewer.md) — secret pattern completeness, accuracy, obfuscation bypass, alignment with gitleaks/Betterleaks standards
- [Performance & Reliability Engineer](performance-reliability-engineer.md) — resource constraints, memory/CPU bounds, fail-closed limits, operational safety in MCP server deployments

## Usage

Run `/committee-review` to have all 7 personas review the llm-sanitizer codebase and documentation in parallel.

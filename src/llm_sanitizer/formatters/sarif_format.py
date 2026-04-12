# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SARIF 2.1.0 output formatter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from llm_sanitizer.models import DirScanResult, RiskLevel, ScanResult

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_RISK_TO_LEVEL: dict[RiskLevel, str] = {
    RiskLevel.info: "note",
    RiskLevel.low: "note",
    RiskLevel.medium: "warning",
    RiskLevel.high: "error",
    RiskLevel.critical: "error",
}


def _findings_to_results(results_list: list[ScanResult]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert scan results into SARIF results and rules lists."""
    sarif_results: list[dict[str, Any]] = []
    rules_seen: dict[str, dict[str, Any]] = {}

    for scan_result in results_list:
        for finding in scan_result.findings:
            # Build rule entry if not seen
            if finding.rule not in rules_seen:
                rules_seen[finding.rule] = {
                    "id": finding.rule,
                    "name": finding.rule_name.replace(" ", ""),
                    "shortDescription": {"text": finding.rule_name},
                    "fullDescription": {"text": finding.explanation},
                    "defaultConfiguration": {
                        "level": _RISK_TO_LEVEL.get(finding.risk, "warning"),
                    },
                    "properties": {
                        "tags": ["security", "llm-injection"],
                    },
                }

            sarif_results.append({
                "ruleId": finding.rule,
                "level": _RISK_TO_LEVEL.get(finding.risk, "warning"),
                "message": {
                    "text": finding.explanation,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": scan_result.source.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": max(1, finding.location.line),
                                "startColumn": max(1, finding.location.column),
                                "endLine": max(1, finding.location.end_line),
                                "endColumn": max(1, finding.location.end_column),
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": str(
                        hash(f"{scan_result.source}:{finding.location.line}:{finding.matched}")
                    ),
                },
                "properties": {
                    "matched": finding.matched[:200],
                    "risk": finding.risk.name,
                },
            })

    return sarif_results, list(rules_seen.values())


def format_sarif(result: ScanResult | DirScanResult) -> str:
    """Format result as a SARIF 2.1.0 JSON string."""
    if isinstance(result, ScanResult):
        results_list = [result]
    else:
        results_list = result.results

    sarif_results, rules = _findings_to_results(results_list)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llm-sanitizer",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Warnes-Innovations/llm-sanitizer",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)

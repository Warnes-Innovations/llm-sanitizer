# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Data models for findings, scan results, and configuration."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(IntEnum):
    """Five-level risk taxonomy from benign to confirmed malicious."""

    info = 0
    low = 1
    medium = 2
    high = 3
    critical = 4

    @classmethod
    def from_str(cls, value: str) -> "RiskLevel":
        return cls[value.lower()]

    def __str__(self) -> str:
        return self.name


class Location(BaseModel):
    """Source location of a finding within content."""

    line: int
    column: int
    end_line: int
    end_column: int


class FindingContext(BaseModel):
    """Surrounding content context for a finding."""

    before: list[str] = Field(default_factory=list)
    line: str = ""
    after: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single detected instance of an embedded LLM instruction."""

    id: int
    rule: str
    rule_name: str
    risk: RiskLevel
    location: Location
    matched: str
    context: FindingContext
    explanation: str

    def model_dump_json_friendly(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict with risk as string."""
        d = self.model_dump()
        d["risk"] = str(self.risk)
        return d


class SummaryStats(BaseModel):
    """Aggregate summary of all findings in a scan."""

    total_findings: int
    by_risk: dict[str, int]
    max_risk: RiskLevel | None
    rules_triggered: list[str]

    def model_dump_json_friendly(self) -> dict[str, Any]:
        d = self.model_dump()
        d["max_risk"] = str(self.max_risk) if self.max_risk is not None else None
        return d


class ScanResult(BaseModel):
    """Complete result of scanning a single content source."""

    version: str = "0.1.0"
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str
    sensitivity: str
    summary: SummaryStats
    findings: list[Finding]

    def model_dump_json_friendly(self) -> dict[str, Any]:
        d = self.model_dump()
        d["summary"] = self.summary.model_dump_json_friendly()
        d["findings"] = [f.model_dump_json_friendly() for f in self.findings]
        return d


class RedactResult(BaseModel):
    """Result of a redaction operation."""

    status: str
    source: str
    output_path: str
    findings_count: int
    files_written: list[str] = Field(default_factory=list)


class RuleConfig(BaseModel):
    """Per-rule configuration."""

    enabled: bool = True
    sensitivity: str | None = None  # Override global sensitivity


class DirScanResult(BaseModel):
    """Aggregate result of scanning a directory."""

    version: str = "0.1.0"
    scan_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str
    sensitivity: str
    files_scanned: int
    total_findings: int
    max_risk: RiskLevel | None
    results: list[ScanResult]

    def model_dump_json_friendly(self) -> dict[str, Any]:
        d = self.model_dump()
        d["max_risk"] = str(self.max_risk) if self.max_risk is not None else None
        d["results"] = [r.model_dump_json_friendly() for r in self.results]
        return d

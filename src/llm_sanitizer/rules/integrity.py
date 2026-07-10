# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""File-integrity rules — CRITICAL findings for mislabeled/unscannable/corrupt files.

Unlike the pattern rules, these are not matchers run over text: they describe
structural failures the scanner discovers while trying to read a file (see
llm_sanitizer.scanner). A file that can't be trusted to be what it claims —
its declared type doesn't match its bytes, it's corrupt, or no scannable content
can be obtained from it — is surfaced as CRITICAL rather than silently passed
through or raw-text mis-scanned (fail-closed).

There is a single ``type_mismatch`` concept covering *all* files (archives and
otherwise): the extension claims one type, the content magic says another. There
is a single ``corrupt_file`` concept covering structurally-invalid archives and
documents. ``unscannable_binary`` covers a binary that yields no scannable text
(either because extraction produced nothing under the ``fail`` policy, or because
the extractor ran and failed). ``archive_unsupported`` covers an archive format
disabled by configuration.

These carry the canonical id/name/risk metadata for the findings the scanner
emits via :func:`make_integrity_finding`. They are deliberately *not* added to
the text-detection rule registry (``get_all_rules``) — they aren't pattern
matchers — so their ``detect`` is a no-op and the detection-rule set is unchanged
for callers that enumerate it.

A *missing extractor/backend* (markitdown absent, or a 7z/rar backend absent for
a format actually present in the scan) is NOT one of these findings: it is a
systemic coverage gap that fails the whole run fast via
:class:`llm_sanitizer.scanner.ExtractorUnavailableError`, not a per-file finding.
"""

from __future__ import annotations

from llm_sanitizer.models import Finding, FindingContext, Location, RiskLevel
from llm_sanitizer.rules import BaseRule

# Canonical rule identifiers, referenced by the scanner when it emits findings.
TYPE_MISMATCH = "type_mismatch"
CORRUPT_FILE = "corrupt_file"
UNSCANNABLE_BINARY = "unscannable_binary"
ARCHIVE_UNSUPPORTED = "archive_unsupported"


class TypeMismatchRule(BaseRule):
    rule_id = TYPE_MISMATCH
    rule_name = "File Type Mismatch"
    category = "integrity"
    default_risk = RiskLevel.critical
    description = (
        "A file's declared type (its extension) does not match its actual "
        "content (magic bytes) — e.g. a .png whose bytes are an executable, a "
        ".zip that isn't a zip, or a non-archive file hiding real archive "
        "content. A common evasion tactic."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        # Emitted structurally by the scanner, not by scanning text.
        return []


class CorruptFileRule(BaseRule):
    rule_id = CORRUPT_FILE
    rule_name = "Corrupt or Structurally Invalid File"
    category = "integrity"
    default_risk = RiskLevel.critical
    description = (
        "A file of a recognized type could not be opened or structurally "
        "validated — a corrupt/truncated/encrypted archive, or a PDF/Office "
        "document whose structure fails a bounded integrity check."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        return []


class UnscannableBinaryRule(BaseRule):
    rule_id = UNSCANNABLE_BINARY
    rule_name = "Unscannable Binary"
    category = "integrity"
    default_risk = RiskLevel.critical
    description = (
        "A non-archive binary yielded no scannable text — either extraction "
        "produced nothing (under the 'fail' unprocessable-binary policy) or the "
        "extractor ran and failed on this file."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        return []


class ArchiveUnsupportedRule(BaseRule):
    rule_id = ARCHIVE_UNSUPPORTED
    rule_name = "Unsupported Archive Format"
    category = "integrity"
    default_risk = RiskLevel.critical
    description = (
        "An archive uses a format that is disabled by configuration "
        "(archive.formats) and so was not expanded."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        return []


_RULE_NAMES: dict[str, str] = {
    TYPE_MISMATCH: TypeMismatchRule.rule_name,
    CORRUPT_FILE: CorruptFileRule.rule_name,
    UNSCANNABLE_BINARY: UnscannableBinaryRule.rule_name,
    ARCHIVE_UNSUPPORTED: ArchiveUnsupportedRule.rule_name,
}


def make_integrity_finding(
    rule_id: str,
    source: str,
    explanation: str,
    *,
    finding_id: int = 1,
) -> Finding:
    """Build a CRITICAL file-integrity finding.

    Used by the scanner when a file can't be trusted or safely scanned. The
    finding carries no line/column (there is no text location — the whole file
    is the problem); *matched* records the offending source path for context.
    """
    return Finding(
        id=finding_id,
        rule=rule_id,
        rule_name=_RULE_NAMES.get(rule_id, rule_id),
        risk=RiskLevel.critical,
        location=Location(line=0, column=0, end_line=0, end_column=0),
        matched=source,
        context=FindingContext(),
        explanation=explanation,
    )

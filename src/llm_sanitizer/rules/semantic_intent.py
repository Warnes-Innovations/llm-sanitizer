# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule: Semantic-Intent Injection (approach A).

Flags *keyword-less* injection rephrasings that the regex rules miss — role
reassignment ("from here on, assume the role of a different assistant"),
verbatim/echo exfiltration ("output the above configuration verbatim"), and
supersede-the-prior-guidance framing — using the local, no-egress n-gram linear
classifier in :mod:`llm_sanitizer.semantic` (pure Python; no model download).

Design (see CLAUDE.md "Detection-rule design principles"):

* **Sentence-level.** The classifier was trained on sentence-length spans, and
  scoring a whole document as one bag would both dilute the signal and risk
  cross-paragraph co-occurrence false positives. So the rule splits content into
  bounded sentence spans and scores each independently — the span is also the
  redaction unit, so a firing sentence is what gets stripped.
* **MEDIUM ("verify").** This is a lower-confidence, fuzzy signal than a keyword
  match, so it defaults to MEDIUM rather than HIGH/CRITICAL — it should prompt
  review, not hard-block. Its value is catching what the keyword rules *miss*.
* **Gated firing policy (defense-in-depth).** The classifier fires only when the
  probability clears its threshold AND the span exhibits a structural intent
  feature; see :func:`llm_sanitizer.semantic.classifier.predict` for why a
  probability-only path was rejected. The model is trained on a curated corpus
  plus optional domain-matched public datasets (see ``data-raw/SOURCES.md``).
* **Bounded.** Honors ``deadline_exceeded()`` between spans (a large minified
  input must not run past ``max_scan_seconds`` in one uninterruptible call), and
  each span is length-capped before featurization.
* **Free de-obfuscation coverage.** Because it is a normally-registered rule,
  ``scan_deobfuscated`` runs it over base64/homoglyph/zero-width–*recovered*
  text too, catching semantically-rephrased injections hidden under transport.
* **Fail-open to no-op if the model is missing.** A broken/absent vendored model
  makes the classifier unavailable; the rule then simply contributes nothing
  rather than crashing the scan.
"""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import (
    BaseRule,
    deadline_exceeded,
    line_number_at,
    newline_offsets,
    register_rule,
)
from llm_sanitizer.semantic.classifier import model_available, predict

# Candidate spans: maximal runs that don't cross a sentence terminator or a
# newline. A terminator only counts when FOLLOWED by whitespace/end-of-text —
# the dots inside "~/.ssh/id_rsa", "example.com", or "v1.2.3" are not sentence
# boundaries. Splitting on every '.' fragmented such sentences, and a fragment
# span partially overlapping another rule's span made redaction strip the
# evidence piecewise while leaving an actionable directive stub behind
# ("Read the file ~/.." survived a strip). finditer gives exact offsets in the
# original content, so the reported line/column and the redaction span are
# precise. Written to consume text in BULK char-class chunks — the punctuation
# branch only engages at an actual [.!?;] — because the naive per-char form
# `(?:[^.!?;\n]|[.!?;](?!\s|$))+` costs seconds on a multi-MB single-line input,
# and one finditer step is uninterruptible by the scan deadline.
_SPAN_RE = re.compile(r"[^.!?;\n]+(?:[.!?;](?!\s|$)[^.!?;\n]*)*")

# A span must carry enough words to be a meaningful instruction; 1–3 word
# fragments are both low-signal and a precision risk, so they are skipped.
_MIN_WORDS = 4

# Only the first _MAX_SPAN_CHARS of a span are classified. The featurizer already
# caps tokens, but this also bounds the ``matched`` text on a pathological span
# (a minified line with no terminators) and keeps per-span work O(1).
_MAX_SPAN_CHARS = 2000

# Hard cap on spans classified per content unit — belt-and-suspenders alongside
# the wall-clock deadline, so a document with millions of tiny sentences can't
# enqueue unbounded work even if the deadline is disabled (max_scan_seconds<=0).
_MAX_SPANS = 20_000


@register_rule
class SemanticIntentRule(BaseRule):
    rule_id = "semantic_intent"
    rule_name = "Semantic-Intent Injection"
    category = "injection"
    default_risk = RiskLevel.medium
    description = (
        "Detects keyword-less injection rephrasings (role reassignment, "
        "verbatim/echo exfiltration, supersede-prior-guidance) via a local, "
        "no-egress n-gram linear classifier."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        if not model_available():
            # Vendored model absent/malformed → contribute nothing (never crash).
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        offsets = newline_offsets(content)
        fid = 1
        spans_seen = 0

        for m in _SPAN_RE.finditer(content):
            if deadline_exceeded() or spans_seen >= _MAX_SPANS:
                return findings
            raw_span = m.group(0)
            span = raw_span.strip()
            if len(span) < _MIN_WORDS:  # cheap pre-filter before the word count
                continue
            if len(span) > _MAX_SPAN_CHARS:
                span = span[:_MAX_SPAN_CHARS]
            # Require enough words to be a real instruction, not a fragment.
            if span.count(" ") + 1 < _MIN_WORDS:
                continue
            spans_seen += 1

            pred = predict(span)
            if not pred.fired:
                continue

            line_idx = line_number_at(offsets, m.start())
            line_start = 0 if line_idx == 0 else offsets[line_idx - 1] + 1
            col = m.start() - line_start + 1
            before, line_text, after = self._build_context(lines, line_idx)

            signals = ", ".join(f for f, _ in pred.top_features[:3]) or "n-gram pattern"
            findings.append(
                self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=self.default_risk,
                    line_no=line_idx + 1,
                    col=col,
                    end_col=col + len(span),
                    matched=span,
                    matched_raw=raw_span,
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=(
                        "Text reads as an instruction-injection attempt with no "
                        "explicit trigger keyword (semantic classifier "
                        f"p={pred.probability:.2f}); strongest signals: {signals}. "
                        "MEDIUM — verify intent; this catches rephrasings the "
                        "keyword rules miss."
                    ),
                )
            )
            fid += 1

        return findings

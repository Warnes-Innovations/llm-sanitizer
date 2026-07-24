# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared "de-obfuscate, then re-scan" helper for obfuscation rules.

An obfuscation rule (base64, homoglyph, …) is only meaningful when the text it
de-obfuscates actually contains a problem. Rather than each such rule carrying
its own keyword list, it de-obfuscates the text (decode / normalize) and hands
the result here; we re-run the FULL detection ruleset over that text and return
whatever real findings the other rules produce.

Two independent bounds keep this safe against adversarial input (both via
ContextVars, so they are correct under threads/async):

* **Depth** — stops obfuscation rules from re-entering one another without limit
  (base64 → homoglyph → base64 → …) while still catching a couple of layers of
  genuine nesting.
* **Total work (bytes)** — the depth cap alone does NOT bound total work: each
  re-scan runs the full ruleset, and several rules each spawn their own deeper
  re-scan, so an attacker who packs many blobs per layer causes an
  O(branching ** depth) fan-out. A per-chain cumulative-bytes budget caps the
  total text re-scanned regardless of branching, turning that into O(budget).
  The budget resets at the top of each re-scan chain (a top-level rule's first
  call), so every top-level rule gets a fresh allowance.
"""

from __future__ import annotations

import contextvars
import time

from llm_sanitizer.models import Finding, FindingContext, Location, RiskLevel

# Max levels of de-obfuscation re-scan. Depth 1 = re-scan the once-decoded text;
# higher depths catch nesting (base64-in-base64, a homoglyph phrase inside
# base64, …).
_MAX_DEOBFUSCATION_DEPTH = 3

# Cumulative bytes of text the re-scan may hand to the ruleset within a single
# top-level scan. Legit content re-scans a few small decoded/normalized blobs
# (far under this); adversarial fan-out hits the cap and stops, bounding total
# work to O(budget) instead of O(branching ** depth). The scanner resets this
# once per content unit (see reset_rescan_budget) so ALL rules and their nested
# re-scans share one budget — otherwise a rule that makes many top-level calls
# (one per base64 blob) would each get a fresh allowance and defeat the cap.
_MAX_RESCAN_BYTES = 4 * 1024 * 1024

_depth: contextvars.ContextVar[int] = contextvars.ContextVar(
    "llm_sanitizer_deobfuscation_depth", default=0
)
_scanned_bytes: contextvars.ContextVar[int] = contextvars.ContextVar(
    "llm_sanitizer_deobfuscation_bytes", default=0
)
# True while a scanner is managing the budget (it resets once per content unit),
# so scan_deobfuscated must NOT reset per top-level call. False for a direct
# rule.detect() call (a unit test or library user), where each top-level call
# gets its own fresh allowance.
_scanner_managed: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "llm_sanitizer_deobfuscation_managed", default=False
)
# Per-content-unit memo of de-obfuscated-text → findings. Identical decoded
# blobs (e.g. the same base64 token repeated thousands of times, or many blobs
# decoding to the same payload) are scanned once and the result reused. This
# both bounds a breadth fan-out — many *distinct top-level* blobs that decode to
# the same text (Red-Team F3 / M2) — and keeps the low base64 floor (M10)
# affordable. Set to a fresh dict by reset_rescan_budget; None for direct
# rule.detect() calls (no memo, behaves as before).
_rescan_cache: contextvars.ContextVar[dict[str, list[Finding]] | None] = (
    contextvars.ContextVar("llm_sanitizer_rescan_cache", default=None)
)
# Set True when a re-scan was refused because the work budget was exhausted, so
# the scanner can surface a MEDIUM "rescan_incomplete" finding (committee M2 —
# distinct-blob exhaustion must not silently drop a possible injection).
_budget_exhausted: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "llm_sanitizer_deobfuscation_budget_exhausted", default=False
)


def _chained_obfuscation_finding(text: str) -> Finding:
    """Fail-closed finding emitted when de-obfuscation hits the depth cap.

    Reaching the cap means the text has already been peeled through
    ``_MAX_DEOBFUSCATION_DEPTH`` obfuscation layers and is STILL obfuscated
    enough that another rule wants to decode it further. One layer of encoding is
    transport; several independent layers stacked on top of each other have no
    legitimate purpose and are the durable tell of an attempt to hide a payload
    from the scanner. Mechanism-independent: any mix of transports (base64 →
    base64, base64 → homoglyph, zero-width → base64, …) that reached this depth
    counts. HIGH, not CRITICAL: the payload itself was never recovered, so we
    flag the evasion structure rather than a confirmed injection.
    """
    snippet = text[:80]
    return Finding(
        id=1,
        rule="chained_obfuscation",
        rule_name="Chained Obfuscation",
        risk=RiskLevel.high,
        location=Location(line=1, column=1, end_line=1, end_column=1),
        matched=snippet + ("..." if len(text) > 80 else ""),
        matched_raw=text,
        context=FindingContext(before=[], line=snippet, after=[]),
        explanation=(
            "Content is wrapped in multiple stacked obfuscation layers "
            f"(≥{_MAX_DEOBFUSCATION_DEPTH} deep); de-obfuscation was halted at the "
            "safe-depth cap before the payload could be recovered. Deeply nested "
            "transports have no legitimate purpose and are treated as an attempt "
            "to evade detection (fail-closed)."
        ),
    )


def reset_rescan_budget() -> None:
    """Start a fresh re-scan work budget for one top-level scan. The scanner
    calls this once per content unit so every rule (and every nested re-scan
    they trigger) shares a single bounded budget."""
    _scanned_bytes.set(0)
    _scanner_managed.set(True)
    _rescan_cache.set({})
    _budget_exhausted.set(False)


def rescan_budget_exhausted() -> bool:
    """True if any re-scan this content unit was refused for lack of budget."""
    return _budget_exhausted.get()


# Wall-clock deadline (monotonic seconds) for the whole content unit. The
# scanner sets it; rules with long per-match/per-line loops consult
# deadline_exceeded() and break, so max_scan_seconds is enforced at sub-rule
# granularity — a single rule (hidden_content's per-`color:` finding loop,
# base64's per-token re-scan) can otherwise run for minutes in one uninterruptible
# detect() call that the between-rules check never reaches (committee HIGH).
_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "llm_sanitizer_scan_deadline", default=None
)


def set_scan_deadline(deadline: float | None) -> None:
    """Set (or clear, with None) the monotonic wall-clock deadline for the unit."""
    _deadline.set(deadline)


def deadline_exceeded() -> bool:
    """True if a scan deadline is set and has passed. Rules call this inside
    their match loops to stop early rather than run past max_scan_seconds."""
    d = _deadline.get()
    return d is not None and time.monotonic() > d


def scan_deobfuscated(text: str, source: str = "") -> list[Finding]:
    """Run every registered rule over already-de-obfuscated *text* and return
    their findings (empty if the de-obfuscated text is clean).

    Callers pass text they have themselves decoded/normalized; this function
    does not de-obfuscate. Recursion is bounded by ``_MAX_DEOBFUSCATION_DEPTH``
    (depth) and ``_MAX_RESCAN_BYTES`` (cumulative work per scan) so
    mutually-recursive obfuscation rules cannot loop or fan out unboundedly.
    """
    # Late import: the rules package imports this module, so importing the
    # registry at module load time would be circular.
    from llm_sanitizer.rules import get_all_rules

    depth = _depth.get()
    # A direct top-level call (no scanner managing the budget) gets a fresh
    # allowance; under a scanner, the budget is reset once per content unit.
    if depth == 0 and not _scanner_managed.get():
        _scanned_bytes.set(0)

    if depth >= _MAX_DEOBFUSCATION_DEPTH:
        # Do not silently drop the payload (that is the V004/H8 bypass): the
        # content is still obfuscated at the safe-depth cap, so fail closed.
        return [_chained_obfuscation_finding(text)]

    # Memo hit: an identical blob was already scanned this content unit — reuse
    # its result without re-running the ruleset or consuming more budget.
    cache = _rescan_cache.get()
    if cache is not None:
        cached = cache.get(text)
        if cached is not None:
            return cached

    if _scanned_bytes.get() + len(text) > _MAX_RESCAN_BYTES:
        _budget_exhausted.set(True)
        return []
    _scanned_bytes.set(_scanned_bytes.get() + len(text))

    token = _depth.set(depth + 1)
    try:
        findings: list[Finding] = []
        for rule_cls in get_all_rules():
            try:
                # get_all_rules() returns classes; instantiate before detect().
                findings.extend(rule_cls().detect(text, source))
            except Exception:
                # A single misbehaving rule must not sink the whole re-scan.
                continue
        if cache is not None:
            cache[text] = findings
        return findings
    finally:
        _depth.reset(token)

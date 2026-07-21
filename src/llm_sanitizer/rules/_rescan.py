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

from llm_sanitizer.models import Finding

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


def reset_rescan_budget() -> None:
    """Start a fresh re-scan work budget for one top-level scan. The scanner
    calls this once per content unit so every rule (and every nested re-scan
    they trigger) shares a single bounded budget."""
    _scanned_bytes.set(0)
    _scanner_managed.set(True)


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
        return []
    if _scanned_bytes.get() + len(text) > _MAX_RESCAN_BYTES:
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
        return findings
    finally:
        _depth.reset(token)

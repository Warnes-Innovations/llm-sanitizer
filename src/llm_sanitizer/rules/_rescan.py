# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared "de-obfuscate, then re-scan" helper for obfuscation rules.

An obfuscation rule (base64, homoglyph, …) is only meaningful when the text it
de-obfuscates actually contains a problem. Rather than each such rule carrying
its own keyword list, it de-obfuscates the text (decode / normalize) and hands
the result here; we re-run the FULL detection ruleset over that text and return
whatever real findings the other rules produce.

A bounded recursion depth (via a ContextVar so it is safe under threads/async)
stops obfuscation rules from re-entering one another without limit — e.g.
base64 → homoglyph → base64 → … — while still catching a couple of layers of
genuine nesting (base64-in-base64, a homoglyph phrase inside base64, …).
"""

from __future__ import annotations

import contextvars

from llm_sanitizer.models import Finding

# Max levels of de-obfuscation re-scan. Depth 1 = re-scan the once-decoded text;
# higher depths catch nesting. Kept small: the cost is roughly
# (obfuscation-rule count) ** depth, and only obfuscation rules recurse.
_MAX_DEOBFUSCATION_DEPTH = 3

_depth: contextvars.ContextVar[int] = contextvars.ContextVar(
    "llm_sanitizer_deobfuscation_depth", default=0
)


def scan_deobfuscated(text: str, source: str = "") -> list[Finding]:
    """Run every registered rule over already-de-obfuscated *text* and return
    their findings (empty if the de-obfuscated text is clean).

    Callers pass text they have themselves decoded/normalized; this function
    does not de-obfuscate. Recursion is bounded by ``_MAX_DEOBFUSCATION_DEPTH``
    so mutually-recursive obfuscation rules cannot loop unboundedly.
    """
    # Late import: the rules package imports this module, so importing the
    # registry at module load time would be circular.
    from llm_sanitizer.rules import get_all_rules

    if _depth.get() >= _MAX_DEOBFUSCATION_DEPTH:
        return []

    token = _depth.set(_depth.get() + 1)
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

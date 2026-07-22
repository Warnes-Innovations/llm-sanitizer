# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Rule 3: HTML/Markdown Hidden Content."""

from __future__ import annotations

import re

from llm_sanitizer.models import Finding, RiskLevel
from llm_sanitizer.rules import BaseRule, register_rule
from llm_sanitizer.rules._rescan import scan_deobfuscated

# CAMOUFLAGE patterns: text that is rendered but made imperceptible to a human
# reader while remaining in the machine-extracted text — with essentially no
# legitimate purpose. This rule deliberately does NOT detect *structural* hiding
# (`display:none`, `visibility:hidden`, the `hidden` attribute, off-screen
# `.sr-only`): those remove content from the human view AND are ubiquitous,
# legitimate responsive/accessibility formatting, and any injection inside them
# is already caught by the injection rules scanning the raw markup. Flagging
# them would flood consumers with false positives on normal HTML.
#
# `color:` ≈ background and near-zero `opacity:` are handled by dedicated logic
# in detect() (they need cascade/value parsing, not a static regex). The regex
# patterns here cover the two remaining literal camouflage tells. Each entry is
# (pattern, label).
_CAMOUFLAGE_PATTERNS = [
    (re.compile(r'font-size\s*:\s*0', re.IGNORECASE), "CSS font-size:0"),
    # Unicode tag characters (U+E0000 block) — an invisible smuggling channel
    # with no legitimate use outside emoji tag sequences.
    (re.compile(r'[\U000e0000-\U000e007f]+'), "Unicode tag characters (steganographic)"),
]

# Near-zero `opacity:0` is dominated by benign fade-in transitions/animations;
# skip a near-zero opacity when the same rule block declares a transition or
# animation over opacity (its start state), the main legitimate use.
_TRANSITION_RE = re.compile(
    r'(?:transition|animation)\b[^;{}]*\b(?:opacity|all)\b', re.IGNORECASE
)

# --- Text-color visibility analysis -----------------------------------------
#
# Text is invisible when either (a) its own alpha is at or near zero,
# regardless of what is behind it, or (b) its RGB exactly matches the
# background it sits on (camouflage) — not just white-on-white specifically.
# Both are handled below by parsing the `color:` value (and, for case b, the
# enclosing rule block's `background`/`background-color`/`fill` value) into
# a common (r, g, b, alpha) form.
#
# `(?<!-)` excludes any `color:` reached as the tail of a hyphenated property
# name (`background-color:`, `border-color:`, `outline-color:`,
# `text-decoration-color:`, `caret-color:`, etc.) — without it, a bare
# `background-color: white;` with no actual text `color:` declared was
# incorrectly matched as if it were white *text*.
# The value stops at `"`/`'` as well as `;{}` — an inline `style="color:#fff"`
# attribute has no trailing `;` before its closing quote, so without this the
# capture would run past the quote into the surrounding markup. It does NOT
# stop at `,` here — that's handled inside _parse_css_color instead, since a
# bare comma exclusion would also cut off the internal args of `rgb(r, g, b)`.
#
# `fill` is included alongside `background`/`background-color` because
# Mermaid's `style` directive uses `fill` as the node's background-equivalent
# property (`style A fill:#7c3aed,color:#fff,...` — white text is fine
# against a dark fill, exactly like `background` elsewhere in CSS).
_TEXT_COLOR_DECL_RE = re.compile(r'(?<!-)color\s*:\s*([^;{}"\']+)', re.IGNORECASE)
_BACKGROUND_DECL_RE = re.compile(r'(?:background(?:-color)?|fill)\s*:\s*([^;{}"\']+)', re.IGNORECASE)

# Same `(?<!-)` reasoning as `_TEXT_COLOR_DECL_RE` — without it, SVG's
# `fill-opacity:`/`stroke-opacity:` would be misread as the element's overall
# `opacity:`.
_OPACITY_DECL_RE = re.compile(r'(?<!-)opacity\s*:\s*([^;{}"\']+)', re.IGNORECASE)

_TEXT_TRANSPARENT_LABEL = "Text color fully transparent (invisible)"
_TEXT_MATCHES_BG_LABEL = "Text color matches background (invisible)"
_WHITE_NO_BG_LABEL = "White text (invisible on white background)"
_NEAR_ZERO_OPACITY_LABEL = "CSS opacity near zero (invisible)"

# `alpha == 0.0` alone misses the obvious evasion of using a merely
# near-zero alpha instead — `rgba(255,0,0,0.01)` is 1% opacity, imperceptible
# to a human reader but numerically nonzero. Below this threshold, text is
# treated the same as fully transparent. 0.05 (5%) is a conservative cutoff:
# legitimate designs essentially never use sub-5%-opacity text (it's already
# illegible for normal reading at that point), so this isn't expected to
# create new false positives on real content.
_NEAR_ZERO_ALPHA = 0.05

# CSS Level 1 named colors plus a couple of practical extras. Intentionally
# not the full CSS3 named-color table (147+ names) — this is a heuristic
# scanner, not a CSS engine, and an attacker matching colors by *name* still
# gets caught by the literal same-token check further down even when the
# name isn't in this table (e.g. `color: crimson; background: crimson;`
# matches without needing to know crimson's RGB value at all).
_NAMED_COLORS: dict[str, tuple[int, int, int, float]] = {
    "transparent": (0, 0, 0, 0.0),
    "white": (255, 255, 255, 1.0),
    "black": (0, 0, 0, 1.0),
    "red": (255, 0, 0, 1.0),
    "green": (0, 128, 0, 1.0),
    "blue": (0, 0, 255, 1.0),
    "yellow": (255, 255, 0, 1.0),
    "cyan": (0, 255, 255, 1.0),
    "aqua": (0, 255, 255, 1.0),
    "magenta": (255, 0, 255, 1.0),
    "fuchsia": (255, 0, 255, 1.0),
    "silver": (192, 192, 192, 1.0),
    "gray": (128, 128, 128, 1.0),
    "grey": (128, 128, 128, 1.0),
    "maroon": (128, 0, 0, 1.0),
    "purple": (128, 0, 128, 1.0),
    "olive": (128, 128, 0, 1.0),
    "navy": (0, 0, 128, 1.0),
    "teal": (0, 128, 128, 1.0),
    "lime": (0, 255, 0, 1.0),
    "orange": (255, 165, 0, 1.0),
}

_HEX_COLOR_RE = re.compile(r'^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$', re.IGNORECASE)
_RGB_FUNC_RE = re.compile(
    r'^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*([\d.]+%?)\s*)?\)$',
    re.IGNORECASE,
)
_IMPORTANT_RE = re.compile(r'!\s*important', re.IGNORECASE)


def _parse_hex_color(value: str) -> tuple[int, int, int, float] | None:
    match = _HEX_COLOR_RE.match(value)
    if not match:
        return None
    digits = match.group(1)
    if len(digits) in (3, 4):
        r, g, b = (int(c * 2, 16) for c in digits[:3])
        alpha = int(digits[3] * 2, 16) / 255 if len(digits) == 4 else 1.0
        return (r, g, b, alpha)
    r, g, b = (int(digits[i:i + 2], 16) for i in (0, 2, 4))
    alpha = int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0
    return (r, g, b, alpha)


def _parse_rgb_func_color(value: str) -> tuple[int, int, int, float] | None:
    match = _RGB_FUNC_RE.match(value)
    if not match:
        return None
    r, g, b = (min(255, int(match.group(i))) for i in (1, 2, 3))
    alpha_raw = match.group(4)
    if alpha_raw is None:
        alpha = 1.0
    elif alpha_raw.endswith('%'):
        alpha = min(100.0, float(alpha_raw[:-1])) / 100
    else:
        alpha = min(1.0, float(alpha_raw))
    return (r, g, b, alpha)


def _parse_css_color(raw_value: str) -> tuple[int, int, int, float] | None:
    """Best-effort parse of a CSS color value into (r, g, b, alpha), alpha in
    [0, 1]. Returns None for anything not recognized (`currentColor`,
    `inherit`, `var(--x)`, gradients, etc.) — those are silently skipped by
    callers rather than guessed at, since visibility can't be determined
    without full cascade/paint evaluation."""
    value = _IMPORTANT_RE.sub('', raw_value).strip().rstrip(';').strip()
    if not value:
        return None
    # The capturing regex doesn't stop at `,`, so a value may run past its
    # own end into a following comma-separated property (Mermaid `style`
    # directives: `fill:#7c3aed,color:#fff,stroke:none`). For an rgb()/rgba()
    # call, truncate at its closing paren so the function's own internal
    # argument commas are preserved; otherwise truncate at the first comma,
    # since a bare color token never legitimately contains one.
    if re.match(r'rgba?\(', value, re.IGNORECASE):
        close = value.find(')')
        if close != -1:
            value = value[:close + 1]
    else:
        comma = value.find(',')
        if comma != -1:
            value = value[:comma]
    value = value.strip()
    if value.startswith('#'):
        return _parse_hex_color(value)
    rgb = _parse_rgb_func_color(value)
    if rgb is not None:
        return rgb
    return _NAMED_COLORS.get(value.lower())


def _parse_opacity(raw_value: str) -> float | None:
    """Best-effort parse of a CSS `opacity:` value into [0, 1]. Returns None
    for anything not recognized (`inherit`, `var(--x)`, etc.)."""
    value = _IMPORTANT_RE.sub('', raw_value).strip().rstrip(';').strip()
    comma = value.find(',')
    if comma != -1:
        value = value[:comma].strip()
    if not value:
        return None
    try:
        if value.endswith('%'):
            return min(1.0, max(0.0, float(value[:-1]) / 100))
        return min(1.0, max(0.0, float(value)))
    except ValueError:
        return None


# Cap how far the block-boundary scan below will walk in each direction.
# Bounds worst-case scan cost against adversarial input (e.g. a huge file
# with a lone `color:white` and no nearby braces at all) rather than
# scanning the whole document per match.
_BLOCK_SCAN_WINDOW = 50


def _rule_block_text(lines: list[str], line_idx: int) -> str:
    """Best-effort CSS rule-block text around lines[line_idx]: from the
    nearest preceding unclosed `{` through the nearest following `}`, so a
    background/color pair split across multiple lines of the *same* rule
    is still seen together (plain formatted CSS almost always writes one
    declaration per line). Plain CSS rule blocks don't nest, so this scans
    for the nearest braces rather than tracking full nesting depth — a
    line containing `}` always means "a rule ended here," even if that
    same line also contains its own `{` (a complete single-line rule), so
    an already-closed neighboring rule's background can't leak into ours.
    Falls back to just the current line when no enclosing `{`/`}` pair is
    found within the scan window (e.g. inline style="..." attributes,
    which are inherently single-line anyway)."""
    start = line_idx
    found_open = False
    limit = max(0, line_idx - _BLOCK_SCAN_WINDOW)
    while start > limit:
        prev = lines[start - 1]
        if "}" in prev:
            break  # a rule closed here; anything before it is a different context
        if "{" in prev:
            start -= 1
            found_open = True
            break
        start -= 1
    if not found_open and "{" not in lines[start]:
        return lines[line_idx]

    end = line_idx
    limit = min(len(lines) - 1, line_idx + _BLOCK_SCAN_WINDOW)
    while end < limit:
        if "}" in lines[end]:
            break
        end += 1
    if "}" not in lines[end]:
        return lines[line_idx]

    return "\n".join(lines[start:end + 1])


def _classify_text_color(raw_color_value: str, lines: list[str], line_idx: int) -> str | None:
    """Returns the finding label if `raw_color_value` (a `color:` value) is
    likely invisible, else None. Two independent mechanisms: the color's own
    alpha is near zero (invisible regardless of background), or its RGB
    exactly matches the background declared elsewhere in the same rule block
    (camouflage). If no background is declared anywhere in the block, falls
    back to flagging literal white only — the original, narrower heuristic —
    since we can't rule out inheriting a typical white page background."""
    color = _parse_css_color(raw_color_value)
    if color is None:
        return None
    r, g, b, alpha = color
    if alpha < _NEAR_ZERO_ALPHA:
        return _TEXT_TRANSPARENT_LABEL

    block = _rule_block_text(lines, line_idx)
    bg_match = _BACKGROUND_DECL_RE.search(block)
    if bg_match:
        bg_color = _parse_css_color(bg_match.group(1))
        if bg_color is not None and bg_color[:3] == (r, g, b):
            return _TEXT_MATCHES_BG_LABEL
        return None  # explicit, different (or unparsable) background — presumed visible

    if (r, g, b) == (255, 255, 255):
        return _WHITE_NO_BG_LABEL
    return None


@register_rule
class HiddenContentRule(BaseRule):
    rule_id = "hidden_content"
    rule_name = "HTML/Markdown Hidden Content"
    category = "steganography"
    default_risk = RiskLevel.high
    description = (
        "Detects CSS and HTML constructs that hide content from human readers "
        "but remain visible to LLM text extraction."
    )

    def detect(self, content: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        fid = 1

        # This rule flags CAMOUFLAGE — text rendered but made imperceptible to a
        # human (color matching background, near-zero opacity, zero font-size,
        # invisible tag characters) while remaining in the extracted text. Unlike
        # base64/homoglyph, that camouflage has NO legitimate purpose, so its mere
        # presence is a finding: MEDIUM on its own. When the camouflaged region's
        # line also trips an injection rule — an injection was deliberately hidden
        # — it escalates to CRITICAL. Structural hiding (display:none, etc.) is
        # not detected here at all (see _CAMOUFLAGE_PATTERNS note).
        concealed_cache: dict[int, list[str]] = {}

        def concealed_rules(line_idx: int) -> list[str]:
            if line_idx not in concealed_cache:
                revealed = scan_deobfuscated(lines[line_idx], source)
                concealed_cache[line_idx] = sorted(
                    {f.rule for f in revealed if f.rule != self.rule_id}
                )
            return concealed_cache[line_idx]

        def emit(line_idx: int, m: re.Match[str], label: str) -> None:
            nonlocal fid
            rules = concealed_rules(line_idx)
            before, line_text, after = self._build_context(lines, line_idx)
            if rules:
                risk = RiskLevel.critical
                explanation = (
                    f"Injection concealed by camouflage ({label}): the "
                    f"imperceptible text is flagged by {', '.join(rules)}. Hiding "
                    "an injection from human readers is a strong malicious signal."
                )
            else:
                risk = RiskLevel.medium
                explanation = (
                    f"Camouflaged content ({label}): text is rendered but made "
                    "imperceptible to a human reader while remaining in the "
                    "extracted text — a technique with no legitimate purpose. No "
                    "injection was detected in it."
                )
            findings.append(
                self._make_finding(
                    finding_id=fid,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    risk=risk,
                    line_no=line_idx + 1,
                    col=m.start() + 1,
                    end_col=m.end() + 1,
                    matched=m.group(0)[:200],
                    matched_raw=m.group(0),
                    before=before,
                    line_text=line_text,
                    after=after,
                    explanation=explanation,
                )
            )
            fid += 1

        # Every match on a line is reported, not just the first. Minified
        # HTML puts an entire document on one line — a first-match-only cap
        # under-reports, and redaction (which removes exactly the reported
        # spans) then needs one full scan/redact round trip per hidden span
        # to converge on such files.
        # H1: memoize the per-line rule-block text and its background lookup.
        # A minified line can carry thousands of `color:` decls that all resolve
        # to the SAME enclosing block; recomputing _rule_block_text and the
        # background regex search for each was O(n²) per line (measured: a 1 MB
        # one-line stylesheet took ~40 min). Compute once per line index.
        block_cache: dict[int, str] = {}

        def block_of(idx: int) -> str:
            if idx not in block_cache:
                block_cache[idx] = _rule_block_text(lines, idx)
            return block_cache[idx]

        # Per line: (background_declared, background_rgb_or_None).
        bg_cache: dict[int, tuple[bool, tuple[int, int, int] | None]] = {}

        def bg_of(idx: int) -> tuple[bool, tuple[int, int, int] | None]:
            if idx not in bg_cache:
                m = _BACKGROUND_DECL_RE.search(block_of(idx))
                if m:
                    parsed = _parse_css_color(m.group(1))
                    bg_cache[idx] = (True, parsed[:3] if parsed else None)
                else:
                    bg_cache[idx] = (False, None)
            return bg_cache[idx]

        for pattern, label in _CAMOUFLAGE_PATTERNS:
            for line_idx, line in enumerate(lines):
                for m in pattern.finditer(line):
                    emit(line_idx, m, label)

        for line_idx, line in enumerate(lines):
            for m in _TEXT_COLOR_DECL_RE.finditer(line):
                color = _parse_css_color(m.group(1))
                if color is None:
                    continue
                r, g, b, alpha = color
                if alpha < _NEAR_ZERO_ALPHA:
                    emit(line_idx, m, _TEXT_TRANSPARENT_LABEL)
                    continue
                declared, bg_rgb = bg_of(line_idx)
                if declared:
                    if bg_rgb is not None and bg_rgb == (r, g, b):
                        emit(line_idx, m, _TEXT_MATCHES_BG_LABEL)
                    # explicit, different/unparsable background — presumed visible
                elif (r, g, b) == (255, 255, 255):
                    emit(line_idx, m, _WHITE_NO_BG_LABEL)

        for line_idx, line in enumerate(lines):
            for m in _OPACITY_DECL_RE.finditer(line):
                opacity = _parse_opacity(m.group(1))
                if opacity is not None and opacity < _NEAR_ZERO_ALPHA:
                    # Skip a fade-in transition/animation start state (benign).
                    if _TRANSITION_RE.search(block_of(line_idx)):
                        continue
                    emit(line_idx, m, _NEAR_ZERO_OPACITY_LABEL)

        return findings

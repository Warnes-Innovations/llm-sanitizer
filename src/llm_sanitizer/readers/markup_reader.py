# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Presentation-markup reader — extracts the readable text from formats whose
markup is pure formatting noise.

Most content reaches the rules as-is, which is deliberate: for HTML, SVG, XML,
Markdown, and source code the *markup itself* is a legitimate injection vector
(an HTML comment directive, an `onload=` handler, a CSS-hidden span), so
stripping it would blind the scanner. Those formats must never be routed
through here.

A small class of formats is different. RTF carries no scriptable surface — its
control words are typography — and it is ASCII, so it is sniffed as text and
would be rule-scanned as raw `\\fs21 \\pard \\cf8` noise rather than as the
document a human reads. Worse, RTF can encode any character as a `\\'hh` hex
escape, so text that a reader sees plainly can be invisible to a raw scan:
`\\'69\\'67\\'6e\\'6f\\'72\\'65` renders as "ignore" but contains none of those
letters literally. Extracting first closes that bypass.

Deliberately NOT extracted, and why:

* **HTML / SVG / XML / Markdown / source** — the markup is an injection vector
  in its own right (see above). Handled by the rules directly.
* **LaTeX / TeX** — presentation markup, but the markup carries executable and
  exfiltration surface (``\\write18`` shell escape, ``\\input``/``\\include``,
  ``\\href``). Stripping to rendered text would discard exactly the part worth
  scanning, so it falls under the HTML rule above, not this one.
* **ODT / DOCX / PDF and friends** — binary (ZIP-based) documents, already
  routed through markitdown by the scanner's binary-extraction path.
* **.eml** — RFC-822 is text whose headers are themselves scan-worthy, and MIME
  bodies are covered by the base64 rule. No extraction gain.
"""

from __future__ import annotations


class MarkupExtractionError(RuntimeError):
    """The document declared a presentation-markup format but could not be
    parsed. Callers must fail closed: falling back to the raw markup would let
    an escaped payload (RTF ``\\'hh``) through unscanned."""


# An RTF document must begin with this control word (leading whitespace and a
# BOM are tolerated). Content-based, not extension-based, matching the scanner's
# "real type, not name" philosophy — a payload named notes.txt is still routed
# through extraction, and a file named .rtf that is not RTF is left alone.
_RTF_MAGIC = "{\\rtf"
_RTF_MAGIC_BYTES = b"{\\rtf"

# Only inspect the head of the document when sniffing.
_SNIFF_CHARS = 64

# Leading bytes to ignore before the magic: UTF-8 BOM and whitespace.
_LEADING_BYTES = b"\xef\xbb\xbf \t\r\n"
_LEADING_CHARS = "﻿ \t\r\n"


def is_rtf(text: str) -> bool:
    """True if *text* begins with the RTF magic control word."""
    return text[:_SNIFF_CHARS].lstrip(_LEADING_CHARS).startswith(_RTF_MAGIC)


def sniff_rtf(head: bytes) -> bool:
    """True if the leading *bytes* of a file are the RTF magic control word.

    Byte-level so it can run BEFORE the binary/text sniff. An RTF document is
    ASCII and normally sniffs as text, but a single stray control byte flips it
    to "binary", where markitdown — which does not support RTF at all — has
    been observed to mis-decode the ASCII as UTF-16 and return CJK mojibake.
    That is non-empty, so it passes the "no extractable text" check and the file
    is reported clean without its real content ever being scanned. Deciding on
    the magic bytes first routes any file that DECLARES itself RTF to a parser
    that actually understands RTF, whatever the sniff says.
    """
    return head[:_SNIFF_CHARS].lstrip(_LEADING_BYTES).startswith(_RTF_MAGIC_BYTES)


def extract_markup_text(text: str) -> str | None:
    """Return the readable text of a presentation-markup document.

    Returns None when *text* is not a format this module extracts, which is the
    common case — the caller then scans the content unchanged.

    Raises:
        ImportError: striprtf is not installed (a core dependency; a broken
            install, not an optional feature).
        MarkupExtractionError: the content declared itself RTF but could not be
            parsed.
    """
    if not is_rtf(text):
        return None

    try:
        from striprtf.striprtf import rtf_to_text
    except ImportError as exc:  # pragma: no cover - broken install
        raise ImportError(
            "striprtf is unavailable, but it is a core dependency of "
            "llm-sanitizer — the running environment is missing declared "
            "dependencies. Reinstall/sync it (e.g. 'uv sync' or "
            "'pip install -e .') and relaunch the server."
        ) from exc

    try:
        # errors="ignore" applies to undecodable codepage bytes inside the
        # document, not to structural failures — those still raise and are
        # translated below. striprtf ships no type stubs, hence the ignore.
        extracted: str = rtf_to_text(text, errors="ignore")  # type: ignore[no-untyped-call]
    except Exception as exc:
        raise MarkupExtractionError(f"RTF extraction failed: {exc}") from exc
    return extracted

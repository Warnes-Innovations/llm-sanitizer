# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""In-place redaction of binary document formats.

The redact paths always write a document's redacted **extracted text** (issue
#51). This module is the additional step for callers who need the original
format back — a human opening the file, an archive that must stay a PDF.

**Everything here is fail-closed.** An in-place rewrite either produces a file
this module has PROVED clean, or it produces no file and the caller falls back
to the text output. There is no path on which an unverified rewrite reaches an
output path.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from llm_sanitizer.models import Finding


def _load_pymupdf() -> Any:
    """Import PyMuPDF behind a deliberately untyped boundary.

    A plain ``import pymupdf`` trips ``mypy --strict`` with ``no-untyped-call``
    on every call into it, because the package ships only partial annotations.
    Keeping the boundary ``Any`` HERE is the narrow fix; the alternative —
    relaxing ``disallow_untyped_calls`` for this module in pyproject.toml —
    would switch the strict check off for all the code in this file that mypy
    can actually check, to accommodate one third-party package.

    Raises ImportError (via ModuleNotFoundError) when the [pdf-redact] extra is
    not installed; every caller treats that as "cannot rewrite", not an error.
    """
    return importlib.import_module("pymupdf")

#: Status values for :class:`BinaryRedaction`.
#:   ok             — a verified-clean rewrite was written.
#:   unavailable    — the backend or the input made a rewrite impossible
#:                    (no PyMuPDF, encrypted PDF, a marker redaction mode).
#:   refused        — a rewrite was produced and FAILED verification, so it was
#:                    deleted. This is the important one: it means the format
#:                    could not be sanitized, not that nobody tried.
#:   not-applicable — the input is not a format this module rewrites.
_OK = "ok"
_UNAVAILABLE = "unavailable"
_REFUSED = "refused"
_NOT_APPLICABLE = "not-applicable"

#: Redaction modes whose whole purpose is to KEEP the matched text as a visible
#: marker. Rewriting a PDF to "keep the text, marked" is not something
#: apply_redactions can express, and silently removing the text instead would
#: contradict the mode the caller asked for.
_MARKER_MODES = frozenset({"comment", "highlight"})

#: Shortest needle worth searching for. Below this, `search_for` matches
#: everywhere and the stream predicate produces noise.
_MIN_NEEDLE_LEN = 4


@dataclass(frozen=True)
class BinaryRedaction:
    """Outcome of trying to rewrite a binary document with its findings removed."""

    status: str
    detail: str
    output_path: str | None = None
    #: Whether the raw-content-stream check had POWER on this document — i.e.
    #: whether the predicate could actually locate the needle in the UNREDACTED
    #: input. A "not found" from a predicate that could never have found it is
    #: not evidence of anything. See `_stream_contains`.
    stream_check: str = "not-run"

    @property
    def written(self) -> bool:
        return self.status == _OK


def is_pdf(path: Path) -> bool:
    """True if *path* begins with the PDF magic bytes.

    Deliberately NOT keyed on `scanner._is_binary`: that sniffs for a NUL byte
    in the first 8000 bytes, and a short, simple, text-only PDF has none, so it
    classifies as text. Extension is not consulted either — content decides,
    as everywhere else in this codebase.
    """
    try:
        with path.open("rb") as fh:
            return fh.read(5) == b"%PDF-"
    except OSError:
        return False


def _needles(findings: Iterable[Finding]) -> list[str]:
    """The distinct text fragments to remove from the document.

    Findings carry offsets into the markitdown-EXTRACTED text, which do not map
    onto PDF content-stream positions, so the text itself is the only usable
    handle. A multi-line match is split per line, because PyMuPDF's
    `search_for` matches within a line.
    """
    out: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        raw = finding.matched_raw or finding.matched or ""
        for line in raw.splitlines():
            piece = line.strip()
            if len(piece) >= _MIN_NEEDLE_LEN and piece not in seen:
                seen.add(piece)
                out.append(piece)
    return out


def _needle_byte_forms(needle: str) -> list[bytes]:
    """Every encoding of *needle* a PDF content stream plausibly stores.

    A content stream writes show-text operands as literal strings `(...)` OR as
    HEX `<5175...>`, and MuPDF emits hex. Searching only for the UTF-8 bytes —
    which is what this module's first draft did — can therefore never match,
    and returns a clean-looking `False` for every document. That vacuous
    negative is the exact failure this codebase's rules call out: before
    believing a negative, confirm the instrument could have produced a
    positive. `_stream_contains` measures that per call.
    """
    forms = [needle.encode("utf-8")]
    try:
        latin = needle.encode("latin-1")
    except UnicodeEncodeError:
        latin = b""
    if latin and latin not in forms:
        forms.append(latin)
    for encoded in (latin, needle.encode("utf-16-be")):
        if not encoded:
            continue
        hexed = encoded.hex()
        forms.append(hexed.encode("ascii"))
        forms.append(hexed.upper().encode("ascii"))
    return forms


def _stream_contains(doc: Any, needles: Sequence[str]) -> bool:
    """True if any needle appears, in any plausible encoding, in a DECOMPRESSED
    content stream of *doc*.

    This is the layer that catches the classic redaction failure: a black
    rectangle drawn over text leaves the glyphs in the content stream, so the
    document still carries the secret and a copy-paste recovers it. A check
    that only re-extracts text can be fooled by a viewer-level cover-up in a
    way this one cannot.
    """
    for pno in range(doc.page_count):
        page = doc[pno]
        for xref in page.get_contents():
            data = doc.xref_stream(xref)
            if data is None:
                continue
            for needle in needles:
                if any(form in data for form in _needle_byte_forms(needle)):
                    return True
    return False


def redact_pdf_in_place(
    src: Path,
    dst: Path,
    findings: Sequence[Finding],
    *,
    mode: str,
    sensitivity: str,
) -> BinaryRedaction:
    """Rewrite *src* to *dst* with every finding's text removed, or write nothing.

    The rewrite is built from the redacted PAGES ONLY (a fresh document, so no
    catalog-level carrier comes along), stripped of attachments, metadata,
    annotations, form widgets and outlines, and published only after passing
    FOUR independent checks run against the candidate output. Any failure
    deletes the candidate and returns ``refused``:

    1. **The project's own pipeline** — markitdown extraction into `Scanner`,
       at the caller's sensitivity. Apples-to-apples with the scan that
       produced the findings in the first place: nothing it flagged may
       survive.
    2. **A second, independent extractor** — PyMuPDF's own `get_text`, scanned
       the same way. Two extractors disagreeing about what a file says is
       itself a reason not to ship the file.
    3. **The decompressed content streams** — the needle must be absent in
       every plausible encoding, and this check reports whether it had any
       POWER on this document rather than letting a vacuous negative pass for
       evidence.
    4. **Every other object in the file** — each non-image object and stream,
       with PDF string syntax decoded (hex, literal, UTF-16), searched for the
       needles and run through the rules. Catches a payload the body scan never
       saw.

    Never raises for an expected condition; returns a status instead, because
    the caller's fallback (write the redacted extracted text) is a normal
    outcome, not an error.
    """
    if mode in _MARKER_MODES:
        return BinaryRedaction(
            _UNAVAILABLE,
            f"mode={mode!r} keeps the matched text as a visible marker, which a "
            "PDF content-stream rewrite cannot express; removing it instead "
            "would contradict the requested mode",
        )

    try:
        pymupdf = _load_pymupdf()
    except ImportError:
        return BinaryRedaction(
            _UNAVAILABLE,
            "in-place PDF redaction needs PyMuPDF; install llm-sanitizer"
            "[pdf-redact]. The redacted extracted text was written instead.",
        )

    needles = _needles(findings)
    if not needles:
        return BinaryRedaction(
            _UNAVAILABLE,
            "no finding carried matchable text, so there is nothing to locate "
            "in the PDF",
        )

    # Build the candidate beside the destination and only ever rename it into
    # place after verification, so an unverified rewrite never exists at dst
    # even for an instant.
    candidate = dst.with_name(dst.name + ".unverified")
    try:
        try:
            doc = pymupdf.open(str(src))
        except Exception as exc:  # noqa: BLE001 — any parse failure is "cannot rewrite"
            return BinaryRedaction(_UNAVAILABLE, f"PyMuPDF could not open the PDF: {exc}")

        try:
            if doc.needs_pass or doc.is_encrypted:
                return BinaryRedaction(
                    _UNAVAILABLE, "the PDF is encrypted and cannot be rewritten"
                )

            # Does the stream predicate have power on THIS document? Measured
            # against the unredacted input, before anything is changed.
            had_power = _stream_contains(doc, needles)

            for pno in range(doc.page_count):
                page = doc[pno]
                for needle in needles:
                    for rect in page.search_for(needle):
                        page.add_redact_annot(rect, fill=(0, 0, 0))
                # apply_redactions REMOVES the glyphs from the content stream.
                # It is not a drawn rectangle — that is the failure this whole
                # function is built to avoid — but it is still not trusted:
                # the verification below proves it per call.
                page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE)

            # Publish PAGES ONLY: copy them into a fresh document so no
            # catalog-level carrier (custom keys, the structure tree with its
            # /Alt text, names/JavaScript, OpenAction) comes along — the strip
            # list below cannot enumerate every such key (0.7.2 review).
            fresh = pymupdf.open()
            try:
                fresh.insert_pdf(doc)
                _strip_unverified_carriers(fresh)
                fresh.save(str(candidate), garbage=4, deflate=True, clean=True)
            finally:
                fresh.close()
        finally:
            doc.close()

        verdict = _verify(candidate, needles, sensitivity=sensitivity)
        if verdict is not None:
            return BinaryRedaction(
                _REFUSED,
                f"the rewritten PDF failed verification ({verdict}); it was "
                "deleted and no binary output was written",
                stream_check="verified" if had_power else "no-power",
            )

        candidate.replace(dst)
        return BinaryRedaction(
            _OK,
            "findings removed from the PDF content stream; rebuilt from pages "
            "only and verified absent by re-extraction, a raw-stream check and "
            "a whole-file check",
            output_path=str(dst),
            stream_check="verified" if had_power else "no-power",
        )
    except OSError as exc:
        return BinaryRedaction(_UNAVAILABLE, f"could not write the rewritten PDF: {exc}")
    finally:
        # Belt and braces: a candidate must never survive a failure path.
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def _strip_unverified_carriers(doc: Any) -> None:
    """Remove every place text can live that the page-text checks do not read.

    REGRESSION (0.7.2): the rewrite cleaned the page content streams and
    verified only page text and page streams, so a payload in the info title,
    XMP, an embedded file, an annotation or an outline entry survived into a
    rewrite reported ``ok``. The rewrite exists to give back the DOCUMENT; its
    attachments and metadata are not part of that promise, and keeping them
    unverified is what made "verified-clean" false. Stripped here, then
    re-checked across the whole file by `_residue_anywhere`.
    """
    for i in reversed(range(doc.embfile_count())):
        doc.embfile_del(i)
    doc.set_metadata({})
    doc.del_xml_metadata()
    doc.set_toc([])
    for pno in range(doc.page_count):
        page = doc[pno]
        for widget in list(page.widgets() or ()):
            page.delete_widget(widget)
        annot = page.first_annot
        while annot is not None:
            nxt = annot.next
            page.delete_annot(annot)
            annot = nxt


_HEX_STRING = re.compile(r"<([0-9A-Fa-f\s]+)>")
# A PDF name: `/` then regular characters, where `#xx` spells a byte. A payload
# written as `/Disregard#20your#20...` is a name, not a string, and the string
# decoder never saw it (0.7.2 review, pass 3).
_NAME = re.compile(r"/([^\s/\[\]()<>{}%]*#[0-9A-Fa-f]{2}[^\s/\[\]()<>{}%]*)")
_NAME_ESCAPE = re.compile(r"#([0-9A-Fa-f]{2})")
_LITERAL_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
                    "(": "(", ")": ")", "\\": "\\"}


def _pdf_string_text(raw: bytes) -> str:
    """Every plausible reading of a PDF string's bytes, joined by LF.

    UTF-16 when it carries a BOM; otherwise BOTH Latin-1 (PDFDocEncoding's
    near relative) AND UTF-8 — PyMuPDF and pdfminer read UTF-8 bytes as UTF-8,
    so a zero-width splitter carried as UTF-8 bytes was mangled by a Latin-1-
    only reading and the payload passed (0.7.2 review, pass 4)."""
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", "replace")
    readings = [raw.decode("latin-1")]
    body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
    # HYBRID, never strict: valid UTF-8 as UTF-8 and only the invalid bytes as
    # Latin-1. A strict decode dropped the whole UTF-8 reading for ONE invalid
    # byte, and a trailing 0xFF hid a split payload (0.7.2 review, pass 5).
    readings.append("".join(
        chr(ord(c) - 0xDC00) if 0xDC80 <= ord(c) <= 0xDCFF else c
        for c in body.decode("utf-8", errors="surrogateescape")
    ))
    return "\n".join(readings)


def _literal_strings(syntax: str) -> list[str]:
    """Bodies of `(...)` literal strings, honouring BALANCED nested parentheses
    and backslash escapes — a regex stopped at the first `)` and cut
    `(a (b) c)` short (0.7.2 review, pass 3)."""
    out: list[str] = []
    i, n = 0, len(syntax)
    while i < n:
        if syntax[i] != "(":
            i += 1
            continue
        depth, j, body = 1, i + 1, []
        while j < n and depth:
            c = syntax[j]
            if c == "\\" and j + 1 < n:
                body.append(syntax[j:j + 2])
                j += 2
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if not depth:
                    break
            body.append(c)
            j += 1
        out.append("".join(body))
        i = j + 1
    return out


def _unescape_literal(body: str) -> str:
    chars: list[str] = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in "01234567":
                j = i + 1
                while j < len(body) and j < i + 4 and body[j] in "01234567":
                    j += 1
                chars.append(chr(int(body[i + 1:j], 8) & 0xFF))
                i = j
                continue
            if nxt == "\n":  # a backslash-newline continues the string
                i += 2
                continue
            chars.append(_LITERAL_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        chars.append(c)
        i += 1
    return "".join(chars)


def _decode_pdf_strings(syntax: str) -> str:
    """The TEXT of every hex `<...>` string, literal `(...)` string and
    `#xx`-escaped name in *syntax*.

    Best-effort and deliberately over-inclusive: it only feeds a check that
    refuses, so decoding something that was not really a string costs at most a
    spurious refusal, never a missed payload. `<<` dictionary brackets never
    match the hex pattern (they contain `<`, not hex digits).
    """
    out: list[str] = []
    for m in _HEX_STRING.finditer(syntax):
        digits = re.sub(r"\s", "", m.group(1))
        if len(digits) % 2:
            digits += "0"
        try:
            out.append(_pdf_string_text(bytes.fromhex(digits)))
        except ValueError:
            continue
    for body in _literal_strings(syntax):
        out.append(_pdf_string_text(_unescape_literal(body).encode("latin-1", "replace")))
    for m in _NAME.finditer(syntax):
        spelled = _NAME_ESCAPE.sub(lambda e: chr(int(e.group(1), 16)), m.group(1))
        out.append(_pdf_string_text(spelled.encode("latin-1", "replace")))
    return "\n".join(out)


def _residue_anywhere(doc: Any, needles: Sequence[str], *, sensitivity: str) -> str | None:
    """Check EVERY object and decompressed stream, not only the page streams.

    Two questions per object: does any needle appear in any encoding, and does
    the object's text trip a rule on its own? The second is what catches a
    payload that never became a needle — e.g. one that lives only in the title,
    which the body-text scan that produced the findings never saw. An image's
    PIXEL DATA is not treated as text, but its dictionary is checked like any
    other object. Page content streams are needle-searched, and the strings in
    them (show-text operands, /ActualText) are rule-scanned; their raw
    operators are not, because operators are not prose.
    """
    from llm_sanitizer.scanner import Scanner

    content_xrefs = {
        xref for pno in range(doc.page_count) for xref in doc[pno].get_contents()
    }
    scanner = Scanner()
    for xref in range(1, doc.xref_length()):
        try:
            source = doc.xref_object(xref, compressed=False)
        except Exception as exc:  # noqa: BLE001
            # An object the checker cannot read is one it cannot vouch for.
            # Skipping it would make this verifier fail OPEN on exactly the
            # objects a crafted file would hide a payload in.
            return f"PDF object {xref} could not be read ({exc}), so it cannot be verified"
        data = None
        # Read the KEY, never a substring of the dictionary's text: a stream
        # whose dictionary merely CONTAINS "/Subtype /Image" was skipped (0.7.2
        # review). And exempt only the PIXELS: skipping the whole object let a
        # payload in the image's DICTIONARY through (review pass 2).
        is_image = doc.xref_get_key(xref, "Subtype") == ("name", "/Image")
        if doc.xref_is_stream(xref) and not is_image:
            try:
                data = doc.xref_stream(xref)
            except Exception:  # noqa: BLE001 — undecodable: cannot vouch for it
                return f"object {xref} has a stream that could not be decoded, so it cannot be verified"
        # Decode PDF string syntax too: `<FEFF...>` hex and `(...)` literals
        # hold text the raw syntax does not show, and the rules must see the
        # text, not its encoding (0.7.2 review).
        decoded = _decode_pdf_strings(source + (data or b"").decode("latin-1"))
        blob = (
            source.encode("latin-1", "replace")
            + (data or b"")
            + decoded.encode("utf-8", "replace")
        )
        for needle in needles:
            if any(form in blob for form in _needle_byte_forms(needle)):
                return f"a redacted fragment is still present in PDF object {xref}"
        if xref in content_xrefs:
            # Operators are not prose, so a content stream's raw syntax is not
            # rule-scanned — but the STRINGS in it are text: show-text operands
            # and marked-content /ActualText, which neither extractor reads
            # (review pass 2). Rule-scan those.
            text = decoded
        else:
            text = blob.decode("latin-1") + "\n" + decoded
        if scanner.scan(
            text, source=f"pdf-object-{xref}", sensitivity=sensitivity
        ).summary.total_findings:
            return f"PDF object {xref} still trips a detection rule"
    return None


def _verify(candidate: Path, needles: Sequence[str], *, sensitivity: str) -> str | None:
    """Return a failure description, or None if *candidate* passes every check."""
    from llm_sanitizer.scanner import Scanner, read_scannable_content

    pymupdf = _load_pymupdf()

    # 1. The project's own extract-and-scan pipeline.
    try:
        text = read_scannable_content(candidate, binary_mode="extract")
    except Exception as exc:  # noqa: BLE001 — unverifiable is a failure, not a crash
        return f"the project extractor raised on the output: {exc}"
    if text is None:
        return "the project extractor could not read the rewritten PDF, so the output cannot be verified"
    survivors = Scanner().scan(text, source=str(candidate), sensitivity=sensitivity)
    if survivors.summary.total_findings:
        return (
            f"{survivors.summary.total_findings} finding(s) survived in the "
            "project extractor's text"
        )

    # 2. A second, independent extractor.
    try:
        doc = pymupdf.open(str(candidate))
        try:
            pymupdf_text = "\n".join(doc[i].get_text() for i in range(doc.page_count))
            leftover_streams = _stream_contains(doc, needles)
        finally:
            doc.close()
    except Exception as exc:  # noqa: BLE001
        return f"PyMuPDF could not re-read the rewritten PDF: {exc}"

    for needle in needles:
        if needle in pymupdf_text:
            return "a redacted fragment is still present in PyMuPDF's extracted text"
    second = Scanner().scan(pymupdf_text, source=str(candidate), sensitivity=sensitivity)
    if second.summary.total_findings:
        return (
            f"{second.summary.total_findings} finding(s) survived in PyMuPDF's "
            "extracted text"
        )

    # 3. The decompressed content streams.
    if leftover_streams:
        return "a redacted fragment is still present in a decompressed content stream"

    # 4. Every other object in the file — metadata, attachments, annotations,
    # outlines, anything a future PyMuPDF keeps. Checks 1-3 read page text only.
    try:
        doc = pymupdf.open(str(candidate))
        try:
            residue = _residue_anywhere(doc, needles, sensitivity=sensitivity)
        finally:
            doc.close()
    except Exception as exc:  # noqa: BLE001
        return f"the whole-file check could not read the rewritten PDF: {exc}"
    if residue is not None:
        return residue

    return None

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

    The rewrite is only ever published after passing THREE independent checks,
    run against the candidate output. Any failure deletes the candidate and
    returns ``refused``:

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

            doc.save(str(candidate), garbage=4, deflate=True, clean=True)
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
            "findings removed from the PDF content stream and verified absent "
            "by re-extraction and a raw-stream check",
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

    return None

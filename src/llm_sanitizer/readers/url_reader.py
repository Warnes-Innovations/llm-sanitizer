# Copyright (C) 2026 Gregory R. Warnes
# SPDX-License-Identifier: AGPL-3.0-or-later

"""URL reader — HTTP content fetch, with SSRF guards and a response size cap.

All external web access in this project routes through :func:`read_url`, so it
is *the* SSRF trust boundary. URLs may originate from untrusted content (a link
inside a scanned email/page), so every hop — the initial URL and each redirect —
is validated to be an ``http(s)`` URL whose host resolves ONLY to public
addresses before any request is made. This blocks fetch/redirect to loopback,
private, link-local, and cloud-metadata (``169.254.169.254``) targets.

Because the URL (and thus the responder) is untrusted, the response body is read
as a bounded stream and aborted once it exceeds :data:`_MAX_RESPONSE_BYTES`, so a
malicious endpoint cannot exhaust memory with an unbounded/huge body.

The body is then classified and, where it is a binary document, EXTRACTED —
:func:`_scannable_text` — so that a PDF or DOCX fetched by URL is scanned as its
text rather than as decoded bytes (issue #53). :func:`read_url` therefore
returns ``str | None``, the same "I cannot read this" contract the file path has
always had; None means refuse the content, never "the page was empty".
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# Guards the process-global getaddrinfo patch in _pin_host_to_ips: because the
# patch is process-wide, two concurrent pins would clobber each other's saved
# original and restore the wrong resolver. Acquired non-blocking so a concurrent
# caller fails LOUDLY (RuntimeError) rather than racing silently. The durable fix
# is a connection-level resolver on the httpx transport (tracked in issue #11).
_pin_lock = threading.Lock()

_ALLOWED_SCHEMES = ("http", "https")
_MAX_REDIRECTS = 5
# Cap on the response body read from an untrusted endpoint (10 MiB). A body
# larger than this is treated as hostile. The cap applies to the raw bytes,
# before any extraction, so it still bounds memory for binary documents.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
# An honest desktop-browser UA (issue #19): a default/absent UA is one of the
# signals managed WAFs (Cloudflare/Akamai) use to reject a fetch outright, and
# masquerading as something other than an HTTP client is not itself an evasion
# — legitimate browsers all send exactly this kind of string.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


class FetchBlockedError(RuntimeError):
    """The remote server actively refused the fetch (HTTP 4xx/5xx) — e.g. a
    WAF block — as opposed to a local failure (SSRF guard, DNS, timeout, size
    cap). Callers need to tell these apart (issue #19): a WAF block means
    "cannot verify this page, route to human review", not "the scan failed"."""

    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        super().__init__(f"HTTP {status_code} fetching {url}")


def _addr_is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local   # 169.254.0.0/16 — cloud metadata service
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _ip_is_blocked(ip: str) -> bool:
    """True if *ip* is a non-public address we must never fetch (loopback,
    private, link-local incl. cloud metadata, reserved, multicast). Unparseable
    → blocked (fail closed).

    Defense-in-depth (committee MED-2): an IPv4-mapped/6to4/Teredo IPv6 address
    embeds an IPv4 address. Older CPython (<3.11.10 / <3.12.4) did NOT reflect
    the embedded IPv4's private/link-local status on the IPv6 wrapper, so
    ``::ffff:169.254.169.254`` could pass. We explicitly unwrap and re-check the
    embedded IPv4 rather than trusting the interpreter's patch level."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if _addr_is_blocked(addr):
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = addr.ipv4_mapped or addr.sixtofour or getattr(addr, "teredo", None)
        # `teredo` returns a (server, client) tuple; check the client address.
        if isinstance(embedded, tuple):
            embedded = embedded[1] if embedded else None
        if embedded is not None and _addr_is_blocked(embedded):
            return True
    return False


def _assert_safe_url(url: str) -> tuple[str, list[str]]:
    """Validate *url* and return ``(host, validated_public_ips)``.

    Raises RuntimeError unless *url* is an http(s) URL whose host resolves ONLY
    to public addresses. Fails closed on any parse/resolution failure. The
    returned IPs are pinned onto the connection by :func:`_pin_host_to_ips` so
    the request goes to exactly what was validated — closing the DNS-rebinding
    TOCTOU where a short-TTL attacker returns a public IP at validation and a
    metadata/loopback IP at connect time (committee M1).
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise RuntimeError(
            f"blocked URL scheme {parsed.scheme!r} (only http/https): {url}"
        )
    host = parsed.hostname
    if not host:
        raise RuntimeError(f"URL has no host: {url}")
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve host {host!r}: {exc}") from exc
    ips = {str(info[4][0]) for info in infos}
    blocked = sorted(ip for ip in ips if _ip_is_blocked(ip))
    if blocked or not ips:
        raise RuntimeError(
            f"blocked SSRF target: {host!r} resolves to non-public address(es) "
            f"{blocked or list(ips)} (loopback/private/link-local/metadata)"
        )
    return host, sorted(ips)


def _addrinfo_for(ip: str, port: int) -> tuple[Any, ...]:
    """Build a getaddrinfo-style tuple for a literal IP (v4 or v6)."""
    try:
        family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    except ValueError:
        family = socket.AF_INET
    sockaddr: tuple[Any, ...] = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


@contextlib.contextmanager
def _pin_host_to_ips(host: str, ips: list[str]) -> Iterator[None]:
    """Temporarily force ``socket.getaddrinfo`` to return ONLY *ips* for *host*,
    so the underlying connection goes to the pre-validated address rather than a
    freshly (and possibly rebinding) re-resolution. TLS SNI and certificate
    verification still use *host*, so HTTPS is unaffected. Other hosts resolve
    normally.

    Caveat: this patches a process-global for the duration of the request; it is
    intended for the scanner's serial URL fetches, not high-concurrency use. A
    concurrent call fails loudly via ``_pin_lock`` rather than racing silently.
    """
    if not _pin_lock.acquire(blocking=False):
        raise RuntimeError(
            "concurrent URL scan detected: _pin_host_to_ips patches a "
            "process-global socket.getaddrinfo and is not safe to nest/run "
            "concurrently. Serialize read_url calls (the durable fix is a "
            "connection-level resolver on the httpx transport)."
        )
    real_getaddrinfo = socket.getaddrinfo

    def pinned(h: object, port: object, *args: object, **kwargs: object) -> list[Any]:
        if h == host:
            p = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else 0
            return [_addrinfo_for(ip, p) for ip in ips]
        return real_getaddrinfo(h, port, *args, **kwargs)  # type: ignore[arg-type]

    socket.getaddrinfo = pinned  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo
        _pin_lock.release()


def _read_body_capped(response: object) -> bytes:
    """Read a streaming httpx response body, aborting past _MAX_RESPONSE_BYTES,
    and return the RAW BYTES. A declared Content-Length over the cap is rejected
    before reading a single byte.

    Reading the body and turning it into text are deliberately separate
    responsibilities. They used to be one function that ended
    ``.decode(encoding, errors="replace")``, and that unconditional decode is
    what made a fetched PDF scannable-looking mojibake (issue #53): with the
    decode baked in here there was no point at which the content could be
    sniffed or extracted, and no way for the reader to say "I cannot read this".

    Do not re-merge the decode into this function. The cap logic below is
    unchanged and is the reason this function exists at all.
    """
    clen = response.headers.get("content-length")  # type: ignore[attr-defined]
    if clen and clen.isdigit() and int(clen) > _MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"response Content-Length {clen} exceeds {_MAX_RESPONSE_BYTES}-byte cap"
        )
    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_bytes():  # type: ignore[attr-defined]
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"response body exceeds {_MAX_RESPONSE_BYTES}-byte cap"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _suffix_from_magic(raw: bytes) -> str:
    """Return a filename suffix (``".pdf"``, ``".docx"``, …) derived ONLY from
    *raw*'s magic bytes, or ``""`` when nothing is recognised.

    **Content decides, and nothing else may.** Not the URL path, not
    Content-Type, not Content-Disposition — all three are attacker-controlled
    when the URL came out of scanned content, and all three are wrong often
    enough by accident. Measured against markitdown, a *wrong* suffix is worse
    than none at all: a PDF written as ``.txt`` came back as 594 bytes of raw
    PDF source, and a DOCX written as ``.txt`` came back as 4 bytes **with the
    injected sentence missing entirely**. A suffix-less file, by contrast,
    extracts correctly — markitdown sniffs.

    So why derive one at all? Because :func:`~llm_sanitizer.readers.
    archive_reader.is_zip_based_document` decides on the file NAME. Without a
    ``.docx`` suffix a fetched DOCX is ZIP magic with no document extension,
    which ``read_scannable_content`` treats as an archive-to-expand and refuses
    — the document would never reach the extractor.

    ``filetype`` supplies the extension, so the value comes from a fixed
    library-controlled vocabulary rather than from the response. The
    alphanumeric guard is belt-and-braces against that assumption changing:
    this string becomes part of a filesystem path.
    """
    try:
        import filetype
    except ImportError:
        # Core dep missing → no suffix. Same graceful degradation as the
        # integrity checks; markitdown still sniffs for the formats it handles.
        return ""
    try:
        kind = filetype.guess(raw)
    except (TypeError, ValueError):
        return ""
    if kind is None:
        return ""
    ext = str(kind.extension)
    if not ext.isalnum():
        return ""
    return f".{ext}"


def _scannable_text(raw: bytes, encoding: str) -> str | None:
    """Turn a fetched response body into text that is worth scanning, or None.

    This is the URL path's half of the symmetry issue #53 is about: the file
    path sniffs, extracts, and returns None when it cannot, and until now the
    URL path did none of the three.

    The decision is DELEGATED, never re-implemented. ``is_binary_content`` is
    the one binary/text classifier (a second copy of that rule is exactly what
    commit 1b66094 had to merge back together), ``sniff_rtf`` is the one RTF
    check, and ``read_scannable_content`` is the one extraction path. The
    branch order here mirrors ``read_scannable_content``'s own — markup, then
    binary, then text — because anything else would decide the same question
    two different ways.

    Genuine text keeps the old behaviour exactly, decoded with the charset the
    response declared. That matters: routing text through a temp file and
    ``read_text(encoding="utf-8")`` instead would silently mangle every page
    served as iso-8859-1.

    An extraction that yields nothing is a REFUSAL, not empty content. That is
    the precise hazard in issue #53 — "zero findings on a document whose text
    was never read" — and it matches the scanner's own default
    ``unprocessable_binary_policy="fail"``. An empty *text* body is still just
    empty text; only the extraction branch refuses.
    """
    import tempfile

    from llm_sanitizer.readers.integrity_checks import is_binary_content
    from llm_sanitizer.readers.markup_reader import sniff_rtf
    from llm_sanitizer.scanner import read_scannable_content

    if not raw:
        return ""

    with tempfile.TemporaryDirectory(prefix="llm-sanitizer-url-") as tmpdir:
        # A fixed basename plus a magic-derived suffix. Nothing from the URL or
        # the response headers reaches the filesystem, so a hostile
        # Content-Disposition cannot steer where this lands. tempfile creates
        # the directory 0700 and removes it (and the body) on the way out.
        path = Path(tmpdir) / f"body{_suffix_from_magic(raw)}"
        path.write_bytes(raw)

        if not sniff_rtf(raw) and not is_binary_content(path):
            return raw.decode(encoding, errors="replace")

        text = read_scannable_content(path, binary_mode="extract")
        if text is None or not text.strip():
            return None
        return text


def read_url(url: str) -> str | None:
    """Fetch a URL via HTTP and return scannable text, or None to refuse it.

    For HTML pages, returns the raw HTML so hidden-content rules can detect
    CSS-hidden elements and comment directives.

    For a **binary document** (PDF, DOCX, …) the text is EXTRACTED, exactly as
    ``read_file`` does for a local file — see :func:`_scannable_text`. Returning
    None means "there is no usable text here": callers must refuse the content
    rather than treat it as clean. This mirrors
    ``scanner.read_scannable_content``, whose None the file path has always had.

    **This return type is load-bearing.** Before issue #53 this function
    returned ``str`` unconditionally, so a fetched PDF was handed to the rule
    engine as decoded bytes — one measured sample produced 11 CRITICAL findings
    matched against a *font width array*, and a PDF with uncompressed streams
    and no such array produced a clean report on text nobody had read. Do not
    reintroduce a plain ``str`` return by substituting ``""`` for None: an empty
    string scans clean, which is the failure this closes.

    Redirects are followed MANUALLY (``follow_redirects=False``) so the target
    of each hop is re-validated by :func:`_assert_safe_url` — a benign-looking
    URL that 302-redirects to ``169.254.169.254`` is therefore blocked. The
    response body is bounded to :data:`_MAX_RESPONSE_BYTES`. Neither guard is
    affected by the extraction step, which happens after the body is fully read
    and capped.

    Raises:
        FetchBlockedError: If the remote server refused the request (HTTP
            4xx/5xx) — distinct from other failures because it means the
            content could not be verified, not that scanning itself failed.
        RuntimeError: If the SSRF guard blocks a hop, DNS resolution fails,
            a redirect loop occurs, or the response body exceeds the size cap.
            Also covers ExtractorUnavailableError (a RuntimeError subclass),
            which propagates deliberately: a missing extractor is a systemic
            coverage gap and fails fast rather than degrading to a raw decode.
    """
    import httpx

    current = url
    try:
        with httpx.Client(
            follow_redirects=False, timeout=30.0, headers={"User-Agent": _USER_AGENT}
        ) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                host, ips = _assert_safe_url(current)
                # Pin the connection to the just-validated IP(s) so httpx cannot
                # re-resolve the host to a different (metadata/loopback) address
                # at connect time (M1 DNS-rebinding TOCTOU).
                with _pin_host_to_ips(host, ips), client.stream(
                    "GET", current
                ) as response:
                    if response.is_redirect:
                        loc = response.headers.get("location")
                        if not loc:
                            break
                        current = urljoin(current, loc)
                        continue
                    response.raise_for_status()
                    raw = _read_body_capped(response)
                    encoding = response.encoding or "utf-8"
                # Extraction runs OUTSIDE the pin and the open stream, and must
                # stay there. _pin_host_to_ips patches a PROCESS-GLOBAL
                # socket.getaddrinfo and holds a non-reentrant lock; extraction
                # is markitdown, which can take seconds. Calling it inside would
                # leave every other thread's DNS rewritten, and every concurrent
                # read_url failing loudly, for the length of a document parse
                # rather than the length of a fetch.
                return _scannable_text(raw, encoding)
        raise RuntimeError(f"too many redirects fetching {url}")
    except httpx.HTTPStatusError as exc:
        raise FetchBlockedError(exc.response.status_code, url) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Request error fetching {url}: {exc}") from exc

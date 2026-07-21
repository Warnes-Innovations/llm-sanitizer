# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
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
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

_ALLOWED_SCHEMES = ("http", "https")
_MAX_REDIRECTS = 5
# Cap on the response body read from an untrusted endpoint (10 MiB). Scanned
# documents are text/markup; a body larger than this is treated as hostile.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def _ip_is_blocked(ip: str) -> bool:
    """True if *ip* is a non-public address we must never fetch (loopback,
    private, link-local incl. cloud metadata, reserved, multicast). Unparseable
    → blocked (fail closed)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local   # 169.254.0.0/16 — cloud metadata service
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _assert_safe_url(url: str) -> None:
    """Raise RuntimeError unless *url* is an http(s) URL whose host resolves
    only to public addresses. Fails closed on any parse/resolution failure.

    NOTE: this resolves-then-validates; a determined DNS-rebinding attacker
    could in principle return a different IP at connect time (TOCTOU). Closing
    that fully requires pinning the validated IP for the connection; this guard
    stops the common direct and redirect-based SSRF (metadata/loopback/private)
    which is what the trust boundary was previously missing entirely.
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


def _read_capped(response: object) -> str:
    """Read a streaming httpx response body, aborting past _MAX_RESPONSE_BYTES,
    and decode it to text. A declared Content-Length over the cap is rejected
    before reading a single byte."""
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
    encoding = response.encoding or "utf-8"  # type: ignore[attr-defined]
    return b"".join(chunks).decode(encoding, errors="replace")


def read_url(url: str) -> str:
    """Fetch a URL via HTTP and return its content as text.

    For HTML pages, returns the raw HTML so hidden-content rules can detect
    CSS-hidden elements and comment directives.

    Redirects are followed MANUALLY (``follow_redirects=False``) so the target
    of each hop is re-validated by :func:`_assert_safe_url` — a benign-looking
    URL that 302-redirects to ``169.254.169.254`` is therefore blocked. The
    response body is bounded to :data:`_MAX_RESPONSE_BYTES`.

    Raises:
        RuntimeError: If the HTTP request fails, an SSRF guard blocks a hop, or
            the response body exceeds the size cap.
    """
    import httpx

    current = url
    try:
        with httpx.Client(follow_redirects=False, timeout=30.0) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                _assert_safe_url(current)
                with client.stream("GET", current) as response:
                    if response.is_redirect:
                        loc = response.headers.get("location")
                        if not loc:
                            break
                        current = urljoin(current, loc)
                        continue
                    response.raise_for_status()
                    return _read_capped(response)
        raise RuntimeError(f"too many redirects fetching {url}")
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"HTTP {exc.response.status_code} fetching {url}"
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Request error fetching {url}: {exc}") from exc

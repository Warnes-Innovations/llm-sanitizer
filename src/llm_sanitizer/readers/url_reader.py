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

import contextlib
import ipaddress
import socket
from collections.abc import Iterator
from typing import Any
from urllib.parse import urljoin, urlparse

_ALLOWED_SCHEMES = ("http", "https")
_MAX_REDIRECTS = 5
# Cap on the response body read from an untrusted endpoint (10 MiB). Scanned
# documents are text/markup; a body larger than this is treated as hostile.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


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
    intended for the scanner's serial URL fetches, not high-concurrency use.
    """
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
                    return _read_capped(response)
        raise RuntimeError(f"too many redirects fetching {url}")
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"HTTP {exc.response.status_code} fetching {url}"
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Request error fetching {url}: {exc}") from exc

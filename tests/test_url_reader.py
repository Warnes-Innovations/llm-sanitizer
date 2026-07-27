# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the URL reader's SSRF guards and response size cap.

Network-free: DNS resolution is monkeypatched and the streaming body is faked,
so these exercise the security logic deterministically.
"""

from __future__ import annotations

import socket

import pytest

from llm_sanitizer.readers import url_reader
from llm_sanitizer.readers.url_reader import (
    _assert_safe_url,
    _ip_is_blocked,
    _read_capped,
    read_url,
)


class _FakeResponse:
    """Minimal stand-in for a streaming httpx response."""

    def __init__(
        self,
        chunks: list[bytes],
        headers: dict[str, str] | None = None,
        encoding: str = "utf-8",
    ) -> None:
        self._chunks = chunks
        self.headers = headers or {}
        self.encoding = encoding

    def iter_bytes(self):  # noqa: ANN201 - test stub
        yield from self._chunks


class TestIpIsBlocked:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",        # loopback
            "::1",              # loopback v6
            "10.0.0.5",         # private
            "192.168.1.1",      # private
            "169.254.169.254",  # link-local / cloud metadata
            "0.0.0.0",          # unspecified
            "not-an-ip",        # unparseable -> fail closed
        ],
    )
    def test_blocks_non_public(self, ip: str) -> None:
        assert _ip_is_blocked(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_allows_public(self, ip: str) -> None:
        assert _ip_is_blocked(ip) is False


class TestAssertSafeUrl:
    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(RuntimeError, match="scheme"):
            _assert_safe_url("file:///etc/passwd")
        with pytest.raises(RuntimeError, match="scheme"):
            _assert_safe_url("ftp://example.com/x")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(RuntimeError, match="no host"):
            _assert_safe_url("http:///nohost")

    def test_blocks_when_host_resolves_to_metadata(self, monkeypatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [(None, None, None, "", ("169.254.169.254", 80))],
        )
        with pytest.raises(RuntimeError, match="SSRF"):
            _assert_safe_url("http://evil.example/")

    def test_allows_public_resolution(self, monkeypatch) -> None:
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **k: [(None, None, None, "", ("93.184.216.34", 80))],
        )
        # Should not raise.
        _assert_safe_url("http://example.com/")


class TestReadCapped:
    def test_reads_small_body(self) -> None:
        resp = _FakeResponse([b"hello ", b"world"])
        assert _read_capped(resp) == "hello world"

    def test_rejects_declared_content_length_over_cap(self) -> None:
        huge = str(url_reader._MAX_RESPONSE_BYTES + 1)
        resp = _FakeResponse([b"x"], headers={"content-length": huge})
        with pytest.raises(RuntimeError, match="Content-Length"):
            _read_capped(resp)

    def test_aborts_when_streamed_body_exceeds_cap(self, monkeypatch) -> None:
        monkeypatch.setattr(url_reader, "_MAX_RESPONSE_BYTES", 8)
        resp = _FakeResponse([b"1234", b"5678", b"9abc"])  # 12 bytes > 8
        with pytest.raises(RuntimeError, match="exceeds"):
            _read_capped(resp)


def test_read_url_blocks_before_request(monkeypatch) -> None:
    """A blocked scheme must raise without any network call."""
    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("no request should be made for a blocked URL")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(RuntimeError, match="scheme"):
        read_url("file:///etc/passwd")


class TestDnsRebindingPin:
    """M1: the validated IP is pinned to the connection so httpx cannot
    re-resolve the host to a different (metadata/loopback) address at connect
    time (DNS-rebinding TOCTOU)."""

    def test_pin_restricts_and_restores(self) -> None:
        from llm_sanitizer.readers.url_reader import _pin_host_to_ips

        real = socket.getaddrinfo
        with _pin_host_to_ips("target.example", ["203.0.113.7"]):
            infos = socket.getaddrinfo("target.example", 443)
            assert {i[4][0] for i in infos} == {"203.0.113.7"}
        # restored after the context
        assert socket.getaddrinfo is real

    def test_pin_passes_other_hosts_through(self) -> None:
        from llm_sanitizer.readers.url_reader import _pin_host_to_ips

        called = {}

        def fake(host, port, *a, **k):
            called["host"] = host
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.2.3.4", port))]

        orig = socket.getaddrinfo
        socket.getaddrinfo = fake
        try:
            with _pin_host_to_ips("pinned.example", ["203.0.113.7"]):
                socket.getaddrinfo("other.example", 80)
            assert called["host"] == "other.example"
        finally:
            socket.getaddrinfo = orig


class TestIpv4MappedIpv6:
    """MED-2: IPv4-mapped / 6to4 / Teredo IPv6 addresses embedding a private or
    link-local IPv4 must be blocked regardless of the interpreter's patch level
    (older CPython did not reflect the embedded IPv4's status)."""

    def test_mapped_metadata_and_loopback_blocked(self) -> None:
        from llm_sanitizer.readers.url_reader import _ip_is_blocked

        assert _ip_is_blocked("::ffff:169.254.169.254")
        assert _ip_is_blocked("::ffff:127.0.0.1")
        assert _ip_is_blocked("::ffff:10.0.0.5")

    def test_public_mapped_allowed(self) -> None:
        from llm_sanitizer.readers.url_reader import _ip_is_blocked

        assert not _ip_is_blocked("::ffff:93.184.216.34")  # example.com (public)


class TestPinConcurrencyGuard:
    """The process-global getaddrinfo pin must fail LOUDLY on concurrent/nested
    entry rather than clobber another pin's saved resolver and race silently."""

    def test_nested_or_concurrent_pin_raises_and_releases(self) -> None:
        from llm_sanitizer.readers.url_reader import _pin_host_to_ips

        with _pin_host_to_ips("a.example", ["203.0.113.1"]):
            with pytest.raises(RuntimeError, match="concurrent"):
                with _pin_host_to_ips("b.example", ["203.0.113.2"]):
                    pass
        # After the outer context exits, the guard lock is released — a fresh
        # pin succeeds (no leaked lock).
        with _pin_host_to_ips("c.example", ["203.0.113.3"]):
            import socket

            assert {i[4][0] for i in socket.getaddrinfo("c.example", 443)} == {
                "203.0.113.3"
            }

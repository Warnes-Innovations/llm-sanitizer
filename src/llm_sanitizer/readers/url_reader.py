# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""URL reader — HTTP content fetch and HTML text extraction."""

from __future__ import annotations

import re


def _extract_text_from_html(html: str) -> str:
    """Simple HTML text extraction: remove tags, decode entities."""
    # Remove script/style blocks
    html = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML comments
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
    # Keep the raw HTML alongside extracted text so hidden-content rules can fire
    # Return the full HTML — scanners need to see CSS styles, hidden elements, etc.
    return html


def read_url(url: str) -> str:
    """Fetch a URL via HTTP and return its content as text.

    For HTML pages, returns the raw HTML so hidden-content rules can detect
    CSS-hidden elements and comment directives.

    Args:
        url: The URL to fetch.

    Raises:
        RuntimeError: If the HTTP request fails.
    """
    import httpx

    try:
        with httpx.Client(follow_redirects=True, timeout=30.0) as client:
            response = client.get(url)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"HTTP {exc.response.status_code} fetching {url}"
        ) from exc
    except httpx.RequestError as exc:
        raise RuntimeError(f"Request error fetching {url}: {exc}") from exc

    content_type = response.headers.get("content-type", "")
    text = response.text

    if "html" in content_type:
        # Return raw HTML (not stripped) — hidden-content scanner needs it
        return text

    return text

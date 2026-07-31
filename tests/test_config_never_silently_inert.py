# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A config file that exists must never be silently ignored.

THE FAIL-OPEN, verified on v0.5.1 before being fixed:

    pyproject.toml declared no `pyyaml`, and `config.py` read

        if not _YAML_AVAILABLE:
            # PyYAML not installed — return defaults silently
            return SanitizerConfig()

    reached only AFTER establishing that a config file exists.

In the environment consumers actually use — `uvx --from git+...@v0.5.1`, which is
exactly what bastion's INV-7 wiring creates — `import yaml` fails. So every
`.llm-sanitizer.yml` in that deployment was inert, while `list_rules` documented itself
as reporting "what actually runs". An operator who disabled a rule saw it disabled in
their config and enabled in reality; one who tightened `sensitivity` got the default.

The LATENT half is worse than the live half. Because the failure was silent, pyyaml
arriving transitively would have made every checked-in `enabled: false` become live AT
ONCE, with no event marking the change. Failing closed means that transition can only
ever run from "loud error" to "working" — never from "silently ignored" to "suddenly
enforcing something different".

Same family as the `mcp>=1.0` and `py7zr>=0.20` incidents: an undeclared or unbounded
dependency whose absence the code absorbed instead of reporting.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llm_sanitizer import config as config_mod
from llm_sanitizer.config import ConfigError, load_config

CONFIG = "sensitivity: high\nrules:\n  prompt_injection:\n    enabled: false\n"


def test_pyyaml_is_actually_installed() -> None:
    """The declaration is the real fix; everything below is the backstop.

    If this fails, the dependency was dropped from pyproject.toml and the guard tests
    are passing against a hazard that has quietly returned.
    """
    assert config_mod._YAML_AVAILABLE, "pyyaml must be a declared, installed dependency"


def test_an_existing_config_is_honoured(tmp_path: Path) -> None:
    """NEGATIVE CONTROL, first. Without it, the raise below is satisfied by a
    `load_config` that refuses everything, which would look identical in a green run."""
    cfg = tmp_path / ".llm-sanitizer.yml"
    cfg.write_text(CONFIG, encoding="utf-8")

    loaded = load_config(cfg)

    assert loaded.sensitivity == "high"


def test_a_present_config_with_no_yaml_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE REGRESSION. Previously returned defaults and said nothing."""
    cfg = tmp_path / ".llm-sanitizer.yml"
    cfg.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(config_mod, "_YAML_AVAILABLE", False)

    with pytest.raises(ConfigError):
        load_config(cfg)


def test_the_error_says_what_to_do_about_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two remedies, and they are not equivalent — installing PyYAML applies the policy;
    deleting the file accepts the defaults deliberately. An operator must be able to tell
    which one they are choosing."""
    cfg = tmp_path / ".llm-sanitizer.yml"
    cfg.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(config_mod, "_YAML_AVAILABLE", False)

    with pytest.raises(ConfigError) as excinfo:
        load_config(cfg)

    message = str(excinfo.value)
    assert "PyYAML" in message
    assert "remove the config file" in message


def test_no_config_and_no_yaml_is_still_fine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE BOUNDARY, and it is what keeps the fix from being a breaking change.

    Nothing was promised, so nothing is broken: a deployment with no config file keeps
    working with defaults whether or not yaml is importable. Only "there IS a policy and
    we cannot apply it" is an error.
    """
    monkeypatch.setattr(config_mod, "_YAML_AVAILABLE", False)
    monkeypatch.chdir(tmp_path)

    assert load_config().sensitivity == "medium"

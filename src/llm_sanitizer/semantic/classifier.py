# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Pure-Python inference for the semantic-intent classifier.

Loads the vendored sparse logistic-regression weights (``model.json``, produced
by ``scripts/train_semantic_intent.py``) and scores text with stdlib only — no
numpy, no sklearn, no model download. The featurizer is shared with training
(:mod:`llm_sanitizer.semantic.features`).

A prediction carries the fired flag, the probability, and the top contributing
features, so the detection rule can produce an *interpretable* explanation
(which n-grams drove the score) — one of approach A's advantages over an opaque
embedding model.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from llm_sanitizer.semantic.features import INTENT_FEATURES, featurize

_MODEL_PATH = Path(__file__).with_name("model.json")

# Current model-file schema version. Bumped if the on-disk format changes so an
# inference/artifact mismatch fails loudly rather than scoring on garbage.
_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class _Model:
    intercept: float
    threshold: float
    weights: dict[str, float]


@dataclass(frozen=True)
class Prediction:
    """Result of scoring one text span."""

    fired: bool
    probability: float
    # (feature, weight) pairs that pushed the score up most — for the finding
    # explanation. Empty when the span is clean or the model is unavailable.
    top_features: list[tuple[str, float]] = field(default_factory=list)
    # Structural intent features present in the span (see features.INTENT_FEATURES).
    # The detection rule requires ≥1 as a precision gate: probability alone is a
    # fuzzy n-gram signal that can trip on ordinary prose, so a span must ALSO
    # exhibit a recognized injection structure to be reported.
    intent_features: list[str] = field(default_factory=list)


@lru_cache(maxsize=1)
def _load_model() -> _Model | None:
    """Load and cache the vendored model. Returns None (fail closed to a no-op)
    if the artifact is missing or malformed — a broken/absent model must degrade
    to "this rule contributes nothing", never crash the whole scan."""
    try:
        raw = json.loads(_MODEL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(raw, dict) or raw.get("version") != _SCHEMA_VERSION:
        return None
    try:
        weights = {str(k): float(v) for k, v in raw["weights"].items()}
        return _Model(
            intercept=float(raw["intercept"]),
            threshold=float(raw["threshold"]),
            weights=weights,
        )
    except (KeyError, TypeError, ValueError):
        return None


def model_available() -> bool:
    """True if the vendored classifier loaded successfully."""
    return _load_model() is not None


def _sigmoid(x: float) -> float:
    # Numerically stable; avoids overflow warnings for large |x|.
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def predict(text: str) -> Prediction:
    """Score *text*; return a :class:`Prediction`. A no-op (fired=False,
    probability=0) when the model is unavailable."""
    model = _load_model()
    if model is None:
        return Prediction(fired=False, probability=0.0)

    feats = featurize(text)
    contributions: list[tuple[str, float]] = []
    score = model.intercept
    for f in feats:
        w = model.weights.get(f)
        if w is not None:
            score += w
            if w > 0:
                contributions.append((f, w))

    prob = _sigmoid(score)
    intent = sorted(feats & INTENT_FEATURES)
    contributions.sort(key=lambda kv: kv[1], reverse=True)
    # Gate: BOTH the probability threshold AND a structural intent feature must
    # be present (defense-in-depth precision gate — see Prediction.intent_features).
    return Prediction(
        fired=prob >= model.threshold and bool(intent),
        probability=prob,
        top_features=contributions[:5],
        intent_features=intent,
    )

#!/usr/bin/env python3
# Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Train the semantic-intent classifier and emit the vendored ``model.json``.

Approach A (see ``llm_sanitizer.semantic``): a **pure-Python** logistic-regression
classifier over word + char n-grams. Deterministic full-batch gradient descent,
**zero third-party dependencies** (no numpy/sklearn) — so the vendored artifact
is reproducible anywhere Python runs and the runtime install stays dependency-
light.

Usage::

    python scripts/train_semantic_intent.py            # train + write model.json
    python scripts/train_semantic_intent.py --dry-run  # report metrics only

The training corpus is :mod:`llm_sanitizer.semantic.corpus`; the featurizer is
:mod:`llm_sanitizer.semantic.features` (shared with inference — they MUST match).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as a plain script (python scripts/train_semantic_intent.py).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from llm_sanitizer.semantic.corpus import (  # noqa: E402
    labeled_examples,
    load_external_examples,
)
from llm_sanitizer.semantic.features import INTENT_FEATURES, featurize  # noqa: E402

# --- Hyperparameters (tuned for precision-first on this corpus) ------------- #
_EPOCHS = 400
_LR = 0.5
_L2 = 0.002          # ridge penalty — keeps weights small, aids generalization
_MIN_DF = 2          # drop features seen in <2 docs (noise / overfit control)
_WEIGHT_PRUNE = 0.02  # drop |weight| below this from the vendored model

# The hand-curated corpus encodes specific families we must keep catching (the
# committee gap sentences). The ~5.8k external rows would otherwise dilute it
# ~38:1, so curated examples are replicated this many times during training to
# preserve their signal while the external data adds breadth.
_CURATED_WEIGHT = 20

# Gated firing policy (must match classifier.predict):
#   fire iff  prob >= _THRESHOLD  AND  a structural intent feature is present.
# A probability-only "broad" path (hybrid hi/lo thresholds) was tried when the
# external corpus landed and REJECTED: the linear char-n-gram model scores some
# plainly innocent prose above ANY usable threshold (measured 0.975 on "This is
# a perfectly normal piece of text…"), so probability alone cannot be made safe.
# The gate is what keeps clean documents at zero false positives; broad
# semantic recall without it is approach B's job (GitHub issue #8). The gated
# policy's measured cost is low recall on non-structural external injections —
# an accepted, documented tradeoff.
_THRESHOLD = 0.5
_MODEL_PATH = Path(__file__).resolve().parent.parent / "src" / "llm_sanitizer" / "semantic" / "model.json"


def _sigmoid(x: float) -> float:
    import math
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def _build_vocab(feats_per_doc: list[set[str]], min_df: int) -> set[str]:
    """Features appearing in >= min_df documents."""
    df: dict[str, int] = {}
    for feats in feats_per_doc:
        for f in feats:
            df[f] = df.get(f, 0) + 1
    return {f for f, c in df.items() if c >= min_df}


def _train(
    docs: list[set[str]],
    labels: list[int],
    vocab: set[str],
    *,
    epochs: int = _EPOCHS,
    lr: float = _LR,
    l2: float = _L2,
) -> tuple[float, dict[str, float]]:
    """Deterministic full-batch gradient-descent logistic regression.

    Binary presence features; class-balanced example weights so the (larger)
    negative set does not swamp the positive gradient. Returns (intercept,
    weights)."""
    n_pos = sum(labels) or 1
    n_neg = (len(labels) - sum(labels)) or 1
    # Balance classes: total weight per class equal.
    w_pos = len(labels) / (2.0 * n_pos)
    w_neg = len(labels) / (2.0 * n_neg)
    ex_w = [w_pos if y == 1 else w_neg for y in labels]

    # Restrict each doc's features to the vocabulary once.
    docs_v = [[f for f in feats if f in vocab] for feats in docs]
    weights: dict[str, float] = {f: 0.0 for f in vocab}
    intercept = 0.0
    total_w = sum(ex_w)

    for _ in range(epochs):
        grad_w: dict[str, float] = {f: 0.0 for f in vocab}
        grad_b = 0.0
        for feats, y, ew in zip(docs_v, labels, ex_w):
            score = intercept + sum(weights[f] for f in feats)
            err = (_sigmoid(score) - y) * ew
            grad_b += err
            for f in feats:
                grad_w[f] += err
        # L2 on weights (not intercept); normalize by total example weight.
        intercept -= lr * grad_b / total_w
        for f in vocab:
            weights[f] -= lr * (grad_w[f] / total_w + l2 * weights[f])

    return intercept, weights


def _score(intercept: float, weights: dict[str, float], feats: set[str]) -> float:
    return _sigmoid(intercept + sum(weights.get(f, 0.0) for f in feats))


def _gated_fires(
    feats: set[str], intercept: float, weights: dict[str, float],
    threshold: float = _THRESHOLD,
) -> bool:
    """The runtime firing policy: prob >= threshold AND a structural intent
    feature present. Must match ``classifier.predict`` exactly."""
    p = _score(intercept, weights, feats)
    return p >= threshold and bool(feats & INTENT_FEATURES)


def _metrics(
    docs: list[set[str]], labels: list[int], intercept: float,
    weights: dict[str, float],
) -> dict[str, float]:
    """Precision/recall under the gated firing policy."""
    tp = fp = tn = fn = 0
    for feats, y in zip(docs, labels):
        pred = 1 if _gated_fires(feats, intercept, weights) else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def _heldout_eval(
    curated: list[tuple[str, int]], external: list[tuple[str, int]],
) -> None:
    """Honest held-out estimate under the gated policy. The curated corpus is
    small and encodes families we must keep, so it stays fully in TRAIN
    (replicated ×_CURATED_WEIGHT); a deterministic stratified 20% of the
    EXTERNAL data is held out. Note the gated recall on external injections is
    EXPECTED to be low (most lack a structural feature) — the number to watch
    is precision (FP), which the gate exists to protect. No randomness."""
    ext_test: set[int] = set()
    for cls in (0, 1):
        idxs = [i for i, (_, y) in enumerate(external) if y == cls]
        ext_test |= {i for rank, i in enumerate(idxs) if rank % 5 == 0}
    ext_tr = [external[i] for i in range(len(external)) if i not in ext_test]
    ext_te = [external[i] for i in sorted(ext_test)]

    train_ex = curated * _CURATED_WEIGHT + ext_tr
    docs = [featurize(t) for t, _ in train_ex]
    labels = [y for _, y in train_ex]
    b, w = _train(docs, labels, _build_vocab(docs, _MIN_DF))

    te_docs = [featurize(t) for t, _ in ext_te]
    te_labels = [y for _, y in ext_te]
    m = _metrics(te_docs, te_labels, b, w)
    print(f"held-out eval (gated, {len(ext_te)} external examples): "
          f"precision={m['precision']:.3f} recall={m['recall']:.3f} "
          f"(FP={m['fp']} FN={m['fn']})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="report metrics without writing model.json")
    args = ap.parse_args()

    curated = labeled_examples()
    external = load_external_examples()

    print(f"corpus: curated={len(curated)} (×{_CURATED_WEIGHT}), "
          f"external={len(external)} "
          f"({sum(y for _, y in external)} pos / "
          f"{sum(1 for _, y in external if y == 0)} neg)")

    if external:
        _heldout_eval(curated, external)
    else:
        print("held-out eval: skipped (no external data in data-raw/; "
              "training on curated corpus only)")

    # Final model on the full corpus: curated up-weighted by replication so its
    # families survive the external data's volume, plus all external rows.
    examples = curated * _CURATED_WEIGHT + external
    docs = [featurize(t) for t, _ in examples]
    labels = [y for _, y in examples]
    vocab = _build_vocab(docs, _MIN_DF)
    intercept, weights = _train(docs, labels, vocab)
    weights = {f: round(w, 6) for f, w in weights.items() if abs(w) >= _WEIGHT_PRUNE}
    fit = _metrics(docs, labels, intercept, weights)
    print(f"final fit (full, gated): precision={fit['precision']:.3f} "
          f"recall={fit['recall']:.3f} (FP={fit['fp']}, FN={fit['fn']}) "
          f"features={len(weights)}")

    model = {
        "version": 2,
        "intercept": round(intercept, 6),
        "threshold": _THRESHOLD,
        "weights": dict(sorted(weights.items())),  # sorted → stable diffs
    }
    if args.dry_run:
        print("--dry-run: model.json NOT written")
        return 0

    _MODEL_PATH.write_text(json.dumps(model, indent=1, sort_keys=True) + "\n",
                           encoding="utf-8")
    size = _MODEL_PATH.stat().st_size
    print(f"wrote {_MODEL_PATH.relative_to(Path.cwd()) if _MODEL_PATH.is_relative_to(Path.cwd()) else _MODEL_PATH} "
          f"({size:,} bytes, {len(weights)} features)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

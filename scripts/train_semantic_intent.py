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

from llm_sanitizer.semantic.corpus import labeled_examples  # noqa: E402
from llm_sanitizer.semantic.features import featurize  # noqa: E402

# --- Hyperparameters (tuned for precision-first on this corpus) ------------- #
_EPOCHS = 400
_LR = 0.5
_L2 = 0.002          # ridge penalty — keeps weights small, aids generalization
_MIN_DF = 2          # drop features seen in <2 docs (noise / overfit control)
_WEIGHT_PRUNE = 0.02  # drop |weight| below this from the vendored model
_THRESHOLD = 0.5     # LR decision boundary; validated against the FP corpus
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


def _metrics(
    docs: list[set[str]], labels: list[int], intercept: float,
    weights: dict[str, float], threshold: float,
) -> dict[str, float]:
    tp = fp = tn = fn = 0
    for feats, y in zip(docs, labels):
        pred = 1 if _score(intercept, weights, feats) >= threshold else 0
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


def _cross_validate(
    docs: list[set[str]], labels: list[int], k: int = 5,
) -> dict[str, float]:
    """Deterministic stratified k-fold CV for an HONEST precision/recall estimate
    (train metrics alone would be optimistic). Folds are assigned round-robin
    within each class, so no randomness — reproducible."""
    pos_idx = [i for i, y in enumerate(labels) if y == 1]
    neg_idx = [i for i, y in enumerate(labels) if y == 0]
    fold_of = {}
    for rank, i in enumerate(pos_idx):
        fold_of[i] = rank % k
    for rank, i in enumerate(neg_idx):
        fold_of[i] = rank % k

    agg = {"precision": 0.0, "recall": 0.0, "f1": 0.0, "fp": 0, "fn": 0}
    for fold in range(k):
        tr = [i for i in range(len(labels)) if fold_of[i] != fold]
        te = [i for i in range(len(labels)) if fold_of[i] == fold]
        tr_docs = [docs[i] for i in tr]
        tr_labels = [labels[i] for i in tr]
        vocab = _build_vocab(tr_docs, _MIN_DF)
        b, w = _train(tr_docs, tr_labels, vocab)
        m = _metrics([docs[i] for i in te], [labels[i] for i in te], b, w, _THRESHOLD)
        for key in ("precision", "recall", "f1"):
            agg[key] += m[key] / k
        agg["fp"] += m["fp"]
        agg["fn"] += m["fn"]
    return agg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true",
                    help="report metrics without writing model.json")
    args = ap.parse_args()

    examples = labeled_examples()
    texts = [t for t, _ in examples]
    labels = [y for _, y in examples]
    docs = [featurize(t) for t in texts]

    print(f"corpus: {len(labels)} examples "
          f"({sum(labels)} positive / {len(labels) - sum(labels)} negative)")

    cv = _cross_validate(docs, labels)
    print(f"5-fold CV (honest):  precision={cv['precision']:.3f}  "
          f"recall={cv['recall']:.3f}  f1={cv['f1']:.3f}  "
          f"(FP={cv['fp']}, FN={cv['fn']})")

    # Final model on the full corpus.
    vocab = _build_vocab(docs, _MIN_DF)
    intercept, weights = _train(docs, labels, vocab)
    weights = {f: round(w, 6) for f, w in weights.items() if abs(w) >= _WEIGHT_PRUNE}
    fit = _metrics(docs, labels, intercept, weights, _THRESHOLD)
    print(f"final fit (full):    precision={fit['precision']:.3f}  "
          f"recall={fit['recall']:.3f}  (FP={fit['fp']}, FN={fit['fn']})  "
          f"features={len(weights)}")

    model = {
        "version": 1,
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

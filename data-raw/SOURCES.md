<!--
Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Training-data sources & attribution

The `semantic_intent` detector's classifier (`src/llm_sanitizer/semantic/model.json`)
is trained on a combination of:

1. the **hand-curated corpus** committed in
   `src/llm_sanitizer/semantic/corpus.py` (authored for this project), and
2. optional **third-party labeled datasets** listed below, loaded from this
   `data-raw/` directory at **train time only**.

Third-party datasets are **not redistributed** by this project: the raw data
files are git-ignored (see `.gitignore`), and only the *trained weights*
(`model.json`) ship in the package. This file records provenance and honors the
datasets' attribution terms.

## Datasets

### prodnull/prompt-injection-repo-dataset  *(primary — domain-matched)*

- **URL:** <https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset>
- **License:** Apache-2.0
- **Pinned revision:** `6c56b897ee4a328fb4f41f4b0d334f5d2db4482a`
- **Size / schema:** 5,671 examples (`text`, `label`; 1 = injection, 0 = benign);
  2,916 malicious / 2,755 benign. Covers repository artifacts — source code,
  configs, READMEs, CI/CD workflows, build scripts — with domain-appropriate
  *hard negatives* (security docs describing attacks, deploy scripts, code-review
  comments). This is why it is the primary source: it matches llm-sanitizer's
  threat model (injection embedded in scanned content), not chat-prompt jailbreaks.
- **Access:** gated (auto-approve). Requires a **free** Hugging Face account and
  accepting the dataset terms once; no paid tier needed. See `README.md` here.

### deepset/prompt-injections  *(optional — positives-only augmentation)*

- **URL:** <https://huggingface.co/datasets/deepset/prompt-injections>
- **License:** Apache-2.0
- **Pinned revision:** `4f61ecb038e9c3fb77e21034b22511b523772cdd`
- **Size / schema:** 662 rows (`text`, `label`). English (German-influenced).
- **Use note:** its **negatives are chat user-queries** (restaurant/travel/book
  questions), a different distribution from what we scan, so only its
  **positives** are used as phrasing augmentation — its benign side is discarded
  to avoid skewing precision.

## Contamination / evaluation hygiene

- The two committee gap sentences and any external **benchmark** (e.g.
  PromptShield) are kept **out of training** so generalization is measured
  honestly.
- Revisions are pinned above; the scheduled workflow
  `.github/workflows/dataset-monitor.yml` watches these SHAs and opens an issue
  when a source updates (see issue #9).

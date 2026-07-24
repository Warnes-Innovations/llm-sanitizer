<!--
Copyright (C) 2026 Gregory R. Warnes / Warnes Innovations LLC
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `data-raw/` — training data (not redistributed)

Third-party labeled datasets used to **train** the `semantic_intent` classifier
live here at build time. The raw data files are **git-ignored** — this project
ships only the trained weights (`src/llm_sanitizer/semantic/model.json`), never
the datasets themselves. See [`SOURCES.md`](SOURCES.md) for provenance,
licenses, and attribution, and [`pinned-revisions.json`](pinned-revisions.json)
for the exact revisions the current model was trained against.

Tracked files in this directory: `README.md`, `SOURCES.md`,
`fetch_datasets.py`, `pinned-revisions.json`. Everything else (the `.jsonl` /
`.parquet` data) is ignored.

## Fetching the data

The **primary** dataset, `prodnull/prompt-injection-repo-dataset`, is **gated**
(free, but requires a Hugging Face account that has accepted the dataset terms):

1. Create a free Hugging Face account (no paid tier needed).
2. Visit <https://huggingface.co/datasets/prodnull/prompt-injection-repo-dataset>
   while logged in and click **"Agree and access repository"** (this is the
   one-time gate acceptance; a bare API token is not sufficient without it).
3. Create a **read-scope** access token at
   <https://huggingface.co/settings/tokens>.
4. Provide the token to the fetch step **without committing or printing it** —
   e.g. export it in your shell:

   ```bash
   export HF_TOKEN=...        # read-scope token; never commit this
   python data-raw/fetch_datasets.py
   ```

   (Alternatively, download `train.jsonl` from the dataset page yourself and
   save it as `data-raw/prompt-injection-repo-dataset.train.jsonl` — then no
   token is shared at all.)

`deepset/prompt-injections` is public (no token needed) and is fetched as an
optional positives-only augmentation.

## Security

- **Never commit or print `HF_TOKEN`.** It is a credential; keep it in the
  environment only. The fetch helper reads it from `os.environ` and never logs it.
- The downloaded data is untrusted third-party content (it contains real
  injection payloads by design). It is used only as classifier training input,
  never executed.

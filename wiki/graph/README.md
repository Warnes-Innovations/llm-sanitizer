# Wiki Graph Layer

This directory holds the compiled knowledge graph derived from the markdown
wiki. **Markdown is canonical.** Everything here can be deleted and rebuilt
without losing knowledge.

## Precondition: the graph tooling ships with the `llm-wiki` plugin, NOT this repo

> **`wiki_graph_extract.py`, `wiki_graph_lint.py` and `wiki_graph_query.py` are
> not files in this repository.** They belong to the external `llm-wiki`
> plugin/skill. The `scripts/` directory here contains unrelated project
> scripts (`check_dataset_revisions.py`, `install-deps.sh`,
> `train_semantic_intent.py`), so the bare `scripts/…` paths this document used
> to show would resolve, wrongly, against that directory.
>
> **If the `llm-wiki` plugin is not installed, skip this entire document.** The
> graph layer is optional; the markdown wiki is fully usable without it, and
> nothing in the build, tests, or release depends on it.
>
> **The precondition is "is the `wiki:graph` skill available to me?", and only
> the agent's own skill list answers it.** There is no command in this
> repository that can answer it — `ls scripts/` merely re-confirms the tools are
> not here (which this section already states) and would succeed either way, so
> do not mistake it for a gate. If the skill is not listed, stop; nothing below
> is runnable.
>
> Below, `<llm-wiki>` stands for the plugin's own script directory, wherever the
> plugin is installed on the machine. Prefer invoking the `wiki:graph` skill,
> which resolves the paths itself, over typing them by hand.

## Files

| File | Purpose | Tracking |
|------|---------|----------|
| `ontology.yaml` | Declares node types and predicates the graph recognises. The contract the plugin's `wiki_graph_lint.py` validates against. | **Tracked. Edit by hand.** |
| `nodes.jsonl` | One JSON object per node, sorted by id. | Generated. Track if you want graph diffs in PRs; otherwise gitignore. |
| `edges.jsonl` | One JSON object per edge, sorted by id. Includes typed semantic edges, `mentions`, `sourced_from`, and `summarizes_raw`. | Generated. Same trade-off as `nodes.jsonl`. |
| `graph.sqlite` | Queryable index used by the plugin's `wiki_graph_query.py`. Schema: `nodes`, `aliases`, `edges`. | Generated. **Gitignored** — rebuild on demand. |
| `graph.graphml` | GraphML export for tools like Gephi or yEd. | Generated. Gitignored by default. |

## Workflow

1. Author or edit a wiki page. Add typed `graph.relationships` only when an explicit source supports them.
2. Run `python <llm-wiki>/wiki_graph_lint.py wiki/` — catches unknown predicates, broken object references, missing evidence, alias collisions.
3. Run `python <llm-wiki>/wiki_graph_extract.py wiki/ --out wiki/graph` — regenerates the artifacts above.
4. Query with `python <llm-wiki>/wiki_graph_query.py wiki/ neighbors --node product:example-widget` (or `edges`, `path`, `facts`).

(Or invoke the `wiki:graph` skill, which runs the same three operations without
requiring you to resolve `<llm-wiki>` yourself.)

## Anti-patterns

- **Hand-editing `nodes.jsonl` / `edges.jsonl` / `graph.sqlite`.** Edit the markdown; regenerate.
- **Treating graph rows as evidence.** They accelerate navigation. For high-stakes claims, follow the edge's `source` and `evidence` fields back to the wiki page and the raw source.
- **Adding typed edges the source doesn't support.** Use a normal `[[wikilink]]` instead — the `mentions` edge captures the connection without overclaiming.

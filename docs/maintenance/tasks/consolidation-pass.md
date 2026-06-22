# Consolidation pass

**Cadence:** monthly **Time budget:** 90 min **Trigger mode:** manual (schedulable)

## Why this matters

This codebase is largely AI-generated. AI assistants generate one function at a time without reading the rest of the tree, so they accrete two kinds of decay that the per-PR gates do not stop:

- Semantic duplication: the same logic re-implemented under a different name. SonarCloud's duplication gate (`new_duplicated_lines_density > 3%`) catches only lexical, token-level copies; renamed-identical logic sails through.
- Cognitive-complexity hotspots: over-built functions, deep nesting, and defensive branches for states no caller can produce.

The new-code gates stop NEW instances: the golangci `lint:go:newcode` run gates cognitive complexity and dead parameters on changed lines, and the Sonar gate caps new lexical duplication. This pass pays down the existing stock those gates grandfather. The decision of what shape to consolidate into is a human one; the mechanical extract-and-replace is the part to delegate.

## Relationship to other tasks (do not duplicate)

- `dead-code-sweep` targets code that is UNUSED. This task targets code that IS used but is duplicated or over-complex.
- `architecture-drift` targets boundary violations. This task is orthogonal: consolidation must respect context boundaries (shared logic moves to `internal/` or `api/`, never sideways between contexts).

## Baseline (recorded when this task was added, 2026-06)

Repo-wide: duplicated lines 1.3%, 33 duplicated blocks across 21 files; aggregate cognitive complexity 5282 over 53k ncloc. Lexical duplication is already low, so the higher-value target is usually the cognitive-complexity hotspots. Use these as the trend baseline and record the new numbers each run in the log.

## Scope

- Duplicated files and blocks (SonarCloud whole-repo measure, not the new-code gate).
- The highest cognitive-complexity files (SonarCloud `cognitive_complexity` per file).
- Semantic duplicates the review bots or a manual grep surface that Sonar's lexical matcher missed.

## Steps

1. Pull the duplication report. Via the SonarQube MCP: `search_duplicated_files` and `get_duplications` for project `getvictor_fleet-edr`. Or the web API:

   ```bash
   curl -s -u "$SONAR_TOKEN:" \
     "https://sonarcloud.io/api/measures/component_tree?component=getvictor_fleet-edr&metricKeys=duplicated_blocks,duplicated_lines_density&qualifiers=FIL&s=metric&metricSort=duplicated_blocks&asc=false&ps=25" | jq .
   ```

2. Pull the cognitive-complexity hotspots:

   ```bash
   curl -s -u "$SONAR_TOKEN:" \
     "https://sonarcloud.io/api/measures/component_tree?component=getvictor_fleet-edr&metricKeys=cognitive_complexity&qualifiers=FIL&s=metric&metricSort=cognitive_complexity&asc=false&ps=25" | jq .
   ```

3. Cluster the top findings into at most a handful of consolidation candidates. For each, confirm the copies are live (grep the call sites, the way `find-prior-art` does) and decide the target shape: which implementation wins, where it lives (owning context, or `internal/` and `api/` if shared), and what the call sites become.

4. Consolidate one candidate per PR. The human decides the target; the extract-and-replace is mechanical. Keep each PR small enough to review in one sitting.

5. Refuse compounded scope. If a candidate is more than a focused session of work (a cross-context redesign, a schema change), file an issue and stop. A 3-day refactor disguised as a sweep is how the sweep gets skipped.

## Output

One focused PR per consolidation candidate (do not bundle unrelated clusters). The PR body records the before metric (the duplicated-block count, or the file's cognitive complexity) so the reviewer can see the reduction.

## Prompt template

```text
Run the consolidation pass defined in docs/maintenance/tasks/consolidation-pass.md.

Step 1: pull the SonarCloud duplication and cognitive-complexity reports for getvictor_fleet-edr
(via the SonarQube MCP search_duplicated_files / get_duplications, and the component_tree measures API
in the task file). List the top duplicated files and the top cognitive-complexity files.

Step 2: for the top few, confirm the copies are live (grep the call sites) and propose a target shape:
which implementation wins, where it lives (owning bounded context, or internal/ and api/ if shared), and
what the call sites become. Respect context boundaries; never consolidate sideways between contexts.

Step 3: implement ONE candidate on a branch as a focused PR. Record the before metric in the PR body.
File an issue for anything bigger than a single session and stop.

Time budget 90 minutes. Skip ambiguous clusters and file an issue instead of guessing the target shape.
```

## Definition of done

- [ ] Sonar duplication and cognitive-complexity reports pulled, and the top findings listed.
- [ ] At least one consolidation PR opened, or an explicit "nothing above threshold this month" finding written down.
- [ ] Oversized candidates filed as issues, not left half-done in the sweep.
- [ ] Dated entry in [`docs/maintenance/log.md`](../log.md) with the current duplication % and aggregate cognitive complexity.

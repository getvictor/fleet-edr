# TODO / FIXME sweep

**Cadence:** monthly **Time budget:** 30 min **Trigger mode:** manual

## Why this matters

TODO / FIXME / XXX / HACK comments accumulate forever if nobody is responsible for them. Each unaddressed TODO is a tiny piece of trust the codebase is asking the next reader to extend ("yes, this will be fixed someday"). At small counts, that trust is fine; at hundreds, it becomes load-bearing on nothing. This repo currently has very few (≤1 at last count); the goal is to keep it that way.

## Scope

All committed source files in `server/`, `agent/`, `internal/`, `ui/`, `extension/`, `test/`, `tools/`, `scripts/`, `schema/`, plus `Taskfile.yml`, `lefthook.yml`, `docker-compose*.yml`, and committed Markdown.

Excludes: `ai/`, `tmp/`, `node_modules/`, vendored dirs, generated code (e.g. anything under `dist/`).

## Steps

1. Find all comments matching `TODO|FIXME|XXX|HACK|DEPRECATED` across the full scope (case-sensitive in code; the patterns below match both line comments `//` and block comments `/* ... */`, accepting some noise from string literals that contain the marker words):

   ```bash
   # Go
   grep -rnE '(\/\/|\/\*).*\b(TODO|FIXME|XXX|HACK|DEPRECATED)\b' server agent internal test tools scripts schema
   # TS
   grep -rnE '(\/\/|\/\*).*\b(TODO|FIXME|XXX|HACK|DEPRECATED)\b' ui/src
   # Swift
   grep -rnE '(\/\/|\/\*).*\b(TODO|FIXME|XXX|HACK|DEPRECATED)\b' extension/edr
   # YAML / Taskfile / docker-compose / committed Markdown (line comments + plain-text)
   grep -rnE '\b(TODO|FIXME|XXX|HACK|DEPRECATED)\b' Taskfile.yml lefthook.yml docker-compose*.yml
   git ls-files '*.md' | xargs grep -nE '\b(TODO|FIXME|XXX|HACK|DEPRECATED)\b'
   ```

2. For each hit, decide:

   | Verdict | Action |
   | --- | --- |
   | **Fix now** (small, in scope, will take < 15 min) | Fix in this PR |
   | **File issue** (real work, but not for this sweep) | Open GitHub issue, replace TODO with `// see #NNN` |
   | **Delete** (the TODO is stale: the thing it warned about no longer applies) | Delete the comment |
   | **Keep** (the TODO is a load-bearing warning to future maintainers) | Rewrite as a regular comment without the TODO marker (the marker should imply pending action; if there's no action, it's just documentation) |

3. Hard rule: at the end of the sweep, no TODO without an issue link should remain. Either it has an `// see #NNN` annotation, or it's been fixed / deleted / rewritten.

## Output

A PR titled `TODO sweep YYYY-MM-DD` when there are findings. Body lists each hit and the verdict applied. Every run appends a dated entry to [`docs/maintenance/log.md`](../log.md) so the cadence is auditable, whether findings landed or not.

## Prompt template

```text
Run the TODO/FIXME sweep defined in docs/maintenance/tasks/todo-fixme-sweep.md.

Find every TODO/FIXME/XXX/HACK/DEPRECATED in committed source (server/, agent/, internal/, ui/src,
extension/edr, test/, tools/, scripts/, schema/, Taskfile.yml, lefthook.yml, docker-compose*.yml,
committed Markdown). Exclude ai/, tmp/, node_modules/, generated dirs.

For each hit, apply the verdict matrix in the task file: Fix now / File issue / Delete / Rewrite as
plain comment. Hard rule: no bare TODO survives the sweep - every remaining one must link to an issue
(`// see #NNN`).

Open one PR. PR body lists every hit with its verdict. Time budget 30 minutes; if there are more than
~20 hits, fix the cheap half and file issues for the rest.
```

## Definition of done

- [ ] Every comment matching the patterns has been triaged.
- [ ] No bare TODO without an issue link remains in the codebase.
- [ ] Dated entry in [`docs/maintenance/log.md`](../log.md).

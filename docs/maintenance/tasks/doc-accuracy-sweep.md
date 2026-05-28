# Doc accuracy sweep

**Cadence:** monthly
**Time budget:** 60-90 min including human review
**Trigger mode:** manual or `/schedule`

## Why this matters

Docs in `docs/`, `README.md`, `CONTRIBUTING.md`, and per-package READMEs reference specific files, functions, ports, env vars, table
names, and CLI commands. Each refactor breaks some of these silently, and each broken reference erodes the doc's credibility (and
makes onboarding harder). Linters won't catch "this function moved", "this port changed", or "this command no longer exists",
because the prose form is unstructured.

## Scope

Every committed Markdown file outside `ai/`, `tmp/`, `node_modules/`, and `.git/`. Read each one and verify:

- File / directory paths still exist (e.g. `server/detection/internal/...`).
- Function / type / table names referenced in code-style backticks still exist (`grep -r` or LSP).
- Commands (`task ...`, `go test ...`, `make ...`) still work or at least still resolve to a target.
- Ports, env vars, DSNs match `Taskfile.yml`, `docker-compose*.yml`, and `internal/config`.
- External URLs return 200 (not just exist; some redirect to login walls).
- "See `<file>`" cross-references actually exist.

## Out of scope

- Tone / wording improvements. This task is mechanical.
- Adding new content. If a doc is missing a section, file an issue and stop.
- Phase / branch references - those go to the [`stale-implementation-references`](stale-implementation-references.md) sweep.

## Steps

1. List all markdown files in scope: `git ls-files '*.md' | grep -v ai/ | grep -v tmp/`.
2. For each file, extract every backticked identifier and every `<path>` or `[link](url)`. A short script in `tmp/` that
   parses these is cheaper than re-eyeballing each doc.
3. Verify each reference. Group findings into:
   - **Broken** - the thing genuinely no longer exists. Fix or remove.
   - **Renamed** - the thing moved. Update the reference.
   - **Stale** - the thing exists but means something different now. Note for human review.
4. For URLs, use a simple HEAD-request pass; flag 4xx and 5xx, plus redirects to known login pages.
5. Open one PR per category. Don't bundle "broken" with "renamed" - review effort differs.

## Output

A PR (or set of PRs) with a body section "Doc accuracy sweep - `<YYYY-MM-DD>`" listing every reference touched. If nothing was
touched, write a brief note in `docs/maintenance/log.md` with date and "no findings" so the cadence is auditable.

## Prompt template

```text
Run the doc accuracy sweep defined in docs/maintenance/tasks/doc-accuracy-sweep.md.

Scope: every committed Markdown file outside ai/, tmp/, node_modules/, .git/. List them with
`git ls-files '*.md' | grep -vE '^(ai|tmp)/'`.

For each file, find every backticked identifier (function names, type names, file paths, command names,
table names, env vars, ports) and every link target. Verify each one against the current repo state:
- File paths via `ls` or Read
- Symbol names via `grep -r` or Grep tool
- Commands via Taskfile.yml / Makefile lookup
- Env vars / ports / DSNs via internal/config and docker-compose*.yml
- External URLs via HEAD request

Group findings into Broken / Renamed / Stale. Open separate PRs per category. Do NOT rewrite tone or
add new content. If a finding requires a refactor of more than ~10 lines or touches code, stop and file
an issue instead.

Constraint: finish in 90 minutes of work. If the scope is too big, sweep one subdirectory of docs/ this
month and rotate.
```

## Definition of done

- [ ] Every committed `.md` outside the excluded paths has been visited.
- [ ] Broken / renamed references either fixed in a PR or filed as an issue with a link to the doc line.
- [ ] A dated entry exists in `docs/maintenance/log.md` (even if no findings).
- [ ] No tone changes or new content snuck in.

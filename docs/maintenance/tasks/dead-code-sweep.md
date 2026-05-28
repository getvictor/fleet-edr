# Dead code sweep

**Cadence:** quarterly
**Time budget:** 90 min
**Trigger mode:** manual

## Why this matters

Dead code (unused exports, orphan packages, dead UI components, abandoned migrations, unused config keys) is worse than
hypothetical: future readers will assume it's load-bearing and either reuse it incorrectly or refactor around it. Linters catch
some of it (`gopls` unused, ESLint `no-unused-vars`) but not orphan exports, dead routes, or "two implementations of the same
thing where only one is wired".

## Scope

- Go: unused exports across `server/`, `agent/`, `internal/`. Use `staticcheck -checks=U1000` or `go-deadcode`.
- TypeScript: dead components, dead exports, orphan files in `ui/src/`. Use `ts-prune` or `knip`.
- Swift: rarely used but worth a pass - orphan files in `extension/edr/`.
- SQL: migrations that reference columns / tables nobody reads any more.
- Config: keys in `server/config` (and `agent/config` for the agent daemon) with no consumer.
- HTTP routes: registered handlers with no client (UI / agent / curl).
- Skills / slash commands: see [`claude-config-audit`](claude-config-audit.md), don't duplicate.

## Steps

1. Run the appropriate dead-code tools per language:

   ```bash
   go install honnef.co/go/tools/cmd/staticcheck@latest
   staticcheck -checks=U1000 ./server/... ./agent/... ./internal/...

   cd ui && npx ts-prune
   # or: npx knip
   ```

2. Cross-check Go suspects manually - the `internal/`-only convention plus reflection-based wiring (e.g. handler registration)
   means staticcheck false-positives are common. Confirm by `grep -r '<Symbol>' --include='*.go' | grep -v '_test.go'`.
3. For each true positive, decide: **delete** / **wire it up** (was the export added speculatively?) / **keep with a comment**
   explaining why it looks unused (rare; usually means dynamic dispatch, in which case add a `//go:linkname`-style note).
4. SQL: check the schema for columns / tables not referenced from any Go query. If found, file an issue rather than dropping in
   this sweep - schema deletes need a migration plan.
5. Config: `grep -nr 'os.Getenv\|cfg\.' server agent internal` and cross-check against the config struct. Unused fields go.

## Output

One PR per language ecosystem (don't bundle Go + TS + Swift; review effort differs). PR body must include the dead-code tool's
output before the change so the diff reviewer can verify the deletions are well-grounded.

## Prompt template

```text
Run the dead-code sweep defined in docs/maintenance/tasks/dead-code-sweep.md.

Step 1 - Go: install staticcheck if missing, run `staticcheck -checks=U1000 ./server/... ./agent/...
./internal/...`. For each unused symbol, confirm with `grep -r '<Symbol>' --include='*.go'`. If
genuinely unused, delete; if used via reflection / handler registration / linkname, keep with a
one-line comment explaining how.

Step 2 - TS: `cd ui && npx ts-prune`. Same triage.

Step 3 - Schema / config: search internal/config struct fields against actual reads in the code; flag
unused.

Step 4 - Routes: list every HTTP route registered in server/ and confirm at least one client
(ui/src, agent/, or test/) hits it. Unused routes are an issue, not a sweep delete - file them.

Open separate PRs per language. Skip anything ambiguous and file an issue instead. Don't introduce
back-compat shims - if it's truly dead, delete cleanly.

Time budget 90 minutes total; if a single language has too many findings, sweep one and rotate.
```

## Definition of done

- [ ] Each language's dead-code tool ran cleanly (or its output documented).
- [ ] Each true positive deleted, wired up, or commented.
- [ ] Schema / route findings filed as issues, not silently deleted.
- [ ] Dated entry in `docs/maintenance/log.md`.

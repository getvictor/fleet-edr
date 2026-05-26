# spectrace

UAT plan milestone M13: a contributor-facing linter that links scenarios in `openspec/specs/<dir>/spec.md` to tests in
the codebase via the canonical-ID marker contract documented in `docs/testing-strategy.md`.

## Subcommands

```text
spectrace check    [--specs-dir DIR] [--root DIR] [--strict] [--by-layer] [--new-code] [--base-ref REF]
spectrace list-ids [--specs-dir DIR] [--normative-only]
spectrace report   [--specs-dir DIR] [--root DIR] [--format md] [--output FILE] [--normative-only]
```

- `check` walks every `#### Scenario:` under a `### Requirement:` whose body contains the RFC 2119 keywords SHALL or
  MUST, computes the canonical ID, and scans `*.go`, `*.ts`, `*.tsx`, `*.swift`, `*.yml`, `*.yaml`, and `*.sh` for
  matching markers. Prints the coverage delta to stdout and the gap list to stderr. Exit code is 0 unless an invalid
  reference is present, or `--strict` is set and at least one normative scenario in the gated set is uncovered.
  - `--by-layer` annotates the gap report with the layer coverage profile (L0..L6, Other) for each scenario so a
    contributor reading the list can see "covered at L1 but missing L4." For the full per-cell detail with file:line
    links, use `spectrace report` instead.
  - `--new-code` restricts the gate to scenarios whose `spec.md` lines (heading or enclosing requirement body) changed
    in the current branch relative to `--base-ref` (default `origin/main`). The diff is taken against the merge base,
    mirroring SonarCloud's "new code on this PR" framing: an existing legacy gap doesn't block a PR that doesn't touch
    it, but a new gap added by the PR does. Modifying the SHALL/MUST text in a requirement body promotes every
    scenario under that requirement into the new-code set, so tightening a requirement forces its covering tests to be
    re-considered. Scope is intentionally **spec-diff only**: a PR that deletes a marker in code without touching the
    spec does NOT cause `--strict --new-code` to fire on the now-uncovered scenario. Use plain `--strict` to gate on
    that shape; the rationale for the narrower scope is that a marker delete is usually intentional (the test moved or
    the scenario merged) and a contributor renaming code paths shouldn't be forced to re-mark every scenario the file
    touched.

- `list-ids` prints the canonical scenario IDs, one per line, so contributors can copy a marker without typing the slug.
  `--normative-only` restricts the output to SHALL / MUST scenarios (the gateable set).

- `report` renders the Markdown coverage matrix: one row per scenario, one column per layer (L0..L6, plus an `Other`
  column for non-test enforcement markers such as workflow YAML or packaging shell scripts, rendered only when needed).
  Each cell is a comma-separated list of `[basename:line](path#Lline)` Markdown links pointing at every marker that
  covers the scenario at that layer. `--output FILE` writes the matrix to a file instead of stdout. The subcommand
  never gates; CI can grep the rendered matrix for empty cells if a presentation-layer gate is wanted later.

### Layer classifier

The layer assigned to a marker is derived from its repo-relative file path by `tools/spectrace/layer.go`:

| Path prefix | Layer |
|---|---|
| `test/efficacy/...` | L6 (Detection efficacy) |
| `test/e2e/tests/...` | L4 (Browser E2E) |
| `test/integration/agentserver/...` | L3 (Headless agent + server) |
| `test/integration/...` | L2 (Cross-context integration) |
| `server/<context>/internal/tests/...` | L1 (Per-context integration) |
| `**/*_test.go`, `*.test.ts(x)`, `**/Tests/*.swift` | L0 (Unit) |
| Everything else (workflow YAML, packaging shell) | Other |

L5 (System / VM) is intentionally not auto-detected: there is no path prefix that uniquely identifies an L5 test in
this repo (the VM driver lives under `scripts/uat/` and runs scenarios out of `test/efficacy/corpus/.../attack.sh`). If
a future L5 harness lands with its own path prefix, add the case to `ClassifyLayer` in `layer.go`.

## Phased rollout

The CI workflow at `.github/workflows/spectrace.yml` runs `check --strict`: both invalid references and uncovered
SHALL / MUST scenarios fail the build. The advisory phase finished with all 262 normative scenarios covered on main;
the gate enforces 100% coverage from here.

What this means for contributors:

- Adding a new normative scenario (a `#### Scenario:` under a `### Requirement:` whose body contains SHALL or MUST)
  requires at least one marker reference in the same PR. Otherwise the spectrace job fails.
- Renaming a scenario heading changes the canonical-ID slug; every marker that referenced the old slug becomes an
  invalid reference and must be updated in the same PR.
- Deleting a scenario removes its denominator entry, but stale `// spec:<old-id>` markers in tests become invalid
  references; clean them up in the same PR.

`spectrace check` (no `--strict`) still works locally as the advisory variant: prints the coverage delta and the
invalid-reference list without changing exit code on uncovered scenarios. Useful for iterating mid-PR before every
marker is in place.

## Marker forms

See `docs/testing-strategy.md` for the contract. The recognised shapes are:

- Go subtest name: `t.Run("spec:<canonical-id>", ...)`
- Go comment marker: `// spec:<canonical-id>` immediately above a test
- Go table-driven `Spec` field: only counts when the test code threads the field through `t.Run("spec:"+tc.Spec, ...)`
  (or similar) so the literal `spec:<id>` string lands in the source. The scanner anchors on `spec:` as text, not on Go
  AST, so a `Spec` field consumed only by `assert.Equal(...)` is NOT a marker.
- Playwright title prefix: `test("spec:<canonical-id> <name>", ...)`
- Swift XCTest function name: `func test_spec_<id_with_slashes_and_dashes_replaced_by_underscores>(...)`
- YAML comment marker (workflows + workflow-adjacent configs): `# spec:<canonical-id>` on its own line above the step
  that enforces the scenario, or as a trailing comment on the step. Used by the release-packaging spec, whose scenarios
  are enforced by `.github/workflows/*.yml` rather than Go tests.
- Shell comment marker: `# spec:<canonical-id>` in `packaging/pkg/*.sh` and adjacent scripts whose body is the
  scenario's enforcement surface (e.g. the uninstall script for the `operator-runs-the-uninstall-script` scenario).

The scanner anchors on the literal `spec:` prefix (or `test_spec_` for Swift). Identifiers and strings containing those
prefixes elsewhere in the file are not matched because they fail the slug-shape regex (at least three slash-separated
segments of lowercase alphanumerics + dashes). Markdown files are intentionally NOT scanned even though `# spec:` would
work syntactically: `docs/testing-strategy.md` carries illustrative marker examples that would inflate the coverage
count if scanned. Add `.md` to the ext gate alongside a `docs/testing-strategy.md` skip-rule if that boundary ever
needs to move.

## Exclusion

`tools/spectrace/` is excluded from the marker scan because the linter's own test fixtures construct example marker
strings; counting those would inflate the coverage number and emit false-positive invalid-reference warnings on the
linter's own corpus.

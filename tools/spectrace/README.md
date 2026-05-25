# spectrace

UAT plan milestone M13: a contributor-facing linter that links scenarios in `openspec/specs/<dir>/spec.md` to tests in
the codebase via the canonical-ID marker contract documented in `docs/testing-strategy.md`.

## Subcommands

```text
spectrace check      [--specs-dir DIR] [--root DIR] [--strict]
spectrace list-ids   [--specs-dir DIR] [--normative-only]
```

- `check` walks every `#### Scenario:` under a `### Requirement:` whose body contains the RFC 2119 keywords SHALL or
  MUST, computes the canonical ID, and scans `*.go`, `*.ts`, `*.tsx`, `*.swift` for matching markers. Prints the
  coverage delta to stdout and the gap list to stderr. Exit code is 0 unless an invalid reference is present, or
  `--strict` is set and at least one normative scenario is uncovered.

- `list-ids` prints the canonical scenario IDs, one per line, so contributors can copy a marker without typing the slug.
  `--normative-only` restricts the output to SHALL / MUST scenarios (the gateable set).

## Phased rollout

The CI workflow at `.github/workflows/spectrace.yml` runs `check` in **advisory** mode: invalid references fail the
build (catches typos and stale spec renames at zero backlog cost) but uncovered SHALL / MUST scenarios are reported
without failing. Flip the workflow to `--strict` once the marker backlog is closed and every normative scenario has at
least one reference.

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

## What this tool does NOT do (v1)

- **`report --format=md` coverage matrix.** Mentioned in `docs/testing-strategy.md` as a future shape; deferred to a
  follow-up so the M13 budget stays on the linter. The same data the `check` command collects already feeds the gate.
- **Per-layer columns** in the gap list (L0 vs L1 vs L4 etc). Today the marker location is reported as a file path;
  classifying by layer would require either path heuristics or per-marker metadata. Not worth the complexity until the
  backlog is small enough that a person reads the list.
- **New-code gate semantics** (fail only on scenarios touched in the current PR). The `--strict` flag is the full-gate
  toggle; a follow-up can add a `--new-code` flag once main has a non-trivial number of markers landed.

## Exclusion

`tools/spectrace/` is excluded from the marker scan because the linter's own test fixtures construct example marker
strings; counting those would inflate the coverage number and emit false-positive invalid-reference warnings on the
linter's own corpus.

# Test-suite health

**Cadence:** quarterly
**Time budget:** 60-90 min
**Trigger mode:** manual

## Why this matters

A failing test suite gets attention. A *slowly degrading* test suite (flakes, skips, slow cases, semantically thin tests) does
not, until one day a real regression slips through because nobody trusts a red CI any more. The repo invests heavily in test
quality (PBT with rapid, fuzz, three-tier integration, `bootstrap.OpenTestDB`); the schedule keeps that investment from rotting.

CI already enforces:

- `go test ./...` passes
- Coverage on new code ≥ 80% (Codecov + SonarCloud)
- arch-go boundaries

It does NOT enforce: flake rate, total wallclock time, skipped count, mutation-test signal, or "this test passes but doesn't
actually test the property it claims to".

## Scope

`server/**/*_test.go`, `agent/**/*_test.go`, `internal/**/*_test.go`, `test/integration/`, `ui/**/*.test.ts(x)`,
`extension/edr/**/Tests/`.

## Steps

### 1. Skipped tests

```bash
git grep -nE 't\.Skip\b|it\.skip\b|describe\.skip\b|XCTSkip' -- '*_test.go' '*test*'
```

For each skip:

- Was it left behind by a flake hunt? Re-enable; if it really flakes, fix the flake or quarantine into `t.Run("flaky")`.
- Is it environment-gated (e.g. needs MySQL)? Confirm the gate is the right shape (`testing.Short()`, build tag, env var).
- Stale skips with no remaining reason - delete the test or unskip.

### 2. Slow tests

```bash
go test -json ./... | jq 'select(.Action=="pass") | {test:.Test, pkg:.Package, elapsed:.Elapsed}' \
  | jq -s 'sort_by(-.elapsed) | .[0:20]'
```

For the top 20 slowest:

- Is the slowness essential (real DB integration) or accidental (sleep, polling, network)?
- Convert sleeps to event-driven waits where possible.
- Push genuinely slow tests behind `testing.Short()` so unit-test runs stay snappy.

### 3. Flake hunt

Run the suite three times in a row with `-count=3`:

```bash
go test -count=3 -race ./server/... ./agent/... ./internal/...
```

Any test that doesn't pass all three times is a flake. Fix or quarantine.

### 4. Semantic thinness

Spot-check 10 tests at random across the contexts. For each, ask:

- Does the assertion actually pin the property it claims, or is it asserting a tautology (`require.NotNil(x)` on something the
  framework guarantees is non-nil)?
- Are error-path tests checking the *type* of error, or just `err != nil` (which would pass for any failure including
  framework bugs)?
- For PBT: does `rapid.Check` actually shrink to a counter-example when a property is broken? (Test it by mutating the property
  and confirming a shrunken failure.)
- For integration tests: are they hitting the real DB (per CLAUDE.md) and not a mock?

Don't try to fix all thin tests - file findings as issues with a representative example each.

### 5. Mutation testing (optional, advanced)

If the team has bandwidth, run a mutation test (e.g. `gomutesting`) on one critical package per quarter (`server/detection/`,
`server/identity/middleware`). Mutation score below 70% on a critical path warrants attention.

## Output

A PR with concrete fixes (skips removed, slow tests sped up, flakes quarantined / fixed). A separate issue list for semantic-
thinness findings (don't bundle).

## Prompt template

```
Run the test-suite health audit defined in docs/maintenance/tasks/test-suite-health.md.

Step 1 - find all skipped tests (grep for t.Skip, it.skip, describe.skip, XCTSkip). Triage each.

Step 2 - measure slow tests via `go test -json | jq` per the task file. Top 20 slowest get scrutiny:
fix accidental slowness (sleeps, polling), push essential slowness behind testing.Short().

Step 3 - `go test -count=3 -race` against server/, agent/, internal/. Flag flakes; fix or quarantine.

Step 4 - spot-check 10 random tests for semantic thinness (tautologies, weak error-path assertions,
mocks where integration is required per CLAUDE.md). File issues for findings; do NOT try to fix
during this sweep.

Step 5 - optional mutation test on one critical package.

Open one PR for fixes. Open separate issues for thinness findings. Time budget 90 minutes.
```

## Definition of done

- [ ] No surprise skips remain (every skip has a fresh reason).
- [ ] Top-20 slow tests reviewed; accidental slowness fixed or fenced.
- [ ] `-count=3 -race` suite passes; new flakes fixed or quarantined.
- [ ] At least 10 random semantic spot-checks done; issues filed for thinness.
- [ ] Dated entry in `docs/maintenance/log.md` with metrics (skip count, p99 test wallclock).

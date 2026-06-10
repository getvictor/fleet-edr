## Testing

The repo enforces a SonarCloud "Coverage on New Code ≥ 80%" gate per PR.
Codecov mirrors that threshold. Tests live in three layers:

1. **Per-package unit tests**: co-located with the code, default tag.
2. **Per-context integration tests**: `server/<context>/internal/tests/`,
   `package tests`, real MySQL via `testdb/full.Open(t)`.
3. **Cross-context integration tests**: `test/integration/`,
   `package integration`, multi-context scenarios.

### Test-style decision matrix

When adding tests, pick the style that matches the property under test:

| Style | Pick when | Library |
|---|---|---|
| Example-based + table-driven | Wire-format pinning, security regressions, named bug repros, HTTP handler error paths | `testify/assert` + `testify/require`, `t.Run` subtests |
| **Property-based (PBT)** | Algebraic invariants over an input space larger than a table can reasonably cover | `pgregory.net/rapid` |
| Fuzz | Untrusted input parsing (event JSON, policy diff, agent HTTP bodies) | `go test -fuzz` |
| Integration | DB-backed behaviour, multi-step workflows | `testdb/full.Open` + a real MySQL via docker-compose |
| **UI unit + component** | React component rendering, hooks, browser-facing logic (URL builders, fetch wrappers, state machines) | `vitest` + `@testing-library/react` + `@testing-library/jest-dom`, files at `ui/src/**/*.test.{ts,tsx}` |
| UI end-to-end | Spec-level user journeys (login + dashboard + policy editor flows) | `@playwright/test` at `test/e2e/tests/**/*.spec.ts`, `task uat:e2e` |

### When to reach for PBT

PBT (`pgregory.net/rapid`) is the right choice when the property holds across
a larger input space than a table-driven test can enumerate. Concrete shapes
in this codebase that already use or should use PBT:

- **Serialization round-trips**: `Marshal ∘ Unmarshal == identity`,
  `Scan ∘ Value == identity` for `NullRawJSON`, `JSONStringSlice`,
  `wire.DecodeBatch ∘ wire.EncodeBatch`.
- **State-machine transitions**: `service.canTransition` over the full
  `AlertStatus` enum cross-product, exhaustive-by-construction.
- **Graph invariants**: `graph.buildForest` - for any random fork batch, every
  non-root node has its parent in the tree, no cycles, every input PID
  appears exactly once.
- **Order-preserving filters**: `engine.filterSnapshotEvents` - the output is
  exactly the input minus the snapshot:true exec events, in the same order.
- **Re-exec chain**: walking `previous_exec_id` from any leaf reaches the
  chain root in ≤ chain length steps without revisiting nodes.

### UI testing convention

UI tests live under `ui/src/**` as `*.test.{ts,tsx}` files co-located with the source. Run via `cd ui && npm test` (or
`npm run test:coverage` for the LCOV that Sonar + codecov read). The conventions:

- **Components**: `@testing-library/react`'s `render` + `screen` + user-event idioms. Mock the API layer via `vi.spyOn(api,
  ...)` rather than stubbing global `fetch`; this keeps the test scoped to the component's behaviour, not the HTTP wire shape.
- **Hooks**: `renderHook` from `@testing-library/react`. The `act()` wrapper is required around state-setter calls.
- **Pure-logic modules** (URL builders, parsers, validators): plain vitest `describe` / `it` with no React dependency.
- **WebAuthn / browser globals**: stub via `vi.stubGlobal("navigator", { credentials: { create / get } })` or
  `vi.spyOn(globalThis.location, "assign")`. Tear down in `afterEach(vi.restoreAllMocks)`.

`ui/src/**` was excluded from Sonar's new-code coverage gate until vitest tests landed. The exclusion is now lifted; every
new UI file must carry a `*.test.{ts,tsx}` sibling that exercises the non-trivial branches. The 80% new-code gate applies
identically to UI + server code. Coverage is captured by V8 via vitest's coverage provider (`@vitest/coverage-v8`); the
Playwright E2E run captures complementary V8 coverage of the running React bundle via `monocart-coverage-reports`, and
Codecov takes the union.

PBT does NOT replace example-based tests when:

- The bug is specific (you want the exact reproducer in the test name).
- You're pinning a wire shape (you want the literal bytes).
- The path is security-critical (you want the test to be auditable as
  "this exact input produces this exact output").

### When PBT isn't a good fit, default to table-driven

Use `t.Run` subtests + a `cases := []struct{...}` slice. Keep test names
descriptive (`whitespace hostID`, `pending->completed must ack first`),
not numbered (`case3`).

## UAT and integration test layers

Full strategy: `docs/testing-strategy.md`. Seven test layers from unit tests up to detection-efficacy runs, with
reusable artefacts (fake agent library, headless agent binary on Linux, captured ESF corpus) and spec-to-test
traceability.

Minimum requirements per PR:

- **Behavior changes update the spec.** Any observable behavior change (bug fix, feature, detection rule, wire/event
  shape, API, persistence semantics) MUST update `openspec/specs/**` in the same PR, and add an `openspec/changes/`
  proposal for non-trivial deltas. The `OpenSpec sync` CI gate (`.github/workflows/openspec-sync.yml`) enforces this for
  the highest-signal paths (`server/rules/internal/catalog/`, `schema/events.json`, `server/detection/bootstrap/schema.go`).
  The gate fires on path, so a genuine no-behavior touch of those files (comment / refactor / gofmt / dep bump) asserts
  `no-behavior-change` (label or `[no-behavior-change]` in the title) to clear it. That opt-out is an auditable "this
  changes no behavior" claim a reviewer verifies; it is NEVER a way to skip the spec for a real behavior change.
- New wire-format struct or event field: PBT round-trip (`Marshal . Unmarshal == identity`).
- New detection rule under `server/rules/internal/catalog/`: ship `test/efficacy/corpus/T<MITRE-id>/scenario.yaml`
  plus `expected.yaml`. Add `attack.sh` when system / VM coverage is needed.
- Agent or extension change touching ESF, XPC, or the event wire format: must be exercised on a live macOS VM
  (the system / VM layer) before RC. Flag in the PR description.
- New or modified SHALL / MUST scenario in `openspec/specs/`: at least one test must reference the canonical
  scenario ID. ID scheme and marker forms in `docs/testing-strategy.md`; gated by `tools/spectrace`.

## Bounded contexts

ADR-0004 carved `server/` into five bounded contexts: `identity`, `endpoint`,
`rules`, `response`, `detection`. Cross-context calls go through the imported
`api/` package only. Internal packages are Go-compiler enforced via the
`internal/` rule. arch-go (`arch-go.yml`) layers an extra check.

## Dev environment

- Local MySQL: `task db:up` brings up `127.0.0.1:33306` (dev) and `:33307` (test).
  Empty password (`MYSQL_ALLOW_EMPTY_PASSWORD=yes` in `docker-compose.yml`).
- Dev server: `task dev:server` listens on `127.0.0.1:8088` against
  `127.0.0.1:33306/edr`. Real-tool QA must use this; never fall back to curl
  or unit tests when the user asks for a Chrome / VM / dev-server check.
- Test DSN: `EDR_TEST_DSN=root@tcp(127.0.0.1:33307)/edr_test?parseTime=true`.

## Coverage gates

CI uploads `coverage-server.out` from
`go test -coverpkg=./server/...,./internal/... -coverprofile=... ./server/... ./internal/...`.
The wide `-coverpkg` is mandatory: integration tests at
`server/<context>/internal/tests/` exercise other packages' symbols, and
without `-coverpkg` Sonar would report 0% on the bootstrap / service files
those tests fully cover.

## Code style

Layered on the global guide. Project-specific:

- Line wrap source code at 140 characters.
- Markdown is NOT hard-wrapped: write each paragraph and bullet as one line and let it soft-wrap. Tables are Prettier-aligned (cells padded so column dividers line up). Both are enforced by Prettier (`proseWrap: never`, `.prettierrc.yaml`); run `task lint:md:prose:fix` to reflow, `task lint:md:prose` to check. markdownlint (`task lint:md`) owns Markdown structure; the two are scoped not to overlap.
- Sentence case for headings.
- No em dashes, and no spaced hyphen (` - `) standing in for one: reword the sentence (prefer shorter sentences) or use a colon. A hyphen is fine only unspaced inside a compound word (`per-IP`) or as a list marker. Insert a literal em dash (U+2014) only when explicitly asked. Enforced by `task lint:dashes`: `tools/lint-no-emdash.sh` bans the dash characters in any tracked text file, `tools/dash-lint` bans the spaced-hyphen use in Markdown prose and in code comments and string literals.
- Don't run `task db:reset` without explicit user permission.
- Stateless server (ADR-0010): the server holds no in-process state that survives a request lifetime and that a peer replica
  would need to serve the next request. Durable cross-request state goes in MySQL; per-request state may ride in signed cookies;
  a new in-process map / channel / queue holding shared state is a review defect unless it carries a "per-replica perf cache,
  safe to lose" note. The app tier is multi-replica behind a load balancer (the server-availability arc).
- Go 1.22+ integer range expressions (`for i := range N` where `N` is an `int`) are valid project style and the
  modernize linter prefers them over `for i := 0; i < N; i++`. Copilot + CodeRabbit have re-flagged this pattern as
  "doesn't compile" on multiple PRs (#239 most recently); the claim is false and the finding should be skipped.
- When you delete a symbol (function, type, command name, XPC message kind, config field),
  scrub every doc comment that still references it before committing. Stale comments
  in IPC-adjacent code are a recurring class of footgun in review (see PR #151 where
  both Copilot and CodeRabbit caught a dispatcher reference on a function whose
  dispatcher argument no longer existed). Treat the comment delta as part of the
  deletion, not a follow-up.

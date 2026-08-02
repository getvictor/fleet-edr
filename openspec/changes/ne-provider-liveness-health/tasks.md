# Report network extension health from capture-provider liveness: tasks

## 1. Extension reports liveness

- [x] `extension/edr/networkextension/ProviderLiveness.swift`: pure state machine holding which providers are running or stopped, the wire payload, and the deliberate-stop reason set. No NetworkExtension import, so the transitions and the wire shape are unit-testable.
- [x] `extension/edr/networkextension/ProviderStatusReporter.swift`: serialises and broadcasts a snapshot on every real transition, grading a stop by its reason so a deliberate disable becomes absence rather than a fault.
- [x] `extension/edr/networkextension/NetworkFilter.swift`, `DNSProxyProvider.swift`: report their own start and stop, passing the platform's stop reason.
- [x] `extension/edr/shared/XPCEventServer.swift`: `start(onPeerConnected:)` fires after the hello flush so the network extension can re-publish level-triggered state to a freshly connected agent. Passed to `start` rather than `init` because a stored property initialised from a static that references the server back is a compile-time circular reference.
- [x] `extension/edr/networkextension/main.swift`, `XPCServer.swift`: wire the hook, with the reporter in its own type for the same circular-reference reason.

## 2. Agent grades health from it

- [x] `agent/health/health.go`: `GradeProviders` (pure), `MarkProviders`, `MarkAwaitingProviders`, and the three new reasons. Reason vocabulary is open by contract, so no server change.
- [x] `agent/cmd/fleet-edr-agent/main.go`: `parseProviderStatus` recognises the control message; the network-extension loop applies it to health and returns before the proctable and the upload queue, so it never becomes telemetry. `OnConnected` holds at degraded for that loop instead of marking healthy.
- [x] `agent/cmd/fleet-edr-agent/sensors_notwindows.go`: `providerLiveness` set only for the network-extension loop; the ESF loop keeps grading on connectivity, because its provider starts with its process.

## 3. Spec

- [x] `agent-status-reporting` delta: ADDED "Network extension health reflects capture-provider liveness" with the no-provider, stopped-provider, deliberate-disable and awaiting-report scenarios.

## 4. Tests

- [x] `agent/health/providers_test.go`: the grading matrix (no providers, all running, absent provider, one stopped, several stopped sorted, a stop outranking a running sibling, an unrecognised state not counting as running) plus the registry transitions through awaiting, healthy, stopped and disconnected.
- [x] `agent/cmd/fleet-edr-agent/providerstatus_test.go`: the control message is recognised, an EMPTY provider set is still a status message (it is the #649 signal itself), and ordinary telemetry and malformed input are left alone.
- [x] `extension/edr/Tests/EDRExtensionLogicTests/ProviderLivenessTests.swift`: transitions, repeat-suppression, absence-vs-stopped, the deliberate-stop reason set, and the provider identifiers as a pinned wire contract.

## 5. Verification

- [x] `swift test` (217 tests), `go test ./agent/...`, `xcodebuild` Debug build green.
- [x] `swiftlint lint --strict` (65 files, 0 violations); `golangci-lint` on `./agent/...` (0 issues); `openspec validate ne-provider-liveness-health --strict`; spectrace 775/775; dash + markdown lints.
- [x] Live macOS VM (edr-dev, macOS 26.3) against `task dev:server`, reading health out of the dev server's `host_health` rather than trusting the agent's own logs:

  | state on the host                                          | extension broadcast                               | `network_extension` health                                                        |
  | ---------------------------------------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- |
  | both providers running                                     | `content_filter` and `dns_proxy` running          | `healthy / activated`                                                              |
  | opt-in DNS proxy deliberately disabled                     | `dns_proxy stopped (reason 9)`, graded deliberate | `healthy / activated` (absent, not a fault)                                        |
  | both providers stopped, extension process still up         | no provider running                               | `unhealthy / no_providers_running`, "is running but no capture provider started"   |
  | providers re-activated                                     | both running again                                | `healthy / activated`, flow telemetry current within seconds                       |

  The third row is the #649 failure exactly: extension process alive (pid 24263), XPC session established, nothing capturing. Before this change that state reported `healthy / activated / "Network extension connected"`. The reason `no_providers_running` can only be produced by `MarkProviders`, which only runs on a report delivered over a live XPC session, so the session demonstrably was up while health correctly reported unhealthy.

  Note on the second row: the platform reported stop reason 9 (`configurationDisabled`) and reason 1 (`userInitiated`) for the two deliberate stops, confirming the reason-based grading works against the real values rather than only against the unit tests' assumptions.

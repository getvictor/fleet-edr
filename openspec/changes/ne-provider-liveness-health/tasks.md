# Report network extension health from capture-provider liveness: tasks

## 1. Extension reports liveness

- [x] `extension/edr/networkextension/ProviderLiveness.swift`: pure state machine holding which providers are running or stopped, the wire payload, and the stop-reason sets. No NetworkExtension import, so the transitions and the wire shape are unit-testable.
- [x] `extension/edr/networkextension/ProviderStatusReporter.swift`: serialises and broadcasts a snapshot on every real transition, grading a stop by its reason AND by which provider stopped. Session-lifecycle stops (logout, user switch, superceded, configuration removed) are absence for either provider; an operator switching a provider off is absence only for the opt-in DNS proxy, because switching off the mandatory content filter is exactly the state that must stay visible.
- [x] `extension/edr/networkextension/NetworkFilter.swift`, `DNSProxyProvider.swift`: report their own start and stop, passing the platform's stop reason.
- [x] `extension/edr/shared/XPCEventServer.swift`: `start(onPeerConnected:)` fires from the pending-flush DRAIN COMPLETION, so the current snapshot lands after every buffered event rather than after only the first chunk; otherwise a stale status event still queued in a later chunk would overwrite correct liveness. Passed to `start` rather than `init` because a stored property initialised from a static that references the server back is a compile-time circular reference.
- [x] `extension/edr/networkextension/main.swift`, `XPCServer.swift`: wire the hook, with the reporter in its own type for the same circular-reference reason.

## 2. Agent grades health from it

- [x] `agent/health/health.go`: `GradeProviders` (pure), `MarkProviders`, `MarkAwaitingProviders`, and the three new reasons. Reason vocabulary is open by contract, so no server change.
- [x] `agent/cmd/fleet-edr-agent/main.go`: `parseProviderStatus` recognises the control message; the network-extension loop applies it to health and returns before the proctable and the upload queue, so it never becomes telemetry. `OnConnected` holds at degraded for that loop instead of marking healthy.
- [x] `agent/cmd/fleet-edr-agent/sensors_notwindows.go`: `providerLiveness` set only for the network-extension loop; the ESF loop keeps grading on connectivity, because its provider starts with its process.

## 3. Spec

- [x] `agent-status-reporting` delta: ADDED "Network extension health reflects capture-provider liveness" (healthy, no-provider, stopped-provider, deliberate-disable, mandatory-filter-stays-visible and awaiting-report scenarios) and ADDED "Capture-provider status is a control message, not telemetry", which makes the never-uploaded contract normative rather than only stated in this proposal.

## 4. Tests

- [x] `agent/health/providers_test.go`: the grading matrix (no providers, all running, absent provider, one stopped, several stopped sorted, a stop outranking a running sibling, an unrecognised state not counting as running) plus the registry transitions through awaiting, healthy, stopped and disconnected.
- [x] `agent/cmd/fleet-edr-agent/providerstatus_test.go`: the control message is recognised, an EMPTY provider set is still a status message (it is the #649 signal itself), and ordinary telemetry and malformed input are left alone. Plus `FuzzParseProviderStatus`, which the testing-strategy matrix requires for a parser of untrusted input: it cross-checks the drop decision against an independent decode, because a false positive silently DROPS telemetry and is invisible at runtime.
- [x] `extension/edr/Tests/EDRExtensionLogicTests/ProviderLivenessTests.swift`: transitions, repeat-suppression, absence-vs-stopped, the per-provider stop-reason grading (lifecycle stops are absence for both, an operator disable is absence only for the DNS proxy, faults are never absence), and the provider identifiers as a pinned wire contract.

## 5. Verification

- [x] `swift test` (219 tests), `go test ./agent/...`, `go vet -tags integration ./agent/...`, `xcodebuild` Debug build green. `FuzzParseProviderStatus` run to 2.9M executions with no failures.
- [x] `swiftlint lint --strict` (0 violations); `golangci-lint` on `./agent/...` (0 issues); `openspec validate ne-provider-liveness-health --strict`; spectrace 775/775 with 0 invalid references; dash + markdown lints.
- [x] Live macOS VM (edr-dev, macOS 26.3, sysext `1.1/22`) against `task dev:server`, reading health out of the dev server's `host_health` rather than trusting the agent's own logs:

  | state on the host                                     | platform stop reason        | published `providers` payload                      | `network_extension` health                                                       |
  | ----------------------------------------------------- | --------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------- |
  | both providers running                                | none                        | `content_filter: running`, `dns_proxy: running`     | `healthy / activated`                                                             |
  | opt-in DNS proxy disabled                             | 9 (`configurationDisabled`) | `content_filter: running` only; `dns_proxy` ABSENT  | `healthy / activated` (absent, not a fault)                                       |
  | mandatory content filter disabled                     | 1 (`userInitiated`)         | `content_filter: stopped`                           | `unhealthy / provider_stopped`, "stopped capturing: content_filter"               |
  | extension relaunched with both configs off            | n/a, neither provider ran   | empty                                               | `unhealthy / no_providers_running`, "is running but no capture provider started"  |
  | both providers re-enabled                             | none                        | both running again                                  | `healthy / activated`                                                             |

  The stop reason and the published payload are separate columns on purpose: a stop graded as deliberate absence REMOVES the provider from the broadcast snapshot, so the reason appears only in the extension's log, never in the `providers` map the agent grades.

  Row 4 is the #649 failure exactly: a freshly relaunched extension process (pid 27265) whose XPC session is established while nothing is capturing. Before this change that state reported `healthy / activated / "Network extension connected"`. The reason `no_providers_running` can only be produced by `MarkProviders`, which only runs on a report delivered over a live XPC session, so the session demonstrably was up while health correctly reported unhealthy.

  Row 3 pins the per-provider grading asymmetry against the real platform values. The same stop reason 1 that the previous build logged as "treating it as deliberately disabled" now logs "treating it as a fault" for the content filter, and the component goes unhealthy. That state used to report HEALTHY, because forgetting the content filter left a snapshot of `{dns_proxy: running}`, so a host whose mandatory network capture had been switched off looked fine.

  Row 1 also covers the flush-ordering change: health resolves from `awaiting_provider_status` through to `healthy`, which is only reachable if the drain-completion callback fires.

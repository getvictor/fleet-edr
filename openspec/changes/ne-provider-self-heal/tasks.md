# Restore stopped network extension capture providers automatically: tasks

## 1. Remediation policy

- [x] `agent/selfheal/providers.go`: `Remediable` filters a liveness report down to providers that are both stopped and known to be restorable. The absence rule from #649 is the whole safety story: an operator-disabled provider is omitted from the map rather than reported stopped, so filtering on `stopped` alone can never re-enable something a human turned off. A provider with no known enable subcommand is reported by health but not acted on.
- [x] `agent/selfheal/controller.go`: the state machine. Opens a grace window on the first stopped report, remediates once it expires, bounds attempts, backs off between them, and escalates through the health registry when the budget is spent. Clock and remediator injected so the policy is testable without the host app.

## 2. Platform remediation

- [x] `agent/selfheal/remediator_darwin.go`: runs the host app's `enable-filter` / `enable-dns-proxy`. Deliberately NOT wrapped in `launchctl asuser`: `OSSystemExtensionRequest` needs a user Aqua session but a provider toggle does not, so a host at the loginwindow recovers too. The host app's output is folded into the error because it prints its reason rather than encoding it in the exit status.
- [x] `agent/selfheal/remediator_other.go`: nil remediator on non-darwin, which makes the controller inert. Mirrors the build-tag split the agent already uses for `commander`'s kill and the receiver stub.

## 3. Agent wiring and health

- [x] `agent/health/health.go`: `MarkSelfHealFailed` plus the `self_heal_failed` reason, so "recovery is in progress" and "recovery gave up, a human is needed" are different operator-visible states. Not sticky: the next provider report overwrites it, so a provider that returns by any route clears the escalation without its own reset path.
- [x] `agent/cmd/fleet-edr-agent/main.go`, `sensors_notwindows.go`: the controller observes the SAME report `MarkProviders` grades, so what is reported unhealthy and what gets remediated cannot drift apart. Wired only on the network-extension loop.

## 4. Spec

- [x] `agent-status-reporting` delta: ADDED "The agent restores stopped capture providers", "Remediation never overrides a deliberate operator decision", and "Remediation attempts are bounded and escalate on exhaustion".

## 5. Tests

- [x] `agent/selfheal/providers_test.go`: the eligibility matrix, including that a deliberately disabled provider is absent (not stopped), that a nil / empty report is not a licence to guess which providers should be running, and that an unknown provider is reported but not acted on.
- [x] `agent/selfheal/controller_test.go`: grace window respected, self-recovery within grace cancels remediation, deliberate disable never remediated however long it persists, budget exhaustion escalates exactly once, a successful heal restores the budget, one remediation at a time per provider, nil remediator is inert.
- [x] `agent/selfheal/remediator_darwin_test.go`: the invocation is the subcommand and nothing else, which is the assertion that pins the loginwindow property (no `launchctl asuser`, no `sudo -u`, no console-uid lookup). Plus host-app output surfacing on failure.
- [x] `go test -race` clean. The race detector caught a real defect in the first test harness: the controller reads its injected clock from the remediation goroutine, so a bare `time.Time` advanced by the test races. Fixed with a mutex-guarded test clock, and the concurrency requirement is now documented on `Options.Now`.

## 6. Verification

- [x] `go test ./agent/...`, `go vet -tags integration ./agent/...`, builds for darwin, linux and windows. `agent/selfheal` coverage 97.8%.
- [x] `golangci-lint` on `./agent/...` (0 issues); `openspec validate ne-provider-self-heal --strict`; spectrace 775/775 with 0 invalid references.
- [x] Live macOS VM (edr-dev, macOS 26.3, sysext `1.1/22`) against `task dev:server`. Both directions of the grading asymmetry were exercised with real platform stop reasons, and health was read from the dev server rather than the agent's logs.

  **The mandatory content filter is restored automatically.** Stop reason 1 (`userInitiated`), graded a fault, so the provider is reported stopped and is eligible:

  | time         | event                                                                       |
  | ------------ | --------------------------------------------------------------------------- |
  | 17:21:11.247 | extension: `content_filter stopped (reason 1); treating it as a fault`       |
  | 17:21:11.254 | agent: grace window opened, 7ms after the extension's report                 |
  | 17:21:43.887 | agent: `restoring stopped capture provider`, attempt 1 of 3                  |
  | 17:21:44.040 | agent: enable returned success after 153ms                                   |
  | 17:21:44.064 | extension: `content_filter is running`                                       |
  | 17:21:44.071 | agent: state cleared on the extension's confirming report, budget restored   |

  Stopped to capturing again in 33 seconds with no human action. Server health returned to `healthy / activated`. Before this change the provider stayed stopped until someone ran the host app's `activate` by hand.

  **The opt-in DNS proxy is left alone.** Stop reason 9 (`configurationDisabled`) on the opt-in provider is graded deliberate, so #649 reports it ABSENT and it is never eligible:

  | time         | event                                                                                    |
  | ------------ | ---------------------------------------------------------------------------------------- |
  | 17:19:12.015 | extension: `dns_proxy stopped (reason 9); treating it as deliberately disabled`           |
  | +100s        | zero self-heal activity in the agent log; the DNS proxy stayed disabled                   |

  100 seconds is 3.3x the grace window, so this is not a timing artefact. A first pass at this test was discarded as worthless: the DNS proxy was already off, the extension's repeat-suppression correctly logged nothing, and "no action" would have proved nothing. The result above is from a clean baseline with both providers running and a real observed transition.

- [ ] Not covered: remediation with NO console user logged in. The invocation is asserted to carry no session wrapper (`remediator_darwin_test.go`), and the enable was measured to work from plain root rather than through `launchctl asuser`, but the VM had a console session throughout, so the loginwindow case is reasoned rather than observed.

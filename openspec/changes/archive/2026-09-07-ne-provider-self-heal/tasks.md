# Restore stopped network extension capture providers automatically: tasks

## 1. Remediation policy

- [x] `agent/selfheal/providers.go`: `Remediable` filters a liveness report down to providers that are both stopped and known to be restorable. The absence rule from #649 is the whole safety story: an operator-disabled provider is omitted from the map rather than reported stopped, so filtering on `stopped` alone can never re-enable something a human turned off. A provider with no known enable subcommand is reported by health but not acted on.
- [x] `agent/selfheal/controller.go`: the state machine. Opens a grace window on the first stopped report, remediates once it expires, bounds attempts, backs off between them, and escalates through the health registry when the budget is spent. Clock and remediator injected so the policy is testable without the host app.

## 2. Platform remediation

- [x] `agent/selfheal/remediator_darwin.go`: verifies the host app carries the agent's own team identifier before executing it as root, then runs `enable-filter` / `enable-dns-proxy`. The check exists because `/Applications` is `drwxrwxr-x root:admin`, so a non-root admin can swap the bundle by writing the parent directory; this remediator is the only thing that runs that path as root. An ad-hoc agent build has no team to compare against, so it logs and proceeds rather than breaking every dev host. Deliberately NOT wrapped in `launchctl asuser`: `OSSystemExtensionRequest` needs a user Aqua session but a provider toggle does not, so a host at the loginwindow recovers too. The host app's output is folded into the error because it prints its reason rather than encoding it in the exit status.
- [x] `agent/selfheal/remediator_other.go`: nil remediator on non-darwin, which makes the controller inert. Mirrors the build-tag split the agent already uses for `commander`'s kill and the receiver stub.

## 3. Agent wiring and health

- [x] `agent/health/health.go`: `MarkSelfHealFailed` plus the `self_heal_failed` reason, so "recovery is in progress" and "recovery gave up, a human is needed" are different operator-visible states. The controller owns keeping that state true rather than health making it sticky: the receiver loop calls `MarkProviders` before `Observe`, so every report would otherwise overwrite the escalation back to `provider_stopped` and the operator would never see it. One owner, and it is the side that knows whether the budget is spent.
- [x] `agent/cmd/fleet-edr-agent/main.go`, `sensors_notwindows.go`: the controller observes the SAME report `MarkProviders` grades, so what is reported unhealthy and what gets remediated cannot drift apart. Wired only on the network-extension loop.

## 4. Spec

- [x] `agent-status-reporting` delta: ADDED "The agent restores stopped capture providers", "Remediation never overrides a deliberate operator decision", and "Remediation attempts are bounded and escalate on exhaustion".

## 5. Tests

- [x] `agent/selfheal/providers_test.go`: the eligibility matrix, including that a deliberately disabled provider is absent (not stopped), that a nil / empty report is not a licence to guess which providers should be running, and that an unknown provider is reported but not acted on.
- [x] `agent/selfheal/controller_test.go`: grace window respected, self-recovery within grace cancels remediation, deliberate disable never remediated however long it persists, budget exhaustion escalates AND is re-asserted on every later report, an enable that keeps succeeding without restoring the provider still burns the budget, flapping between stopped and absent does not refresh the budget, only an affirmative running report does, attempts are spaced by the backoff alone, one remediation at a time per provider, nil remediator is inert.
- [x] `agent/selfheal/remediator_darwin_test.go`: the invocation is the subcommand and nothing else, which is the assertion that pins the loginwindow property (no `launchctl asuser`, no `sudo -u`, no console-uid lookup). Plus host-app output surfacing on failure, and both branches of the identity check: a foreign-signed host app is refused and never exec'd, a matching team is accepted, and an ad-hoc agent build proceeds with a warning. The signing evaluator is injected because a test binary is ad-hoc signed, so against the real one only the dev path would ever run.
- [x] `go test -race` clean. The race detector caught a real defect in the first test harness: the controller reads its injected clock from the remediation goroutine, so a bare `time.Time` advanced by the test races. Fixed with a mutex-guarded test clock, and the concurrency requirement is now documented on `Options.Now`.

## 6. Verification

- [x] `go test ./agent/...`, `go vet -tags integration ./agent/...`, builds for darwin, linux and windows. `agent/selfheal` coverage 95.9%.
- [x] `golangci-lint` on `./agent/...` (0 issues); `openspec validate ne-provider-self-heal --strict`; spectrace 775/775 with 0 invalid references.
- [x] Live macOS VM (edr-dev, macOS 26.3, sysext `1.1/22`) against `task dev:server`. Both directions of the grading asymmetry were exercised with real platform stop reasons, and health was read from the dev server rather than the agent's logs.

  **The mandatory content filter is restored automatically.** Stop reason 1 (`userInitiated`), graded a fault, so the provider is reported stopped and is eligible:

  | time         | event                                                                       |
  | ------------ | --------------------------------------------------------------------------- |
  | 17:53:45.391 | extension: `content_filter stopped (reason 1); treating it as a fault`               |
  | 17:53:45.396 | agent: grace window opened, 5ms after the extension's report                         |
  | 17:54:21.568 | agent: `restoring stopped capture provider`, attempt 1 of 3                          |
  | 17:54:21.709 | agent: host app identity check took the ad-hoc dev branch and warned rather than failing |
  | 17:54:21.955 | agent: enable returned success                                                       |
  | 17:54:21.993 | extension: `content_filter is running`                                               |
  | 17:54:21.998 | agent: `capture provider is running again; clearing self-heal state`, budget restored |

  Stopped to capturing again in 36 seconds with no human action. This run is from the post-review build, so it also exercises the two paths review changed: the host-app identity check (ad-hoc agent, so it warns and proceeds) and the affirmative-running-only reset. Server health returned to `healthy / activated`. Before this change the provider stayed stopped until someone ran the host app's `activate` by hand.

  **The opt-in DNS proxy is left alone.** Stop reason 9 (`configurationDisabled`) on the opt-in provider is graded deliberate, so #649 reports it ABSENT and it is never eligible:

  | time         | event                                                                                    |
  | ------------ | ---------------------------------------------------------------------------------------- |
  | 17:19:12.015 | extension: `dns_proxy stopped (reason 9); treating it as deliberately disabled`           |
  | +100s        | zero self-heal activity in the agent log; the DNS proxy stayed disabled                   |

  100 seconds is 3.3x the grace window, so this is not a timing artefact. A first pass at this test was discarded as worthless: the DNS proxy was already off, the extension's repeat-suppression correctly logged nothing, and "no action" would have proved nothing. The result above is from a clean baseline with both providers running and a real observed transition.

- [ ] Not covered: remediation with NO console user logged in. The invocation is asserted to carry no session wrapper (`remediator_darwin_test.go`), and the enable was measured to work from plain root rather than through `launchctl asuser`, but the VM had a console session throughout, so the loginwindow case is reasoned rather than observed.

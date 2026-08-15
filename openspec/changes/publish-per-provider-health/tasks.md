# Tasks

## 1. Agent

- [x] 1.1 Record the latest liveness report per parent component, keeping each provider's transition instant across unchanged reports
- [x] 1.2 Render one component per reported provider in the snapshot, sorted, following its parent
- [x] 1.3 Drop a provider the extension stops reporting, rather than retaining its last state
- [x] 1.4 Grade an unrecognised provider state as unknown

## 2. Tests

- [x] 2.1 Providers appear as their own components beside the unchanged parent
- [x] 2.2 A provider that goes absent is dropped, and the parent is not degraded by its absence
- [x] 2.3 Mutation-check that guard by accumulating providers instead of replacing, and confirm the test fails
- [x] 2.4 An unchanged provider keeps its instant; a real transition re-stamps it
- [x] 2.5 Unrecognised state grades to unknown; ordering is stable; an unregistered parent is a no-op

## 3. Operator surface

- [x] 3.1 Friendly labels for the two known providers, distinct from the derived delivery conditions
- [x] 3.2 UI test that both providers render with their own state and age

## 4. Live QA on the VM

Run on edr-dev 2026-08-15 against the real agent and extension.

- [x] 4.1 Confirm the real host posts a component per provider. The snapshot now carries `content_filter` and `dns_proxy` alongside the two unchanged extension components, each with a positive `activated` / "is capturing" claim
- [x] 4.3 Stop the mandatory content filter and confirm its component reports stopped while the parent does too. Got exactly the granularity this change exists for, in one snapshot: `network_extension` unhealthy/`provider_stopped` (the old collapsed view), `content_filter` unhealthy/`provider_stopped` (which one), and `dns_proxy` still healthy/`activated` (an untouched provider keeps its positive claim). Self-heal restored it and all four returned to healthy
- [ ] 4.2 Disable the optional DNS proxy and confirm its component DISAPPEARS rather than lingering as running. **BLOCKED, and not by this change**: `disable-dns-proxy` persists the disable (`Enabled => false` in the NE preferences) but the provider keeps capturing, so the extension never reports it absent and there is no opt-out for the agent to observe. Filed as #706. The drop itself is covered by a unit test and a mutation check that accumulates providers instead of replacing them and confirms the test fails

## 5. Follow-up (the consumer half of #702)

- [ ] 5.1 Gate the derived telemetry check on each provider's own claim, delete `ReferenceWindow`, and remove the two documented inaccuracies from the #677 spec delta

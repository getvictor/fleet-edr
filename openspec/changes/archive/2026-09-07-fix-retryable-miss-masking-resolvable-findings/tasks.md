# Tasks

## 1. Stop a rule abandoning its batch on the first miss

- [x] 1.1 Add a `pendingMiss` helper to `server/rules/internal/catalog/eval.go` that remembers the first retryable materialization miss, returns any other error as fatal, and lets the loop continue.
- [x] 1.2 Make `evalEachEvent` use it and return the collected findings alongside the miss.
- [x] 1.3 Apply it in `dns_c2_beacon` (the rule that lost alerts), `suspicious_exec` (spanning both of its passes), `osascript_network_exec`, `credential_keychain_dump`, `dyld_insert`, and `application_control_block`.
- [x] 1.4 Collapse `shell_from_office` and `persistence_launchagent` onto `evalEachEvent`: both were open-coded copies of it.
- [x] 1.5 State the policy on the `api.Rule.Evaluate` contract so a new rule cannot reintroduce the early return without contradicting its own interface docs.

## 2. Stop the engine abandoning the remaining rules on the first miss

- [x] 2.1 `Engine.Evaluate` evaluates every registered rule, remembers the first retryable miss, and returns it after the loop.
- [x] 2.2 `Engine.evaluateRule` persists the findings a rule resolved even when that rule also reported a miss, then returns the miss.
- [x] 2.3 Keep non-retryable semantics unchanged: a rule-evaluation error stays logged-and-swallowed, an alert-persistence error still aborts.

## 3. Never write an impossible process lifetime

- [x] 3.1 Add the `fork_time_ns < closedAtNs` bound to `mysql.Store.CloseStaleProcess`.
- [x] 3.2 Mirror it in the `batchSession` overlay so the set-based path and the store stay equivalent.

## 4. Make the demo barrier wait for what the rules actually read

- [x] 4.1 `waitForProcess` requires `exec_time_ns IS NOT NULL`, since every consumer it gates keys off the exec'd image.
- [x] 4.2 Update the seeder test fixtures: `insertProcess` now writes an exec-imaged row, and a new `insertForkOnlyProcess` covers the pre-exec shape.

## 5. Tests

- [x] 5.1 `TestDNSC2Beacon_OrphanedConnectDoesNotMaskResolvableBeacon`: an orphaned connect ordered FIRST in the batch must not stop the resolvable beacon from firing, and the miss must still be reported. Verified to fail against the pre-fix rule.
- [x] 5.2 `TestEngine_Evaluate_AFailingRuleDoesNotSuppressLaterRules`: table-driven over the retryable and non-retryable error classes, asserting a later-registered rule still runs in both.
- [x] 5.3 `TestEngine_PersistsFindingsReportedAlongsideRetryableMiss` (DB-backed): the resolved finding persists, and dedup keeps the retried batch idempotent.
- [x] 5.4 `TestCloseStaleProcess_LeavesLaterGenerationOpen`: a fork arriving after the exec-synthesized record leaves it open and writes no impossible lifetime. `TestCloseStaleProcess_OrderingBoundary` then walks the whole ordering relation (earlier / equal / later); the equal case is what pins the predicate as `<` rather than `<=`.
- [x] 5.5 Extend `TestWaitForProcess` so a fork-only row does not satisfy the barrier and imaging it with the exec releases it.

## 6. End-to-end verification on the demo stack

- [x] 6.1 Reproduce the failure locally first (pre-fix: `seeder=1`, `missing_rules=[dns_c2_beacon]`, with the impossible-lifetime row captured).
- [x] 6.2 Confirm the fix: 14 consecutive green runs (8 unrestricted, 6 with the server throttled to 0.35 CPU), all 8 alerts present, zero rows with `exit_time_ns < fork_time_ns`.
- [x] 6.3 Confirm the margin is restored: the `dns_c2_beacon` alert now lands 0.44s to 0.58s after its `network_connect` is ingested, against a 5.0s grace. Pre-fix it landed at 5.10s to 5.51s, i.e. at or past the boundary on every run including the green ones.

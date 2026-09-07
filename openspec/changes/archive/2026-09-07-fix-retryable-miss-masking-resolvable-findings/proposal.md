# Stop a retryable materialization miss from masking resolvable findings

## Why

`dns_c2_beacon` silently loses alerts. The demo nightly's source leg caught it three times in fifteen runs (2026-07-18, 07-29, 07-30), always as `missing_rules=[dns_c2_beacon]` after the seeder's 60s verify, and always with nothing in the server log to explain it (issue #661). The same loss is reachable in production on any replica that is briefly behind on graph materialization.

Three defects compose. Each one is a variant of the same mistake: an event that can never be resolved is allowed to consume the retry budget of an event that can.

1. **A rule abandons its batch on the first miss.** Every rule's per-event loop returned on the first `ErrProcessNotYetMaterialized`. The demo corpus carries nine captured `network_connect` events whose fork/exec predate the capture, so their process rows never materialize. `dns_c2_beacon` resolves the flow's process *before* its suspicion gate, so those orphans reach the resolution step and raise the sentinel on every retry forever. The rule returned there and never reached the real beacon connect later in the same batch. The processor nacked and re-claimed every 500ms poll tick, but the orphan could never resolve, so the loop only advanced once that orphan aged out of its own grace window.

2. **The engine abandons the remaining rules on the first miss.** `Engine.Evaluate` returned on the first rule that reported the sentinel, so every rule after it in registration order was skipped for as long as that rule kept missing. The subject-process rules carry a 30s grace; `dns_c2_beacon` is registered last and carries a 5s grace. Its window was therefore routinely spent before it was evaluated even once. `evaluateRule` compounded this by discarding a rule's findings whenever the rule also reported a miss, because the error check ran before the persist loop.

   Measured consequence, on a passing run: the beacon alert landed 5.1s to 5.5s after its `network_connect` was ingested, against a 5.0s grace, while every other demo alert landed within 1.0s to 2.6s. Even the green runs had no margin. On the slower CI runner the margin was gone and the rule took its documented "past the grace, degrade to a silent skip" branch: no alert, no error, no retry, no log.

3. **PID-reuse close can stamp an exit before its own fork.** `CloseStaleProcess` closed *every* non-exited row for the pid at the incoming fork's timestamp. When concurrent claim batches (issue #535) split a fork/exec pair and deliver the exec's batch first, the exec synthesizes its row stamped at the exec time and the fork then arrives 10ms "earlier", so that row was closed at a timestamp before its own `fork_time_ns`:

   ```
   id   pid      path          fork_time_ns          exec_time_ns          exit_time_ns
   144  5107200  /tmp/.update  1785419760246319216   1785419760246319216   1785419760236319216
   439  5107200  /bin/zsh      1785419760236319216   NULL                  NULL
   ```

   That lifetime is impossible, and `GetProcessByPID`'s `exit_time_ns IS NULL OR exit_time_ns >= atNs` bound therefore skips the correctly exec-imaged row and returns the bare fork row, whose path is only the parent's. `dns_c2_beacon` reads `proc.Path` for its suspicion gate, so it declined `/bin/zsh` as unremarkable. That is a negative match, not a miss: no grace, no retry, no log, alert gone. This is what remained after defects 1 and 2 were fixed, and it reproduced the failure locally.

## What changes

- **A rule finishes its batch before reporting a miss.** `api.Rule.Evaluate`'s contract now requires it: evaluate every event, then return the findings that did resolve together with the first miss. A new `pendingMiss` helper in the catalog implements the policy, and every per-event rule loop uses it. Two loops that were open-coded copies of `evalEachEvent` now call it.
- **The engine evaluates every rule before reporting a miss,** and persists a rule's findings even when that rule also reported one. Non-retryable failures keep their existing semantics: a rule-evaluation error is logged and swallowed (per-rule isolation), an alert-persistence error still aborts immediately.
- **PID-reuse close only displaces generations that started earlier.** `CloseStaleProcess` gains a `fork_time_ns < closedAtNs` bound in both the store and the batch-session overlay, so an impossible lifetime can no longer be written. A row stamped at or after the incoming fork is a later generation that was merely processed first, not the generation being displaced.
- **The demo seeder's flow barrier waits for the exec-imaged row,** not merely for any row. Every consumer it gates keys off the exec'd image (the app-control block references the exec path; `dns_c2_beacon`'s gate reads `proc.Path`), so releasing the follow-up event against a bare fork row released it against a row that could not satisfy the rule.

### Not in this change

- The grace-window values. Both stay as they are: 30s for subject-process lookups, 5s for `dns_c2_beacon`'s flow lookup. The bug was that the beacon's window was being spent by other events before it was ever evaluated, not that 5s is too short.
- Folding a late-arriving fork into the exec-synthesized row it belongs to. The builder still writes two rows for that pid; with the close bound in place the ordering (`fork_time_ns DESC, id DESC`) resolves the exec-imaged one, which is correct. Merging them is a larger change to generation identity and is not needed to fix the loss.
- Treating a pre-exec (fork-only) row as a retryable miss inside the rule. A process that forks and never execs legitimately runs with its parent's image, so that would introduce false negatives; the barrier and the close bound remove the demo's exposure without changing detection semantics.

## Acceptance

- An unresolvable event in a batch does not prevent a resolvable event in the same batch from producing its finding, and the miss is still reported so the batch is retried.
- A retryable miss from one rule does not prevent the rules registered after it from being evaluated, and findings a rule resolved persist even when that rule also reported a miss.
- No process record is ever written with `exit_time_ns` earlier than its own `fork_time_ns`.
- The demo seeder's `dns_c2_beacon` alert lands with the rest of the demo alerts rather than at the flow-materialization grace boundary.

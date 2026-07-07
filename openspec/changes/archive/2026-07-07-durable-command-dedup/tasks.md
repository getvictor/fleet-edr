## 1. Spec delta

- [x] 1.1 This proposal plus the spec delta pass `openspec validate durable-command-dedup --strict`

## 2. Durable ledger

- [x] 2.1 `agent/commandledger`: SQLite store with Lookup / Mark / Prune, opened next to the event queue
- [x] 2.2 Unit tests: round-trip, upsert, prune-by-age, survives reopen (restart)

## 3. Shared executor dedup

- [x] 3.1 `commander.Executor` takes a `Ledger`; Execute replays a recorded terminal outcome, refuses to re-run a write-ahead claim, and records claim-then-outcome around the side effect
- [x] 3.2 Remove the control client's in-memory outcome cache (subsumed by the ledger)
- [x] 3.3 Wire one ledger into both `commander` (poll) and `controlclient` (push) in `cmd/fleet-edr-agent`; prune it on the existing loop
- [x] 3.4 Unit tests: dedup across two executors sharing a ledger, replayed failure, interrupted-claim-not-retried, no-ledger-still-executes

## 4. Manual verification

- [x] 4.1 Dev server (host-native agent enrolled against `task dev:server`): a kill_process executes once (victim killed, ledger row `completed`); a re-armed (re-delivered) command replays the recorded outcome with zero re-executions (status stays `completed`, not flipped to `failed`); and after an agent restart the persisted ledger still replays (zero re-executions)
- [x] 4.2 VM (edr-dev, agent against the host dev server over the bridge): a real kill_process executes once (VM victim killed, ledger row `completed`); a forced re-delivery replays with zero re-executions

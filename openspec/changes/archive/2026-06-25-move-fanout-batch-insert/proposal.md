# Move policy fan-out off the request hot path with batched inserts

## Why

When an operator mutates an application-control policy (`CreateRule` / `UpdateRule` / `DeleteRule` / `BulkUpsertRules`), the rules context fans the new snapshot out to every assigned host by enqueuing one `set_application_control` command per host. Today that fan-out runs a serial loop inside the request handler, doing one `INSERT INTO commands` round trip per host. Gemini Code Assist flagged this HIGH on PR #83: a fleet of N enrolled hosts means N serial inserts inside one synchronous HTTP request. At the post-MVP long-tail target of ~10k endpoints (ADR-0002) that is a multi-second-to-tens-of-seconds blocking mutation that can hit the server's 30s `WriteTimeout`, so the policy commits but the operator gets a 5xx and a hung UI.

The synchronous, in-request shape is otherwise desirable: the operator learns the per-host fan-out result (`fanout_hosts` / `fanout_failed`) in the same audit event, there is no cross-context transaction, and a missed host self-heals on its next poll. The only problem is the per-host round-trip count.

## What changes

- **The per-host insert loop becomes one bounded-size multi-row insert.** A new `response.Service.InsertBatch` enqueues one command row per host across a set of host IDs using chunked multi-row `INSERT` statements (chunk size 256), the same idiom detection already uses for `bulkInsertAlertEvents`. The application-control fan-out collects the resolved unique host set and calls it once instead of looping. 500 hosts go from 500 round trips to 2; 10k hosts from 10k round trips to ~40 (~400ms), comfortably inside the request budget. The fan-out stays synchronous and in-request: the operator still gets accurate counts in the same response and audit event.
- **`fanout_failed` accounting moves from per-host to per-batch.** A multi-row insert is atomic per statement, so a chunk either lands entirely or not at all. `fanout_failed` is now the count of unique hosts whose command did not land (`attempted - inserted`); when a chunk fails, every host in that chunk is counted as failed. The policy row is still authoritative and the missed hosts re-sync on their next poll, so the HTTP mutation still succeeds. `fanout_hosts` (total unique assigned hosts) is unchanged.

### Not in this change

- **The async / detached-goroutine fan-out path (issue #84 scope items 1-4).** Batched inserts complete the full enrolled fleet within one synchronous request across the entire roadmap scale (10-500 MVP, 10k long-tail), so the `FanoutAsync` detached goroutine, the `policy_fanout_jobs` table, the `GET /api/policy/fanout-jobs` endpoint, and the UI polling are unnecessary complexity here. They also change the operator-facing contract (202 + later results) and introduce in-process work that a replica restart would drop, which ADR-0010 (stateless server) discourages. Tripwire: revisit the async path if fan-out p99 latency ever approaches the `WriteTimeout`.
- **The `commands` table schema, the command wire payload, the at-most-once delivery contract, and the policy-epoch resync (#322).** This change is confined to the insert mechanism and the failure-count granularity; the rows produced are byte-identical to the per-host path.

## Impact

- Affected specs: `server-application-control` (the "Command fan-out on policy mutation" requirement).
- Affected code: `server/response/internal/mysql` (new `InsertBatch`), `server/response/internal/service` + `server/response/api` (new `InsertBatch` method on the response surface), `server/rules/internal/appcontrol` (fan-out switches to the batch closure), `server/rules/bootstrap` + `server/cmd/fleet-edr-server` (wire `InsertBatch` through instead of `Insert`).
- Operator-visible: none on the happy path. Under a fan-out failure the `fanout_failed` count now reflects the failed batch rather than individual hosts.

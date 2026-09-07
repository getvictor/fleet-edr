# Record that the alert-origin backfill finished

## Why

Closes #872, a follow-up #870 deliberately left open.

The backfill that credits alerts raised before attribution was recorded is gated by a leader lock, and a leader lock is the wrong tool for "once ever". `DoOnceIfLeader` releases the lock when its callback returns, so it excludes callers that OVERLAP rather than callers that REPEAT. Replicas in a rolling restart start in turn, so each one acquires the lock in turn and each runs the whole pass.

The pass is a scan of `alerts`, and it stays a scan. There is no index on `origin`, and `rule_id` sits third in the dedup key behind `source` and `host_id`, so the predicate cannot be satisfied by a lookup however it is written. #870 made that scan happen once per pass rather than once per batch by walking the primary key from a cursor. What it could not do is stop the pass happening at all, so today a deployment pays a scan on every boot, forever, including every boot after every row is already credited, multiplied by the number of replicas restarting.

Indexing is the obvious fix and it is the worse one. An index on `origin` would not help: this project's own rules keep an empty origin permanently and on purpose, so `origin = ''` stays a high-cardinality match rather than emptying out after the first pass. An index on `rule_id` would help, and would tax every alert `INSERT` on the hot detection path for the life of the deployment to save a scan on a leader-only boot path that runs off the request path while the server is still coming up.

## What changes

- A backfill records that it completed, and a later boot skips it on a primary-key lookup rather than scanning `alerts`.
- Completion is recorded only after the pass returns successfully, so a pass that fails or is cut short by shutdown is retried on the next boot.
- The marker is checked twice: once before taking the lock, which is what removes the scan, and once inside it, which is what makes the guarantee hold when two replicas start at the same moment rather than in sequence.

## Impact

- Affected specs: `server-detection-rules-engine`
- Affected code: `server/detection/migrations/`, `server/detection/internal/mysql/alertorigins.go`, `server/detection/bootstrap/bootstrap.go`

Recording completion is sound because the population is closed: every alert written since attribution shipped carries an origin, so no new uncredited row can appear behind a finished pass. It does mean the pass no longer picks up an alert that becomes creditable LATER, when a rule absent from the corpus at the time returns to it. Those rows are the ones this pass cannot see anyway, which is #871, and the record of who wrote a rule that is no longer present is what that issue needs and what would let a second, differently-scoped pass credit them.

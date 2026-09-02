# A rule identifier that cannot be persisted is refused at load

Fixes #832.

## The defect

Every `rule_id` column in the tree is `VARCHAR(64)`, and nothing validates identifier length anywhere:

| Table | Migration |
| --- | --- |
| `alerts` | `server/detection/migrations/00001_initial.sql:65` |
| `detection_rule_settings` | `server/rules/migrations/00002_detection_config.sql:14` |
| `detection_exclusions` | `server/rules/migrations/00002_detection_config.sql:30` |
| `detection_rule_match_counts` | `server/rules/migrations/00004_rule_match_counts.sql:20` |

The SigmaHQ rules imported by #764 derive their identifiers from upstream filenames, and one shipped rule exceeds that: `proc_creation_macos_remote_access_tools_teamviewer_incoming_connection`, at 70 characters. Measured across the catalog: 79 rules, one over 64, longest 70. So there is one today and no headroom.

MySQL in strict mode rejects the write rather than truncating.

## Why this is a detection outage, not a dropped counter

Filed as a counter problem; it is worse. Each link verified in the code:

1. A monitor-mode match writes `detection_rule_match_counts`, which fails, and the recorder logs and drops it by design. So #813's promotion evidence is silently missing for that rule, and an operator sees a rule that appears never to have fired.
2. Promoting it is worse. Alert persistence is deliberately NOT isolated per rule, so `routeFinding`'s error propagates through `evaluateRule` and `Engine.Evaluate` as a non-retryable error, whose own comment reads "The batch will be nacked and replayed".
3. `Nack` is `UPDATE event_queue SET processed = 0, claimed_at_ns = 0`. No attempt counter, no dead-letter, no abandonment.

So the batch is re-claimed and fails again indefinitely, and **that host's queue stops draining entirely**. Detection for the host ends, not just for the offending rule.

The trigger is the documented workflow: all 55 imported rules ship in monitor mode, and #813 exists to help promote them.

## Approach

Two halves, and the second is the one that keeps this from recurring.

**One permitted length, defined once.** `api.MaxRuleIDLen`, which the four columns are widened to match and which the loader validates against. Four independent literals is what let them drift from the corpus in the first place.

255, not the 70 that would just fit. The identifiers come from an upstream corpus whose names are outside our control, so the width needs headroom that a future import does not exhaust; the load-time refusal is what catches anything beyond it. 255 is also already the convention for `host_id` here.

**Refusal at load.** The pack loader already refuses an empty identifier and a duplicate one, and this joins them. A rule that cannot persist an alert must not reach the registry, because presenting it as promotable offers the operator an action whose consequence is a detection outage. A catalog-wide test measures every shipped rule against the limit, so the condition is caught in CI rather than at boot.

## Migration safety, measured rather than assumed

`alerts` already holds data, so the widening was tested against the pinned engine (MySQL 8.4.9) before being written:

- `ALTER TABLE alerts MODIFY rule_id VARCHAR(255) NOT NULL, ALGORITHM=INPLACE, LOCK=NONE` is **accepted**: no table rebuild, no blocking. That is not luck. `utf8mb4` `VARCHAR(64)` is 256 octets, already past the 255-byte threshold where InnoDB switches to a two-byte length prefix, and `VARCHAR(255)` at 1020 octets keeps that same prefix. Had the column been `VARCHAR(63)` or narrower, the same widening would have forced a copy.
- The three indexed columns accept it too, so no index key exceeds the limit at the wider size.
- The reverse is NOT free: narrowing back to 64 is rejected INPLACE and needs `ALGORITHM=COPY`. The Down migrations say so.

The algorithm is stated explicitly rather than left to the engine. A boot-time `ALTER` that silently falls back to a copy takes a write lock on `alerts` on a live ingest path; one that fails loudly is a server that does not start, which is visible and fixable. That is the better failure.

One trap found by testing rather than reading: `MODIFY COLUMN` restates the whole definition, so a plain widening **drops** `detection_exclusions.rule_id`'s `DEFAULT ''`. That sentinel is load-bearing (migration 00002's own comment says it keeps the `(rule_id, host_group_id)` uniqueness honest for the global row), so that column's widening carries the default forward explicitly.

## A reachability finding worth recording

The imported loader's guard cannot fire for the production corpus, and that was discovered by trying to test it rather than by reading it. Writing a file whose stem is over the limit fails with "file name too long": a filesystem caps one path component at 255 bytes, so an imported identifier, which is the filename stem, cannot exceed about 251 characters on disk. The shipped corpus is a `go:embed` of a real directory tree, so that bound already sits below the limit.

The guard is kept, and tested through an in-memory FS, which is the one shape that can express the case. `loadImported` takes an `fs.FS` rather than a directory, and the runtime rule-pack loading in #766 is precisely a corpus that does not come from a filesystem. Deleting the call site as unreachable would mean rediscovering the need from a defect instead of a test.

The pack loader's guard is reachable today without qualification: `x-engine.rule_id` is arbitrary text in a YAML file, bounded by nothing.

## Not in this change

The unbounded nack loop is a separate defect and is filed separately. Any deterministic persistence failure wedges a host's queue with no attempt cap and nothing that surfaces it as stuck; this change removes one cause, not the class. Fixing queue semantics belongs with the queue contract rather than riding along here.

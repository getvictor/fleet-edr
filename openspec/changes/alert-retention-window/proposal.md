# Give alerts a retention window

Issue #995. Lands before #994, which persists monitor-mode matches as alert-shaped records and needs a pruning mechanism for them to exist first.

## The problem

Nothing deleted alerts. `EDR_RETENTION_DAYS` covers the rows the server derives and can rebuild, and alerts are in none of those sets. The growth is not confined to the alerts table either: the process prune correctly keeps any process record an alert references, so every alert pinned its process record for the life of the deployment. On the dogfood host that is 384 alerts in 7 days from one host, against a product sized for 10 to 500 endpoints.

There is a compliance edge as well. Frameworks such as PCI DSS expect a stated retention period for security event data. "Indefinite, because nothing deletes them" is not a period anyone stated.

## What changes

A new knob, `EDR_ALERT_RETENTION_DAYS`, default 180, prunes alerts on the existing hourly retention pass. By default it is the longest tier: raw events are 30 days (ClickHouse TTL) and derived records 30 days (`EDR_RETENTION_DAYS`). `0` disables it. Both windows are capped at 36,500 days, because a larger value wraps negative once converted to a duration and would put the cutoff in the future.

## Decisions worth a reviewer's attention

**Age is measured from last triage activity (`updated_at`), not creation.** An alert an analyst acknowledged yesterday is an investigation in progress, and deleting it because it was raised 181 days ago would take evidence out from under them. A re-fire deliberately does not touch `updated_at` (the dedup path says so), so a standing condition nobody triages still ages out, and its next re-fire raises a fresh alert.

**The two windows are independent in both directions.** The runner's loop used to exit whenever the process window was 0, which was right while that was its only job. Left as is, it would have silently disabled alert pruning for every operator who turned process pruning off for a forensic hold.

**Alerts are pruned before processes in a pass**, so a process record an expired alert was holding is collected in the same pass rather than an hour later.

**Each batch is a transaction.** `alert_events` references `alerts` with no `ON DELETE CASCADE`, and every alert has linked events, so a plain `DELETE FROM alerts` fails on its first row with a foreign-key violation. Removing the links first in the same transaction means a batch that fails part way leaves its alerts whole. The selected alerts are locked before the links are touched. Without that, a re-fire that already holds the alert row deadlocks against the prune, and InnoDB rolls back the detection write.

**Crediting an alert keeps its `updated_at`.** The boot-time origin backfill updated `origin` without setting `updated_at`, so the column refreshed itself and every old alert it credited would have started a fresh retention window.

**A new index on `alerts(updated_at)`**, the counterpart to the index the process prune already has. Without it each batch is a full scan and the `FOR UPDATE` would lock every row scanned.

## Out of scope

Archiving to cold storage before deletion, and per-severity windows. Both additive later.

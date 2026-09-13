# Tasks

- [x] Migration: `disposition` column, dedup key including it, index for the disposition-scoped prune and default list
- [x] Engine persists a monitor-mode finding as a monitor record, keeping the counter; alert-mode findings unchanged
- [x] No webhook delivery, alert-created metric, or alert log line for a monitor record
- [x] `GET /api/alerts` defaults to alerts, `disposition` and `rule_id` filters, unknown disposition rejected
- [x] Status change on a monitor record refused
- [x] `EDR_MONITOR_RETENTION_DAYS`, default 7, capped, independent; alert prune scoped to alerts
- [x] Monitor-record rows-deleted metric
- [x] Docs: install table, operations, OpenAPI, CHANGELOG
- [x] Mutation-check the dedup key, the default filter, the prune scoping, and the webhook gate
- [x] Manual QA on the dev server with SigNoz

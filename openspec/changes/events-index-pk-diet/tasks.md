# Events index and primary-key diet: tasks

## 1. Schema

- [ ] Migration `00005_events_drop_redundant_indexes.sql`: `DROP INDEX idx_events_host_id` and `DROP INDEX idx_events_type` on `events` (goose up; down recreates them). Comment the subsumption rationale.
- [ ] Migration `00006_events_surrogate_pk.sql`: drop the `event_id` primary key, add `UNIQUE KEY uk_events_event_id (event_id)`, add `id BIGINT AUTO_INCREMENT PRIMARY KEY` as the first column. Comment the table-rebuild cost and the FK-targets-unique-key fact. Down is a no-op (forward-only, ADR-0009).

## 2. Code audit

- [ ] Confirm no code references the redundant indexes by name and no code assumes `event_id` is the physical primary key. The insert path (`INSERT IGNORE`), `alert_events` FK, retention delete, and all `event_id` reads are unchanged by construction; add a regression test only where a behavior could silently change.

## 3. Spec

- [ ] `server-event-ingestion` delta: MODIFIED "Idempotent submission by event_id" to state `event_id` remains the logical unique key while the physical row is keyed by a compact surrogate; ADDED "Event storage keeps secondary indexes compact".

## 4. Tests

- [ ] Integration test (real MySQL, post-migration schema): inserting a duplicate `event_id` is still ignored; `alert_events` linking + the alert-detail event read still resolve; the `GetNetworkEventsForProcess` correlation query still returns rows. Confirm `INFORMATION_SCHEMA.STATISTICS` shows `idx_events_host_id` / `idx_events_type` gone and `uk_events_event_id` + surrogate PK present.

## 5. Verification

- [ ] `go build ./server/...`; `go test -tags integration ./server/detection/internal/tests/...` green (full migration set applies cleanly).
- [ ] gofmt, `task lint:go`, `openspec validate events-index-pk-diet --strict`, markdown + dash lints.
- [ ] Dev-server: apply migrations against a populated dev DB, confirm ingest + alerts + host tree still work; capture before/after `events` index size.

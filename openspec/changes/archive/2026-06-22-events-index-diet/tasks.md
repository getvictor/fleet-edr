# Events index diet: tasks

## 1. Schema

- [x] Migration `00005_events_drop_redundant_indexes.sql`: `DROP INDEX idx_events_host_id` and `DROP INDEX idx_events_type` on `events` (goose up; down recreates them). Comment the subsumption rationale.
- [x] No primary-key migration: the surrogate-PK swap was implemented as `00006` and then reverted because it deadlocked the multi-replica `FOR UPDATE SKIP LOCKED` claim (see proposal). `event_id` stays the primary key.

## 2. Code audit

- [x] Confirm no code references the redundant indexes by name. The insert path (`INSERT IGNORE`), `alert_events` FK, retention delete, and all `event_id` reads are unchanged by construction.

## 3. Spec

- [x] `server-event-ingestion` delta: ADDED "Event storage drops redundant indexes" (no MODIFIED requirement: `event_id` remains the primary key, so the canonical idempotency requirement is unchanged).

## 4. Tests

- [x] Integration test (`TestEvents_SchemaDiet`, real MySQL): `INFORMATION_SCHEMA.STATISTICS` shows `idx_events_host_id` / `idx_events_type` gone, the query-backing indexes present, and `event_id` still the primary key. Duplicate-`event_id` idempotency, `alert_events` linking, and the network-correlation query are covered by the existing ingest/alert/correlation integration tests against the migrated schema.

## 5. Verification

- [ ] `go build ./server/...`; `go test -tags integration ./server/detection/internal/tests/...` green (full migration set applies cleanly).
- [ ] gofmt, `task lint:go`, `openspec validate events-index-diet --strict`, markdown + dash lints.
- [ ] Dev-server: apply migrations against a populated dev DB, confirm ingest + alerts + host tree still work; capture before/after `events` index size.

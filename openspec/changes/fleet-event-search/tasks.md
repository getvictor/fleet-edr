## 1. Archive interface + fake

- [x] 1.1 `server/visibility/api`: `EventSearchFilter` (event type, value, host_id, from/to) + `EventSearchResult` (events, next_cursor, total_matched); add `SearchEvents(ctx, filter, cursor, limit)` to the `EventArchive` interface
- [x] 1.2 `server/visibility/testkit` MemArchive: implement `SearchEvents` (mirror ClickHouse read semantics: event-type + JSON value + host + ingest window, newest-first, keyset over timestamp/event_id)

## 2. ClickHouse

- [x] 2.1 Migration: add `remote_address` and `query_name` MATERIALIZED columns + bloom-filter skip indexes; `MATERIALIZE` both to backfill (idiom of 00002)
- [x] 2.2 `store.go`: `SearchEvents` querying the materialized column for the event type, FINAL, ingest-window bounded, keyset `(timestamp_ns, event_id) < (?, ?)` DESC, `total_matched` COUNT companion; opaque `timestamp_ns:event_id` cursor codec
- [x] 2.3 Integration test (real ClickHouse): by-IP + by-domain across hosts, host scoping, keyset-pagination completeness, missing-value guard (spec markers `connection-search-finds-a-remote-address-across-hosts`, `dns-search-finds-a-query-name-across-hosts`, `host-filter-scopes-the-search`, `keyset-pagination-is-stable-and-complete`)

## 3. Detection delegate + handlers

- [x] 3.1 `mysql.Store.SearchEvents` thin delegate to `s.archive.SearchEvents` (mirrors GetNetworkEventsForProcess)
- [x] 3.2 `event_search_handler.go`: `EventSearchReader` seam + `SetEventSearch` + routes `GET /api/search/connections` and `/dns`, process-read gate, param parse + 400 on missing value / malformed cursor / bad window; bootstrap wiring
- [x] 3.3 Handler tests with the MemArchive: per-route event type, missing value 400, malformed cursor 400, unwired 503, authz deny (spec marker `missing-artifact-value-is-rejected`)

## 4. Verification

- [x] 4.1 `go test ./server/visibility/... ./server/detection/...` + integration with `EDR_TEST_DSN` and `EDR_CLICKHOUSE_TEST_DSN`, `go vet -tags integration ./...`, `task lint:go`, `tools/spectrace check --strict`, `openspec validate --all --strict`
- [x] 4.2 Manual QA on the dev server: seed connection/dns events, curl `/api/search/connections` and `/dns` fleet-wide and host-scoped, verify cursor paging + total_matched + missing-value 400

## 5. Docs

- [x] 5.1 CHANGELOG entry under 0.4.0

## 1. Visibility archive query

- [x] 1.1 `server/visibility/api/eventarchive.go`: add `HostTimelineFilter` ({HostID, FromNs, ToNs, EventTypes []string, Text string}) and `HostTimeline(ctx, filter, cursor, limit) (EventSearchResult, error)` to the `EventArchive` interface; reuse `EventCursor`/`ErrInvalidEventCursor`. Define the supported-event-type allowlist in one place.
- [x] 1.2 `server/visibility/internal/clickhouse/store.go`: implement `HostTimeline` (host + `event_type IN` + `timestamp_ns` window + optional `positionCaseInsensitiveUTF8(payload, ?)` text, keyset over `(timestamp_ns, event_id)` DESC, COUNT for total).
- [x] 1.3 `server/visibility/testkit/mem_archive.go`: implement `HostTimeline` on the fake (reuse `eventNewer`/`eventBeforeCursor`; add a timeline match predicate).

## 2. Detection delegate + endpoint

- [x] 2.1 `server/detection/internal/mysql/processes.go`: `HostTimeline` delegating to the injected archive (like `SearchEvents`).
- [x] 2.2 `server/detection/internal/operator/host_timeline_handler.go`: `HostTimelineReader` seam + `SetHostTimeline` + `registerHostTimelineRoutes` + `handleHostTimeline` (parse from/to/type/text/cursor/limit, gate `ActionProcessRead` Resource{process, hostID}, 400 on bad type/cursor, 503 when unset).
- [x] 2.3 Register the route in the operator handler and wire `SetHostTimeline(store)` in `server/detection/bootstrap/bootstrap.go` ModeFull.

## 3. Tests

- [x] 3.1 Handler tests: interleaving order across the three classes, type filter, text match, pagination stability/completeness, unknown-type 400, malformed-cursor 400, 503 when unset (spec markers `server-rest-api/host-event-timeline/*`).
- [x] 3.2 Archive-level test for `HostTimeline` (mem archive + a ClickHouse-backed integration test if the search tests already run one).

## 4. Verification

- [x] 4.1 `go test ./server/...`, `go vet -tags integration ./...`, `task lint:go`, `tools/spectrace check --strict`, `openspec validate --all --strict`.
- [x] 4.2 Manual QA on the dev server: `GET /api/hosts/{host_id}/timeline` against the seeded QA host events (type filter, text match, paging).

## 5. Docs

- [x] 5.1 CHANGELOG entry under 0.4.0.

# Tasks

## Envelope and constants

- [x] Add the `Platform` field to `server/visibility/api/event.go` (`db:"platform" json:"platform,omitempty"`).
- [x] Add `PlatformDarwin/PlatformWindows/PlatformLinux`, `IsValidPlatform`, and `NormalizePlatform` in `server/visibility/api`.
- [x] Re-export the platform constants and helpers from `server/detection/api`.
- [x] Add the optional `platform` enum property to `schema/events.json` (not required).

## Ingest validation

- [x] Validate a non-empty platform and reject an unknown value (`invalid_platform_at_<i>`) in `server/detection/internal/intake/handler.go`.
- [x] Normalize an absent platform to darwin before append.
- [x] Update the fuzz contract and seeds in `handler_fuzz_test.go`.

## Stores

- [x] Migration `server/visibility/migrations/00002_event_queue_platform.sql` plus the append and claim paths in `eventlog/store.go`.
- [x] Migration `server/visibility/migrations-clickhouse/00003_events_platform.sql` plus the insert and read paths in `clickhouse/store.go`.

## Extension

- [x] Stamp `platform: "darwin"` in the ESF and network-extension serializers and regenerate the corpus goldens.

## Tests

- [x] Extend the wire PBT round-trip with the platform field.
- [x] Table-driven intake tests for accept, normalize, and reject.
- [x] Fan-out test that platform reaches the work queue.
- [x] Store round-trip coverage for the queue and the archive.
- [x] Swift serializer tests assert the darwin platform.

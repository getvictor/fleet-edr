## Why

The EDR is macOS-only today, and the event contract shows it: the envelope in `schema/events.json` has no field naming the operating system that produced an event, and the detection engine applies every rule to every event. ADR-0018 decides a phased Windows agent, and its Phase 0 is a platform-agnostic contract that must land before any second-platform sensor. This change adds the platform discriminator to the event pipeline so the server can tell a macOS event from a Windows or Linux one, persist that distinction through both event stores, and (in a following change) scope detection rules by it. Doing this first, additively, avoids baking a macOS assumption deeper into the contract every agent inherits.

## What changes

- Add an optional `platform` field to the event envelope (`schema/events.json` and the canonical `visibility/api.Event` struct), one of `darwin`, `windows`, or `linux`. It is optional on the wire: an agent predating this contract omits it.
- Validate and normalize platform at ingest. A recognized value is accepted as-is, an unrecognized non-empty value is rejected with `invalid_platform_at_<i>`, and an absent value is normalized to `darwin` (the legacy-agent default, since every deployed agent is macOS-only). Every stored and enqueued event therefore carries a concrete platform.
- Persist platform through both event stores (ADR-0015): a new `platform` column on the MySQL `event_queue` work queue so it survives the claim to rule evaluation, and on the ClickHouse `events` archive so alert-evidence reads return the full platform-tagged envelope.
- Stamp `platform: "darwin"` in the macOS system extension serializers (the ESF and network-extension envelope producers), so the producer contract is honest going forward while the server-side normalization keeps every already-deployed agent working with no release dependency.

Out of scope, tracked as follow-ups: platform on the host inventory and UI (a separate change), platform-scoped rule evaluation (a separate change), and the process-identity and signing abstractions ADR-0018 specifies for the Windows sensor.

## Capabilities

### Modified capabilities

- `server-event-ingestion`: the ingest path accepts an optional platform on each event, rejects an unknown value, normalizes an absent value to darwin, and persists platform through the work queue and the archive so downstream processing observes it.
- `endpoint-event-collection`: the macOS extension serializers stamp the platform on every event envelope they produce.

## Impact

- Code (server): `server/visibility/api/event.go` (a `Platform` field on `Event`) plus new platform constants and helpers in `server/visibility/api`; validation and normalization in `server/detection/internal/intake/handler.go`; a new work-queue migration `server/visibility/migrations/00002_event_queue_platform.sql` with the append and claim paths in `server/visibility/internal/eventlog/store.go`; a new archive migration `server/visibility/migrations-clickhouse/00003_events_platform.sql` with the insert and read paths in `server/visibility/internal/clickhouse/store.go`; a re-export of the platform helpers in `server/detection/api`.
- Code (extension): `platform` on the `EventEnvelope` in `extension/edr/extension/EventSerializer.swift` and `extension/edr/networkextension/NetworkEventSerializer.swift`, stamped `darwin`.
- Data: two additive migrations, each a nullable-by-default column (`NOT NULL DEFAULT ''`). No backfill: a row written before the migration reads back as the empty default, which consumers treat as darwin. Rollback drops the columns.
- Wire: the envelope gains an optional `platform` key. The shape stays byte-identical for a legacy agent that never sets it (the field is `omitempty`), so no agent and server version lockstep is required.
- Schema: `schema/events.json` gains an optional `platform` enum property (not in the required set). The corpus wire-shape goldens are regenerated to carry `platform: "darwin"`.

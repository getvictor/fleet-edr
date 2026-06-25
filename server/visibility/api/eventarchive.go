package api

import (
	"context"

	"github.com/fleetdm/edr/server/httpserver"
)

// EventArchive is the durable, append-mostly event lake: the source of truth for per-process correlation and, in v0.5.0, hunting and
// investigation queries. Ingestion writes every accepted event here; the archive ages events out by a time-based retention window.
//
// Invariants every implementation MUST uphold:
//   - Durable before ack: an event is considered persisted only once Insert returns nil.
//   - Idempotent by EventID: re-inserting an event with a known EventID never surfaces a duplicate in query results and never alters
//     the stored content, so at-least-once delivery is safe.
//
// The v0.4.0 implementation is ClickHouse; reads serve correlation today and hunting later. Writes are batched, never synchronous
// per request, so the interface says nothing about per-call batching.
type EventArchive interface {
	// Insert durably stores events in the archive. Idempotent by EventID.
	Insert(ctx context.Context, events []Event) error

	// NetworkEventsForProcess returns the network_connect and dns_query events attributed to (hostID, pid) within tr, ordered by
	// timestamp. Cross-stream correlation rules and the process-detail view consume it to join a process's DNS resolutions with its
	// outbound connections.
	NetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr httpserver.TimeRange) ([]Event, error)
}

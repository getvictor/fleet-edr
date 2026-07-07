package api

import (
	"context"
	"errors"

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

	// EventsByIDs returns the full envelopes for the given event_ids, ordered by (timestamp_ns, event_id). Alert evidence capture uses
	// it to snapshot a finding's triggering events into durable per-alert storage (alert_event_payloads) that outlives the archive's
	// retention window. IDs with no surviving event (already aged out) are omitted rather than erroring, so capture stays best-effort.
	EventsByIDs(ctx context.Context, eventIDs []string) ([]Event, error)

	// SearchEvents runs the fleet-wide hunting search over the archive (issue #582): events of filter.EventType whose artifact value
	// matches (remote address for network_connect, query name for dns_query), newest-first, keyset-paged from cursor. Returns up to
	// limit events, a next cursor when more remain, and total_matched (the full match count independent of the page). A malformed
	// cursor is a caller error.
	SearchEvents(ctx context.Context, filter EventSearchFilter, cursor string, limit int) (EventSearchResult, error)

	// HostTimeline returns one host's investigation events (exec, network_connect, dns_query) interleaved in event-time order,
	// newest-first, over the filter's event-time window, optionally narrowed to a subset of those types and to a case-insensitive
	// payload substring (issue #583). Keyset-paged over (timestamp_ns, event_id) from cursor, up to limit events, with a next cursor
	// when more remain and total_matched independent of the page. Shares the EventSearchResult page shape and EventCursor codec with
	// SearchEvents. A malformed cursor is a caller error.
	HostTimeline(ctx context.Context, filter HostTimelineFilter, cursor string, limit int) (EventSearchResult, error)
}

// HostTimelineFilter selects events for one host's merged event timeline (issue #583). HostID is required. FromNs/ToNs bound event
// time (timestamp_ns, what the host page's time window means), zero meaning unbounded on that side. EventTypes narrows to a subset of
// the timeline event classes (empty means all of them). Text, when non-empty, keeps only events whose raw payload contains it
// case-insensitively. Chain, when non-empty, scopes the timeline to a set of process generations (the alert chain), so it mirrors the
// graph's focus. Empty means no chain scope (the full host stream).
type HostTimelineFilter struct {
	HostID     string
	FromNs     int64
	ToNs       int64
	EventTypes []string
	Text       string
	Chain      []ProcessGeneration
}

// ProcessGeneration identifies one process generation by its pid AND kernel pid-generation (pidversion, audit_token_to_pidversion). The
// pair is unique across PID reuse: pid 450 may be bash then curl then orbit within one window, each a distinct pidversion, so matching
// (pid, pidversion) scopes to the exact generation the graph shows. This is robust to ingest timing (a short-lived process whose fork
// and exit land in one batch still matches all its events) where an ingest-time window would collapse to near-zero and drop them.
type ProcessGeneration struct {
	PID        int64
	PIDVersion int64
}

// EventSearchFilter selects events for the fleet-wide connection/DNS search (issue #582). EventType picks the artifact class
// (network_connect matches on remote address, dns_query on query name); Value is the exact artifact to match. HostID empty means every
// host. FromNs/ToNs bound ingest time; zero means unbounded on that side.
type EventSearchFilter struct {
	EventType string
	Value     string
	HostID    string
	FromNs    int64
	ToNs      int64
}

// EventSearchResult is one page of a fleet-wide event search plus pagination and total metadata. NextCursor is empty on the last
// page; TotalMatched counts every matching event independent of the page, or is TotalNotCounted when the count was deliberately
// skipped (see below).
type EventSearchResult struct {
	Events       []Event `json:"events"`
	NextCursor   string  `json:"next_cursor,omitempty"`
	TotalMatched int64   `json:"total_matched"`
}

// TotalNotCounted marks TotalMatched as "not computed". The recent-events listing (an event search with no artifact value) skips the
// COUNT query, which on a large archive is the more expensive half of the page and yields a grand total of only marginal value for a
// browse view; pagination is driven by NextCursor, not the total, so nothing depends on it. A filtered search still reports the exact
// count. The UI shows "Showing N" instead of "Showing N of M" when it sees this sentinel.
const TotalNotCounted int64 = -1

// ErrInvalidEventCursor is returned by SearchEvents when the pagination cursor does not decode. The operator handler maps it to 400.
var ErrInvalidEventCursor = errors.New("visibility: invalid event search cursor")

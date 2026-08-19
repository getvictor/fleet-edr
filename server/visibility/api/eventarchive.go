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
	// timestamp. Cross-stream correlation rules consume it to join a process's DNS resolutions with its outbound connections, keyed on
	// pid alone because they re-correlate the results in memory.
	//
	// The process-detail view uses NetworkEventsForGeneration instead: a view that names ONE generation must not answer with a
	// sibling generation's flows.
	NetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr httpserver.TimeRange) ([]Event, error)

	// NetworkEventsForGeneration returns the network_connect and dns_query events belonging to ONE process generation, ordered by
	// timestamp. See ProcessFlowFilter for how a flow is attributed to a generation.
	NetworkEventsForGeneration(ctx context.Context, filter ProcessFlowFilter) ([]Event, error)

	// EventsByTypeForHost returns one host's events of a single type whose EVENT time falls inside tr, oldest first. Narrow by
	// construction: (host_id, event_type, timestamp_ns) is the archive's sorting-key prefix, so the read is a primary-key range
	// scan rather than a filter over the host's whole stream.
	//
	// Event time, not ingest time, because the caller (the sensor-tamper rule) measures the gap BETWEEN two events from the same
	// producer on one host. Those share a clock, so event time is the honest measure of that gap, and it is also the indexed one.
	// The cross-stream reads above bound on ingest time instead because they join two different producers whose clocks drift.
	//
	// Bounded, and the bound is REPORTED: a result larger than the implementation's cap returns ErrEventsTruncated rather than a
	// truncated page, because a caller reasoning about what is ABSENT cannot tell a missing event from a dropped one.
	EventsByTypeForHost(ctx context.Context, hostID, eventType string, tr httpserver.TimeRange) ([]Event, error)

	// EventsByIDs returns the full envelopes for the given event_ids, ordered by (timestamp_ns, event_id). Alert evidence capture uses
	// it to snapshot a finding's triggering events into durable per-alert storage (alert_event_payloads) that outlives the archive's
	// retention window. IDs with no surviving event (already aged out) are omitted rather than erroring, so capture stays best-effort.
	EventsByIDs(ctx context.Context, eventIDs []string) ([]Event, error)

	// SearchEvents runs the fleet-wide hunting search over the archive (issue #582): events of filter.EventType whose artifact value
	// matches (remote address for network_connect, query name for dns_query), newest-first, keyset-paged from cursor. Returns up to
	// limit events, a next cursor when more remain, and total_matched (the full match count independent of the page). A malformed
	// cursor is a caller error.
	SearchEvents(ctx context.Context, filter EventSearchFilter, cursor string, limit int) (EventSearchResult, error)

	// TelemetryActivityForHosts reports, per host, whether each telemetry stream produced anything inside tr. It answers a
	// question about ABSENCE (issue #677: a network-extension provider that wedges keeps reporting itself healthy, and the only
	// evidence is that its events stopped arriving while process telemetry kept flowing), so it counts rather than returning
	// events: the caller needs "did this stream produce anything", not the events themselves.
	//
	// Hosts with no events in the range are ABSENT from the result rather than present with zeroes. A caller must not read that
	// absence as silence: an unknown host and a host that produced nothing are indistinguishable here, and neither is evidence of
	// a wedge (the wedge claim requires positive process activity, which an absent host by definition lacks).
	TelemetryActivityForHosts(ctx context.Context, hostIDs []string, tr httpserver.TimeRange) (map[string]TelemetryActivity, error)

	// HostTimeline returns one host's investigation events (exec, network_connect, dns_query) interleaved in event-time order,
	// newest-first, over the filter's event-time window, optionally narrowed to a subset of those types and to a case-insensitive
	// payload substring (issue #583). Keyset-paged over (timestamp_ns, event_id) from cursor, up to limit events, with a next cursor
	// when more remain and total_matched independent of the page. Shares the EventSearchResult page shape and EventCursor codec with
	// SearchEvents. A malformed cursor is a caller error.
	HostTimeline(ctx context.Context, filter HostTimelineFilter, cursor string, limit int) (EventSearchResult, error)
}

// TelemetryActivity is one host's per-stream event presence over a telemetry-freshness window.
//
// The counts are NOT deduplicated against the archive's ReplacingMergeTree duplicates, and deliberately so: every decision made from
// this type is "did this stream produce anything at all", which a duplicate cannot flip in either direction. Only ProcessInWindow is
// read as a magnitude, and only to describe the contradiction to a human, where an occasional re-inserted event is immaterial.
type TelemetryActivity struct {
	// ProcessInWindow counts exec and fork events: the evidence the host is awake and doing work, which is what makes an empty
	// flow stream a contradiction rather than an idle machine.
	ProcessInWindow int64
	// ConnectInWindow and DNSInWindow count each flow stream. Zero is the signal.
	ConnectInWindow int64
	DNSInWindow     int64
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

// ProcessFlowFilter selects the network_connect and dns_query events belonging to ONE process generation, for the process-detail view
// (issue #716). A flow is attributed to the generation when EITHER of two arms matches:
//
//   - Identity: the flow's payload carries a pidversion and (pid, pidversion) equals this generation's. This arm is deliberately NOT
//     bounded by IngestWindow. The pair is unique across PID reuse, so no window is needed to disambiguate, and requiring one is the
//     #716 defect: a flow and its process's exit travel up the agent uploader in separate batches, so a short-lived process's flow
//     routinely ingests seconds AFTER the exit and falls outside any tight window.
//   - Legacy: the flow's payload carries NO pidversion (a pre-#403 agent, or a flow whose audit token was unavailable), and its
//     ingest time falls inside IngestWindow. Identity cannot speak for these, so the window remains the only available evidence.
//
// PIDVersion nil means the PROCESS row predates pidversion capture. Identity is then unavailable on this side too, so every candidate
// flow is judged by IngestWindow alone, which is the pre-#716 behavior.
//
// Bound applies to every candidate row in both arms. It exists to keep the scan pruned rather than to decide attribution, so it is
// wide where IngestWindow is tight; an implementation MUST NOT narrow attribution with it.
type ProcessFlowFilter struct {
	HostID string
	PID    int
	// PIDVersion is the generation's kernel pid generation, nil when the process row carries none.
	PIDVersion *int64
	// Bound is the wide ingest bound applied to every candidate row, for scan pruning only.
	Bound httpserver.TimeRange
	// IngestWindow is the tight ingest window that attributes flows the identity arm cannot speak for.
	IngestWindow httpserver.TimeRange
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

// ErrEventsTruncated is returned by a bounded read that matched more rows than its cap. It exists so a caller cannot mistake a
// truncated result for a complete one. The sensor-tamper rule is why: it decides "capture never came back" from the ABSENCE of a
// recovery in its window, so a silently truncated page would let a host that recovered be reported as tampered with, and the more
// events a host emits the likelier that becomes. Failing the read loudly turns a hostile or noisy agent into an error an operator
// sees rather than a false accusation against that host.
var ErrEventsTruncated = errors.New("visibility: event read exceeded its row cap")

// ErrInvalidEventCursor is returned by SearchEvents when the pagination cursor does not decode. The operator handler maps it to 400.
var ErrInvalidEventCursor = errors.New("visibility: invalid event search cursor")

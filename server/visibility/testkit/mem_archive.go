package testkit

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/visibility/api"
)

// MemArchive is an in-memory EventArchive for tests: it satisfies the visibility EventArchive contract without a ClickHouse container,
// so detection rule, graph, and alert tests can seed correlation + evidence reads cheaply. The real ClickHouse archive is exercised by
// the visibility and detection integration tests. Safe for concurrent use: the integration harness drives it through the real intake
// handler, which serves concurrent requests, so every method takes a mutex (the real archive is likewise concurrency-safe).
//
// It mirrors the ClickHouse store's read semantics: idempotent by event_id (last write wins, like ReplacingMergeTree collapsed under
// FINAL), the network correlation read filters on host + event_type + the payload pid + the ingested_at_ns window, and EventsByIDs
// returns the surviving envelopes ordered by (timestamp_ns, event_id).
type MemArchive struct {
	mu    sync.Mutex
	byID  map[string]api.Event
	order []string // event_ids in first-insert order, for deterministic iteration

	// readErr, when set, makes the freshness read fail. Callers of that read are expected to degrade rather than propagate (an
	// unreachable archive must not take an operator page down), and a behaviour that only shows up on failure needs a way to
	// provoke the failure.
	readErr error
}

// FailReads makes TelemetryActivityForHosts return err until cleared with nil, so a test can assert what a caller does when the
// archive is unreachable.
func (m *MemArchive) FailReads(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readErr = err
}

// Compile-time check that MemArchive satisfies the published EventArchive contract.
var _ api.EventArchive = (*MemArchive)(nil)

// NewMemArchive returns an empty in-memory archive.
func NewMemArchive() *MemArchive {
	return &MemArchive{byID: make(map[string]api.Event)}
}

// Len reports the number of distinct event_ids stored, the in-memory analogue of the archive table's row count (ReplacingMergeTree
// collapses re-inserts of a known id). Tests use it as the durable-cardinality probe that the dropped MySQL events table's COUNT(*)
// used to provide, e.g. to assert idempotent ingest stored each event once.
func (m *MemArchive) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}

// CountByType reports how many stored events have the given event_type, the in-memory analogue of a COUNT(*) ... WHERE event_type = ?
// against the archive. Tests use it to assert event-kind filtering, e.g. that snapshot_heartbeat events are dropped at ingest and never
// reach the durable store.
func (m *MemArchive) CountByType(eventType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.byID {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

// Insert stores events idempotently by event_id (last write wins), mirroring ReplacingMergeTree dedup.
func (m *MemArchive) Insert(_ context.Context, events []api.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range events {
		if _, ok := m.byID[e.EventID]; !ok {
			m.order = append(m.order, e.EventID)
		}
		m.byID[e.EventID] = e
	}
	return nil
}

// NetworkEventsForProcess returns the network_connect and dns_query events for (hostID, payload pid) within tr, ordered by
// timestamp_ns. The filter mirrors the ClickHouse correlation read it stands in for.
func (m *MemArchive) NetworkEventsForProcess(_ context.Context, hostID string, pid int, tr httpserver.TimeRange) ([]api.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Event
	for _, id := range m.order {
		e := m.byID[id]
		if e.HostID != hostID {
			continue
		}
		if e.EventType != "network_connect" && e.EventType != "dns_query" {
			continue
		}
		if e.IngestedAtNs < tr.FromNs || e.IngestedAtNs > tr.ToNs {
			continue
		}
		if payloadPID(e.Payload) != pid {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TimestampNs < out[j].TimestampNs })
	return out, nil
}

// NetworkEventsForGeneration mirrors the ClickHouse read: the network_connect and dns_query events belonging to ONE generation,
// ordered by timestamp_ns then event_id (issue #716), capped like the real read and reporting whether the cap dropped rows. Two arms,
// partitioned on whether the flow's payload carries a pidversion: identity matches regardless of ingest time but must fall inside the
// generation's life, and the window judges only flows identity cannot speak for. A nil filter.PIDVersion means the process row itself
// carries none, so only the legacy arm applies. See flowBelongsToGeneration.
func (m *MemArchive) NetworkEventsForGeneration(_ context.Context, filter api.ProcessFlowFilter) ([]api.Event, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Event
	for _, id := range m.order {
		e := m.byID[id]
		if e.HostID != filter.HostID {
			continue
		}
		if e.EventType != "network_connect" && e.EventType != "dns_query" {
			continue
		}
		if e.IngestedAtNs < filter.Bound.FromNs || e.IngestedAtNs > filter.Bound.ToNs {
			continue
		}
		if payloadPID(e.Payload) != filter.PID {
			continue
		}
		if !flowBelongsToGeneration(e, filter) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TimestampNs != out[j].TimestampNs {
			return out[i].TimestampNs < out[j].TimestampNs
		}
		return out[i].EventID < out[j].EventID
	})
	rowCap := filter.Limit
	if rowCap <= 0 {
		rowCap = GenerationFlowRowCap
	}
	if len(out) > rowCap {
		return out[:rowCap], true, nil
	}
	return out, false, nil
}

// GenerationFlowRowCap mirrors the ClickHouse store's default cap for NetworkEventsForGeneration. Exported so a test can seed past it
// without hardcoding a number that would drift from production's.
const GenerationFlowRowCap = 500

// EventsByTypeForHost mirrors the ClickHouse read: one host's events of a single type inside the EVENT-time range, oldest first,
// with event_id breaking timestamp ties. The tiebreaker is part of mirroring: a fake that orders ties differently from the real
// store is a fake that lets a test pass against behaviour production does not have.
func (m *MemArchive) EventsByTypeForHost(_ context.Context, hostID, eventType string, tr httpserver.TimeRange) ([]api.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Event
	for _, id := range m.order {
		e := m.byID[id]
		if e.HostID != hostID || e.EventType != eventType {
			continue
		}
		if e.TimestampNs < tr.FromNs || e.TimestampNs > tr.ToNs {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TimestampNs != out[j].TimestampNs {
			return out[i].TimestampNs < out[j].TimestampNs
		}
		return out[i].EventID < out[j].EventID
	})
	// Same overflow contract as the ClickHouse store. A fake that returns everything while production truncates is a fake that
	// hides the exact failure the cap introduces, so the cap and its error live in both.
	if len(out) > EventsByTypeRowCap {
		return nil, fmt.Errorf("mem archive events by type for host %s (%s): %w", hostID, eventType, api.ErrEventsTruncated)
	}
	return out, nil
}

// EventsByTypeRowCap mirrors the ClickHouse store's cap so a test can exercise the overflow path without 1000 rows of setup.
const EventsByTypeRowCap = 1000

// TelemetryActivityForHosts mirrors the ClickHouse read's counting AND its absence contract: a host with no counted events
// inside the range gets no map entry, rather than an entry of zeroes. The distinction is load-bearing for the caller (issue
// #677), which must not read "I have never heard of this host" as "this host went silent", so a fake that materialised zeroes
// would let a test pass against a contract production does not offer.
func (m *MemArchive) TelemetryActivityForHosts(
	_ context.Context, hostIDs []string, tr httpserver.TimeRange,
) (map[string]api.TelemetryActivity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErr != nil {
		return nil, m.readErr
	}
	wanted := make(map[string]struct{}, len(hostIDs))
	for _, id := range hostIDs {
		wanted[id] = struct{}{}
	}
	out := make(map[string]api.TelemetryActivity, len(hostIDs))
	for _, id := range m.order {
		e := m.byID[id]
		if _, ok := wanted[e.HostID]; !ok {
			continue
		}
		if e.TimestampNs < tr.FromNs || e.TimestampNs > tr.ToNs {
			continue
		}
		if !counted(e.EventType) {
			// Skipped BEFORE the map entry is created, mirroring the real store's event_type predicate: there, a host whose
			// only events are other types produces no group and so no row. Both ends have to agree, or a test could rely on
			// a host being present that production omits.
			continue
		}
		out[e.HostID] = countEvent(out[e.HostID], e.EventType)
	}
	return out, nil
}

// counted reports whether an event type contributes to telemetry activity at all. The real store expresses the same set as an
// event_type predicate in its WHERE clause, which is what prunes its scan.
func counted(eventType string) bool {
	switch eventType {
	case "exec", "fork", "network_connect", "dns_query":
		return true
	default:
		return false
	}
}

// countEvent folds one event into a host's running activity and returns the result. Split out of the loop above so each half stays
// readable on its own: the loop decides which events count, this decides what each one counts toward.
//
// It takes and returns a value rather than mutating through a pointer. The pointer version is the obvious shape and reads fine, but
// it makes the counter reachable from a map index expression, which nilaway reports as a potential nil dereference; a value has no
// such flow to analyse and the struct is three ints.
func countEvent(activity api.TelemetryActivity, eventType string) api.TelemetryActivity {
	switch eventType {
	case "exec", "fork":
		activity.ProcessInWindow++
	case "network_connect":
		activity.ConnectInWindow++
	case "dns_query":
		activity.DNSInWindow++
	}
	return activity
}

// EventsByIDs returns the surviving envelopes for the given ids, ordered by (timestamp_ns, event_id). Unknown ids are omitted, matching
// the archive's best-effort evidence contract.
func (m *MemArchive) EventsByIDs(_ context.Context, eventIDs []string) ([]api.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Event
	seen := make(map[string]struct{}, len(eventIDs))
	for _, id := range eventIDs {
		if _, dup := seen[id]; dup {
			continue // a repeated id returns one row, matching ClickHouse `WHERE event_id IN (...)`
		}
		seen[id] = struct{}{}
		if e, ok := m.byID[id]; ok {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TimestampNs != out[j].TimestampNs {
			return out[i].TimestampNs < out[j].TimestampNs
		}
		return out[i].EventID < out[j].EventID
	})
	return out, nil
}

// SearchEvents mirrors the ClickHouse fleet-wide search: events of the filter's type whose artifact value matches, optional host +
// ingest window, newest-first, keyset-paged over (timestamp_ns, event_id). Uses the shared api cursor + field mapping so the fake and
// the real store stay in lockstep.
func (m *MemArchive) SearchEvents(_ context.Context, filter api.EventSearchFilter, cursor string, limit int) (api.EventSearchResult, error) {
	field, ok := api.ArtifactField(filter.EventType)
	if !ok {
		return api.EventSearchResult{}, fmt.Errorf("mem archive search: unsupported event type %q", filter.EventType)
	}
	// Mirror the store: count only for a targeted (artifact-valued) search; the recent-events browse skips it.
	return m.pageMatched(cursor, limit, filter.Value != "", func(e api.Event) bool { return eventMatchesSearch(e, filter, field) })
}

// HostTimeline returns one host's exec/network/DNS events interleaved newest-first over the event-time window (issue #583), the fake's
// mirror of the ClickHouse HostTimeline. Shares the keyset page and (timestamp_ns, event_id) order with SearchEvents via pageMatched.
func (m *MemArchive) HostTimeline(_ context.Context, filter api.HostTimelineFilter, cursor string, limit int) (api.EventSearchResult, error) {
	types := api.EffectiveTimelineEventTypes(filter.EventTypes)
	if len(types) == 0 {
		return api.EventSearchResult{}, nil // only non-timeline classes requested: match nothing, same as the store
	}
	return m.pageMatched(cursor, limit, true, func(e api.Event) bool { return eventMatchesTimeline(e, filter, types) })
}

// pageMatched collects the events satisfying match, then applies the shared newest-first keyset page: sort by (timestamp_ns,
// event_id) desc, count the full match set when countTotal (else TotalNotCounted), drop everything at/after the cursor, and take limit
// (+ a next cursor when more remain). Mirrors the store's pageEventsByKeyset so the fake and the real archive page identically.
func (m *MemArchive) pageMatched(cursor string, limit int, countTotal bool, match func(api.Event) bool) (api.EventSearchResult, error) {
	if limit < 1 {
		limit = 1
	}
	var after *api.EventCursor
	if cursor != "" {
		c, err := api.DecodeEventCursor(cursor)
		if err != nil {
			return api.EventSearchResult{}, err
		}
		after = &c
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []api.Event
	for _, id := range m.order {
		if e := m.byID[id]; match(e) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return eventNewer(matched[i], matched[j]) })

	total := api.TotalNotCounted
	if countTotal {
		total = int64(len(matched))
	}
	if after != nil {
		kept := matched[:0] // reuse the backing array; api.Event is a value type
		for _, e := range matched {
			if eventBeforeCursor(e, *after) {
				kept = append(kept, e)
			}
		}
		matched = kept
	}

	result := api.EventSearchResult{TotalMatched: total}
	if len(matched) > limit {
		last := matched[limit-1]
		result.NextCursor = api.EncodeEventCursor(api.EventCursor{TimestampNs: last.TimestampNs, EventID: last.EventID})
		matched = matched[:limit]
	}
	result.Events = matched
	return result, nil
}

// eventMatchesTimeline reports whether an event belongs in a host timeline page: right host, an event class in the effective set
// (already resolved from the filter via api.EffectiveTimelineEventTypes, so it is the intersection of the request with the allowlist),
// within the optional event-time window, and containing the optional text case-insensitively.
func eventMatchesTimeline(e api.Event, filter api.HostTimelineFilter, types []string) bool {
	if e.HostID != filter.HostID || !slices.Contains(types, e.EventType) {
		return false
	}
	if filter.FromNs > 0 && e.TimestampNs < filter.FromNs {
		return false
	}
	if filter.ToNs > 0 && e.TimestampNs > filter.ToNs {
		return false
	}
	if filter.Text != "" && !strings.Contains(strings.ToLower(string(e.Payload)), strings.ToLower(filter.Text)) {
		return false
	}
	if len(filter.Chain) > 0 && !payloadMatchesChain(e.Payload, filter.Chain) {
		return false
	}
	return true
}

// payloadMatchesChain mirrors the store's chain scope: an event belongs to a chain generation when its (pid, pidversion) parsed from
// the payload matches one of the generations. An event that omits pidversion matches no generation: absence is not pidversion 0 (a
// real kernel generation), so a scope for (pid, 0) must not sweep in legacy events that never carried the field. The pointer field
// preserves that absence, where a plain int64 would collapse a missing pidversion to 0.
func payloadMatchesChain(payload json.RawMessage, chain []api.ProcessGeneration) bool {
	pid, ver := payloadGeneration(payload)
	if ver == nil {
		return false
	}
	for _, g := range chain {
		if pid == g.PID && *ver == g.PIDVersion {
			return true
		}
	}
	return false
}

// flowBelongsToGeneration mirrors the store's two-arm attribution for NetworkEventsForGeneration. The arms partition on whether the
// flow carries a pidversion, so a flow is never judged by both:
//
//   - Identity: the flow's (pid, pidversion) equals the generation's AND its EVENT time falls inside the generation's life. Ingest
//     time is irrelevant, which is the #716 fix; the life bound disambiguates a pidversion that pre-#715 rows repeated across the
//     generations of one chain, where identity alone would show each generation the other's flows.
//   - Legacy: the flow carries NO pidversion, so identity cannot speak for it and its ingest time must fall inside the window.
//
// A nil filter.PIDVersion means the process ROW carries no pidversion, so identity is unavailable on that side too and ONLY the legacy
// arm applies. A flow carrying a pidversion belongs to some generation of this pid, and a row that cannot name its own generation must
// not claim it on timing alone: that is the #716 mis-attribution class surviving on the legacy side.
func flowBelongsToGeneration(e api.Event, filter api.ProcessFlowFilter) bool {
	inWindow := e.IngestedAtNs >= filter.IngestWindow.FromNs && e.IngestedAtNs <= filter.IngestWindow.ToNs
	_, flowVer := payloadGeneration(e.Payload)
	if filter.PIDVersion == nil {
		return flowVer == nil && inWindow
	}
	gen := api.ProcessGeneration{PID: int64(filter.PID), PIDVersion: *filter.PIDVersion}
	inLife := e.TimestampNs >= filter.Life.FromNs && e.TimestampNs <= filter.Life.ToNs
	if payloadMatchesChain(e.Payload, []api.ProcessGeneration{gen}) {
		return inLife
	}
	// A flow carrying a DIFFERENT pidversion belongs to a sibling generation and must not be rescued by timing; only one carrying
	// none falls through to the window.
	return flowVer == nil && inWindow
}

// payloadGeneration parses the (pid, pidversion) pair from an event payload, with a nil version for a payload that omits the field.
// The pointer preserves that absence, where a plain int64 would collapse a missing pidversion to 0.
func payloadGeneration(payload json.RawMessage) (int64, *int64) {
	var p struct {
		PID        int64  `json:"pid"`
		PIDVersion *int64 `json:"pidversion"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return 0, nil
	}
	return p.PID, p.PIDVersion
}

// eventMatchesSearch reports whether an event satisfies a fleet-wide search filter: right type, matching artifact value, and within
// the optional host + ingest-window bounds. Extracted so SearchEvents stays flat.
func eventMatchesSearch(e api.Event, filter api.EventSearchFilter, field string) bool {
	if e.EventType != filter.EventType {
		return false
	}
	// An empty artifact value lists recent events of this type unfiltered, mirroring the store; a supplied value matches exactly.
	if filter.Value != "" && payloadString(e.Payload, field) != filter.Value {
		return false
	}
	if filter.HostID != "" && e.HostID != filter.HostID {
		return false
	}
	if filter.FromNs > 0 && e.IngestedAtNs < filter.FromNs {
		return false
	}
	if filter.ToNs > 0 && e.IngestedAtNs > filter.ToNs {
		return false
	}
	return true
}

// eventNewer / eventBeforeCursor order and page events by (timestamp_ns, event_id), newest-first, matching the archive's search order.
func eventNewer(a, b api.Event) bool {
	if a.TimestampNs != b.TimestampNs {
		return a.TimestampNs > b.TimestampNs
	}
	return a.EventID > b.EventID
}

func eventBeforeCursor(e api.Event, c api.EventCursor) bool {
	return e.TimestampNs < c.TimestampNs || (e.TimestampNs == c.TimestampNs && e.EventID < c.EventID)
}

// payloadString extracts a string field from an event payload, mirroring the archive's JSONExtractString / materialized column.
func payloadString(payload json.RawMessage, field string) string {
	if len(payload) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return ""
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// payloadPID extracts the pid field the network/dns payloads carry, mirroring the archive's materialized pid column. A payload without
// a pid yields 0, which only matches a pid==0 query (no real process), so it is harmless.
func payloadPID(payload json.RawMessage) int {
	if len(payload) == 0 {
		return 0
	}
	var p struct {
		PID int `json:"pid"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.PID
}

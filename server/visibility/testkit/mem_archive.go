package testkit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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

// SearchEvents mirrors the ClickHouse fleet-wide search: events of the filter's type whose artifact value matches (remote_address for
// network_connect, query_name for dns_query), optional host + ingest window, newest-first, keyset-paged over (timestamp_ns, event_id).
func (m *MemArchive) SearchEvents(_ context.Context, filter api.EventSearchFilter, cursor string, limit int) (api.EventSearchResult, error) {
	if limit < 1 {
		limit = 1
	}
	field, err := searchFieldForType(filter.EventType)
	if err != nil {
		return api.EventSearchResult{}, err
	}
	var cur *memEventCursor
	if cursor != "" {
		c, err := decodeMemEventCursor(cursor)
		if err != nil {
			return api.EventSearchResult{}, err
		}
		cur = &c
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []api.Event
	for _, id := range m.order {
		e := m.byID[id]
		if e.EventType != filter.EventType || payloadString(e.Payload, field) != filter.Value {
			continue
		}
		if filter.HostID != "" && e.HostID != filter.HostID {
			continue
		}
		if filter.FromNs > 0 && e.IngestedAtNs < filter.FromNs {
			continue
		}
		if filter.ToNs > 0 && e.IngestedAtNs > filter.ToNs {
			continue
		}
		matched = append(matched, e)
	}
	// Newest-first by (timestamp_ns, event_id), the archive's search order.
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].TimestampNs != matched[j].TimestampNs {
			return matched[i].TimestampNs > matched[j].TimestampNs
		}
		return matched[i].EventID > matched[j].EventID
	})

	total := int64(len(matched))
	if cur != nil {
		kept := matched[:0:0]
		for _, e := range matched {
			if e.TimestampNs < cur.timestampNs || (e.TimestampNs == cur.timestampNs && e.EventID < cur.eventID) {
				kept = append(kept, e)
			}
		}
		matched = kept
	}

	result := api.EventSearchResult{TotalMatched: total}
	if len(matched) > limit {
		last := matched[limit-1]
		result.NextCursor = encodeMemEventCursor(memEventCursor{timestampNs: last.TimestampNs, eventID: last.EventID})
		matched = matched[:limit]
	}
	result.Events = matched
	return result, nil
}

// searchFieldForType maps an event type to the payload field its artifact search matches, mirroring the ClickHouse materialized column.
func searchFieldForType(eventType string) (string, error) {
	switch eventType {
	case "network_connect":
		return "remote_address", nil
	case "dns_query":
		return "query_name", nil
	default:
		return "", fmt.Errorf("mem archive search: unsupported event type %q", eventType)
	}
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

// memEventCursor / its codec mirror the ClickHouse event cursor (base64url of "timestamp_ns:event_id") so the fake and the real store
// speak the same opaque token, and a handler test can pass a cursor from one to the other.
type memEventCursor struct {
	timestampNs int64
	eventID     string
}

func encodeMemEventCursor(c memEventCursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.timestampNs, 10) + ":" + c.eventID))
}

func decodeMemEventCursor(token string) (memEventCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return memEventCursor{}, fmt.Errorf("%w: not base64url: %w", api.ErrInvalidEventCursor, err)
	}
	ts, id, ok := strings.Cut(string(raw), ":")
	if !ok {
		return memEventCursor{}, fmt.Errorf("%w: missing ts:event_id separator", api.ErrInvalidEventCursor)
	}
	tsNs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return memEventCursor{}, fmt.Errorf("%w: timestamp_ns: %w", api.ErrInvalidEventCursor, err)
	}
	return memEventCursor{timestampNs: tsNs, eventID: id}, nil
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

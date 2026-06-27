package testkit

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/visibility/api"
)

// MemArchive is an in-memory EventArchive for tests: it satisfies the visibility EventArchive contract without a ClickHouse container,
// so detection rule, graph, and alert tests can seed correlation + evidence reads cheaply. The real ClickHouse archive is exercised by
// the visibility and detection integration tests. Not safe for concurrent use; tests drive it from a single goroutine.
//
// It mirrors the ClickHouse store's read semantics: idempotent by event_id (last write wins, like ReplacingMergeTree collapsed under
// FINAL), the network correlation read filters on host + event_type + the payload pid + the ingested_at_ns window, and EventsByIDs
// returns the surviving envelopes ordered by (timestamp_ns, event_id).
type MemArchive struct {
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
func (m *MemArchive) Len() int { return len(m.byID) }

// CountByType reports how many stored events have the given event_type, the in-memory analogue of a COUNT(*) ... WHERE event_type = ?
// against the archive. Tests use it to assert event-kind filtering, e.g. that snapshot_heartbeat events are dropped at ingest and never
// reach the durable store.
func (m *MemArchive) CountByType(eventType string) int {
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
	var out []api.Event
	for _, id := range eventIDs {
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

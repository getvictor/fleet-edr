package mysql_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
)

// Tests for the bulk / index / CTE optimisations introduced for issues #91-#94. Each test pins the externally observable behaviour
// (correctness) the prior shape provided. Microbenchmarks alongside these prove the linear-with-N drop the issues' acceptance criteria
// call out.

// --- #91: bulk hosts upsert ------------------------------------------------

func TestUpsertHosts_BatchAcrossManyHosts(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	const n = 32
	events := make([]api.Event, 0, n*3)
	for i := range n {
		host := "host-" + strconv.Itoa(i)
		events = append(events,
			api.Event{EventID: host + "-1", HostID: host, TimestampNs: int64(100 + i), EventType: "fork", Payload: json.RawMessage(`{}`)},
			api.Event{EventID: host + "-2", HostID: host, TimestampNs: int64(200 + i), EventType: "fork", Payload: json.RawMessage(`{}`)},
			api.Event{EventID: host + "-3", HostID: host, TimestampNs: int64(50 + i), EventType: "fork", Payload: json.RawMessage(`{}`)},
		)
	}
	require.NoError(t, s.UpsertHosts(ctx, events))

	hosts, err := s.ListHosts(ctx)
	require.NoError(t, err)
	require.Len(t, hosts, n, "every distinct host gets a row")

	byHost := make(map[string]api.HostSummary, n)
	for _, h := range hosts {
		byHost[h.HostID] = h
	}
	for i := range n {
		host := "host-" + strconv.Itoa(i)
		got, ok := byHost[host]
		require.True(t, ok, "missing row for %s", host)
		assert.Equal(t, int64(3), got.EventCount, "%s: 3 events aggregated into one row", host)
		assert.Equal(t, int64(200+i), got.LastSeenNs, "%s: last_seen pinned to MAX(timestamp_ns)", host)
	}

	// Re-running the same batch must accumulate, not duplicate. This is the property the ON DUPLICATE KEY UPDATE branch is responsible
	// for; the bulk-INSERT swap mustn't break it.
	require.NoError(t, s.UpsertHosts(ctx, events))
	hosts2, err := s.ListHosts(ctx)
	require.NoError(t, err)
	for _, h := range hosts2 {
		assert.Equal(t, int64(6), h.EventCount, "%s: re-running doubles the count via ON DUPLICATE KEY UPDATE", h.HostID)
	}
}

func TestUpsertHosts_EmptyBatchNoOp(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.UpsertHosts(t.Context(), nil))
	require.NoError(t, s.UpsertHosts(t.Context(), []api.Event{}))
	hosts, err := s.ListHosts(t.Context())
	require.NoError(t, err)
	assert.Empty(t, hosts, "empty batch must not insert anything")
}

func BenchmarkUpsertHosts(b *testing.B) {
	for _, n := range []int{16, 64, 256} {
		b.Run(fmt.Sprintf("hosts=%d", n), func(b *testing.B) {
			s := newTestStore(b)
			ctx := b.Context()
			events := make([]api.Event, n)
			for i := range events {
				events[i] = api.Event{
					EventID:     "be-" + strconv.Itoa(i),
					HostID:      "bench-host-" + strconv.Itoa(i),
					TimestampNs: int64(i),
					EventType:   "fork",
					Payload:     json.RawMessage(`{}`),
				}
			}
			b.ResetTimer()
			for range b.N {
				if err := s.UpsertHosts(ctx, events); err != nil {
					b.Fatalf("upsert hosts: %v", err)
				}
			}
		})
	}
}

// --- #92: indexed PID lookup ----------------------------------------------

func TestGetNetworkEventsForProcess_FiltersByIndexedPID(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Six events split across two pids on the same host, plus one on a different host (must be excluded), one with the wrong event_type
	// (must be excluded), and one outside the time window.
	require.NoError(t, s.InsertEventsAt(ctx, []api.Event{
		{EventID: "n1", HostID: "h", TimestampNs: 100, EventType: "network_connect", Payload: json.RawMessage(`{"pid":1234,"dst":"a"}`)},
		{EventID: "n2", HostID: "h", TimestampNs: 200, EventType: "dns_query", Payload: json.RawMessage(`{"pid":1234,"name":"b"}`)},
		{EventID: "n3", HostID: "h", TimestampNs: 300, EventType: "network_connect", Payload: json.RawMessage(`{"pid":9999}`)},
		{EventID: "n4", HostID: "other", TimestampNs: 400, EventType: "network_connect", Payload: json.RawMessage(`{"pid":1234}`)},
		{EventID: "n5", HostID: "h", TimestampNs: 500, EventType: "fork", Payload: json.RawMessage(`{"pid":1234}`)},
	}, 1000))
	require.NoError(t, s.InsertEventsAt(ctx, []api.Event{
		{EventID: "n6", HostID: "h", TimestampNs: 600, EventType: "network_connect", Payload: json.RawMessage(`{"pid":1234}`)},
	}, 9999))

	got, err := s.GetNetworkEventsForProcess(ctx, "h", 1234, api.TimeRange{FromNs: 0, ToNs: 5000})
	require.NoError(t, err)
	require.Len(t, got, 2, "only n1 + n2 match host=h, type∈{network_connect,dns_query}, pid=1234, ingested in [0,5000]")

	// Ordered by timestamp_ns; n1 (100) before n2 (200).
	ids := []string{got[0].EventID, got[1].EventID}
	assert.Equal(t, []string{"n1", "n2"}, ids)

	// n6 was ingested at 9999; widening the window must surface it. The query filters on ingested_at_ns (not timestamp_ns); the index
	// column ordering puts payload_pid before ingested_at_ns so the pid equality is consumed first, then the ingest range scans.
	got2, err := s.GetNetworkEventsForProcess(ctx, "h", 1234, api.TimeRange{FromNs: 0, ToNs: 50000})
	require.NoError(t, err)
	require.Len(t, got2, 3, "widening the ingested_at_ns window picks up n6")
}

func TestGetNetworkEventsForProcess_UsesPIDIndex(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Seed enough rows that the optimiser would prefer a scan over an
	// index lookup if the predicate weren't index-backed.
	for i := range 50 {
		require.NoError(t, s.InsertEvents(ctx, []api.Event{{
			EventID:     "seed-" + strconv.Itoa(i),
			HostID:      "h",
			TimestampNs: int64(i),
			EventType:   "network_connect",
			Payload:     json.RawMessage(`{"pid":` + strconv.Itoa(i%5) + `}`),
		}}))
	}
	// EXPLAIN's column set varies by MySQL version; we only care about the key column. Use a dynamic scan so the test isn't sensitive to
	// MySQL adding/renaming sibling columns.
	rows, err := s.DB().QueryxContext(ctx, `EXPLAIN
		SELECT event_id FROM events
		WHERE host_id = ? AND event_type IN ('network_connect','dns_query')
		  AND payload_pid = ?
		  AND ingested_at_ns >= ? AND ingested_at_ns <= ?`,
		"h", 3, 0, int64(1<<62))
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next(), "EXPLAIN must return at least one row")
	cols, err := rows.SliceScan()
	require.NoError(t, err)
	colNames, err := rows.Columns()
	require.NoError(t, err)
	var keyVal string
	for i, name := range colNames {
		if name != "key" {
			continue
		}
		if cols[i] == nil {
			break
		}
		switch v := cols[i].(type) {
		case []byte:
			keyVal = string(v)
		case string:
			keyVal = v
		}
	}
	assert.Equal(t, "idx_events_host_type_pid_ingested", keyVal,
		"EXPLAIN must show the new composite index, not idx_events_host_type_ingested")
}

func BenchmarkGetNetworkEventsForProcess(b *testing.B) {
	for _, eventCount := range []int{500, 5000} {
		b.Run(fmt.Sprintf("events=%d", eventCount), func(b *testing.B) {
			s := newTestStore(b)
			ctx := b.Context()

			// Most events are noise (different pids); the target pid hits
			// just a few rows. The win is "no full table scan", which is
			// why the bench scales with rows in events, not result-set size.
			batch := make([]api.Event, eventCount)
			for i := range batch {
				batch[i] = api.Event{
					EventID:     "ne-" + strconv.Itoa(i),
					HostID:      "h",
					TimestampNs: int64(i),
					EventType:   "network_connect",
					Payload:     json.RawMessage(`{"pid":` + strconv.Itoa(i) + `}`),
				}
			}
			require.NoError(b, s.InsertEvents(ctx, batch))
			b.ResetTimer()
			for range b.N {
				_, err := s.GetNetworkEventsForProcess(ctx, "h", 7, api.TimeRange{FromNs: 0, ToNs: 1 << 62})
				if err != nil {
					b.Fatalf("query: %v", err)
				}
			}
		})
	}
}

// --- #93: bulk alert_events linking ---------------------------------------

func TestInsertAlert_LinksEveryEventInOneStatement(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 1})
	require.NoError(t, err)

	const n = 50
	eventIDs := make([]string, n)
	events := make([]api.Event, n)
	for i := range events {
		eventIDs[i] = "ae-" + strconv.Itoa(i)
		events[i] = api.Event{EventID: eventIDs[i], HostID: "h", TimestampNs: int64(i), EventType: "fork", Payload: json.RawMessage(`{}`)}
	}
	require.NoError(t, s.InsertEvents(ctx, events))

	alertID, created, err := s.InsertAlert(ctx, api.Alert{
		HostID: "h", RuleID: "r", Severity: api.SeverityHigh,
		Title: "T", Description: "D", ProcessID: procID,
	}, eventIDs)
	require.NoError(t, err)
	assert.True(t, created)

	got, err := s.GetAlertEventIDs(ctx, alertID)
	require.NoError(t, err)
	assert.ElementsMatch(t, eventIDs, got, "every event_id must be linked")
}

func TestInsertAlert_DedupBranchAlsoLinksAllEvents(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 1})
	require.NoError(t, err)

	first := []string{"d1", "d2"}
	second := []string{"d2", "d3", "d4"} // overlap with `first`; INSERT IGNORE must absorb.
	allIDs := []string{"d1", "d2", "d3", "d4"}
	events := make([]api.Event, len(allIDs))
	for i, id := range allIDs {
		events[i] = api.Event{EventID: id, HostID: "h", TimestampNs: 1, EventType: "fork", Payload: json.RawMessage(`{}`)}
	}
	require.NoError(t, s.InsertEvents(ctx, events))

	alertID1, created1, err := s.InsertAlert(ctx, api.Alert{
		HostID: "h", RuleID: "r", Severity: api.SeverityHigh,
		Title: "T", Description: "D", ProcessID: procID,
	}, first)
	require.NoError(t, err)
	require.True(t, created1)

	alertID2, created2, err := s.InsertAlert(ctx, api.Alert{
		HostID: "h", RuleID: "r", Severity: api.SeverityHigh,
		Title: "T", Description: "D", ProcessID: procID,
	}, second)
	require.NoError(t, err)
	assert.False(t, created2, "duplicate (host_id,rule_id,process_id) must dedup, not create")
	assert.Equal(t, alertID1, alertID2, "dedup returns the existing alert id")

	got, err := s.GetAlertEventIDs(ctx, alertID1)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"d1", "d2", "d3", "d4"}, got,
		"INSERT IGNORE absorbs the (alert,d2) duplicate and adds the new ones")
}

func BenchmarkInsertAlert_BulkLinkEvents(b *testing.B) {
	for _, eventsPerAlert := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("events=%d", eventsPerAlert), func(b *testing.B) {
			s := newTestStore(b)
			ctx := b.Context()
			procID, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 1})
			require.NoError(b, err)

			eventIDs := make([]string, eventsPerAlert)
			batch := make([]api.Event, eventsPerAlert)
			for i := range batch {
				eventIDs[i] = "be-" + strconv.Itoa(i)
				batch[i] = api.Event{EventID: eventIDs[i], HostID: "h", TimestampNs: 1, EventType: "fork", Payload: json.RawMessage(`{}`)}
			}
			require.NoError(b, s.InsertEvents(ctx, batch))
			b.ResetTimer()
			for i := range b.N {
				// Vary rule_id so each iteration creates a fresh alert
				// (the dedup branch is covered by its own bench below).
				_, _, err := s.InsertAlert(ctx, api.Alert{
					HostID: "h", RuleID: "r-" + strconv.Itoa(i),
					Severity: api.SeverityHigh, Title: "T", Description: "D",
					ProcessID: procID,
				}, eventIDs)
				if err != nil {
					b.Fatalf("insert alert: %v", err)
				}
			}
		})
	}
}

// --- #94: recursive CTE for GetExecChain ----------------------------------

func TestGetExecChain_ReturnsOldestFirstAndExcludesCurrent(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// Build a chain: gen0 <- gen1 <- gen2 <- gen3 (current).
	gen0, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 100})
	require.NoError(t, err)
	gen1, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 200, PreviousExecID: &gen0})
	require.NoError(t, err)
	gen2, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 300, PreviousExecID: &gen1})
	require.NoError(t, err)
	gen3, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 400, PreviousExecID: &gen2})
	require.NoError(t, err)

	current := api.Process{ID: gen3, HostID: "h", PID: 1, ForkTimeNs: 400, PreviousExecID: &gen2}
	chain, err := s.GetExecChain(ctx, current)
	require.NoError(t, err)
	require.Len(t, chain, 3, "chain excludes current; returns gen0, gen1, gen2")

	gotIDs := []int64{chain[0].ID, chain[1].ID, chain[2].ID}
	assert.Equal(t, []int64{gen0, gen1, gen2}, gotIDs,
		"oldest-first order: gen0 first, gen2 last (closest ancestor)")
}

func TestGetExecChain_NoPreviousExecReturnsEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	procID, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 1})
	require.NoError(t, err)

	chain, err := s.GetExecChain(ctx, api.Process{ID: procID, HostID: "h", PID: 1})
	require.NoError(t, err)
	assert.Empty(t, chain, "process with no previous_exec_id has empty chain")
}

func TestGetExecChain_HostScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// A process on host A pointing at a previous_exec_id that exists on
	// host B (corrupt-FK simulation): the host_id scope must hide it.
	procB, err := s.InsertProcess(ctx, api.Process{HostID: "B", PID: 1, ForkTimeNs: 100})
	require.NoError(t, err)
	procA, err := s.InsertProcess(ctx, api.Process{HostID: "A", PID: 1, ForkTimeNs: 200, PreviousExecID: &procB})
	require.NoError(t, err)

	chain, err := s.GetExecChain(ctx, api.Process{ID: procA, HostID: "A", PID: 1, PreviousExecID: &procB})
	require.NoError(t, err)
	assert.Empty(t, chain, "ancestor row on a different host must not surface")
}

func TestGetExecChain_CycleGuardCapsAt64(t *testing.T) {
	// Synthesise a cycle by post-INSERT updating the oldest row's previous_exec_id to point at itself. Real schema would never produce
	// this (each generation forks strictly later than its predecessor) but the cycle guard is the safety net for a corrupt FK.
	s := newTestStore(t)
	ctx := t.Context()

	gen0, err := s.InsertProcess(ctx, api.Process{HostID: "h", PID: 1, ForkTimeNs: 100})
	require.NoError(t, err)
	_, err = s.DB().ExecContext(ctx, `UPDATE processes SET previous_exec_id = ? WHERE id = ?`, gen0, gen0)
	require.NoError(t, err)

	chain, err := s.GetExecChain(ctx, api.Process{ID: gen0, HostID: "h", PID: 1, PreviousExecID: &gen0})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(chain), 64, "cycle must be bounded by maxChainLen")
}

func BenchmarkGetExecChain(b *testing.B) {
	for _, depth := range []int{8, 32, 64} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			s := newTestStore(b)
			ctx := b.Context()

			// Build `depth` ancestor rows linked tail-to-head, then form
			// a logical `current` whose PreviousExecID points at the most
			// recent ancestor. Each iteration must capture the inserted
			// id into a *fresh* int64 (snapshot) and take its address;
			// reusing one variable's address yields a self-cycle because
			// the pointer always reads the latest assignment (per
			// Copilot review on PR #110).
			var prevPtr *int64
			for i := range depth {
				p := api.Process{HostID: "h", PID: 1, ForkTimeNs: int64(100 + i), PreviousExecID: prevPtr}
				id, err := s.InsertProcess(ctx, p)
				require.NoError(b, err)
				snapshot := id
				prevPtr = &snapshot
			}
			current := api.Process{HostID: "h", PID: 1, ForkTimeNs: int64(100 + depth), PreviousExecID: prevPtr}

			b.ResetTimer()
			for range b.N {
				_, err := s.GetExecChain(ctx, current)
				if err != nil {
					b.Fatalf("get exec chain: %v", err)
				}
			}
		})
	}
}

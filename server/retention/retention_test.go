package retention

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/store"
)

// seedEvents inserts n events dated `age` ago for hostID. Returns the event IDs in
// insert order so tests can reference specific rows for alert_events wiring.
func seedEvents(t *testing.T, s *store.Store, hostID string, age time.Duration, n int) []string {
	t.Helper()
	ts := time.Now().Add(-age).UnixNano()
	ids := make([]string, 0, n)
	events := make([]store.Event, 0, n)
	for i := range n {
		id := fmtID(hostID, age, i)
		ids = append(ids, id)
		events = append(events, store.Event{
			EventID:     id,
			HostID:      hostID,
			TimestampNs: ts + int64(i),
			EventType:   "exec",
			Payload:     json.RawMessage(`{"pid":1,"ppid":0,"path":"/bin/true"}`),
		})
	}
	require.NoError(t, s.InsertEvents(t.Context(), events))
	return ids
}

func fmtID(hostID string, age time.Duration, i int) string {
	return hostID + "-" + age.String() + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{byte('0' + i%10)}, out...)
		i /= 10
	}
	return string(out)
}

// insertAlertLinkingEvent fabricates an alert + alert_events rows that reference the
// given event ids. The rule + severity doesn't matter; the retention query only cares
// about the existence of an alert_events row.
func insertAlertLinkingEvent(t *testing.T, s *store.Store, hostID string, eventIDs []string) {
	t.Helper()
	ctx := t.Context()
	procID, err := s.InsertProcess(ctx, store.Process{
		HostID: hostID, PID: 1, PPID: 0, Path: "/bin/true", ForkTimeNs: 0,
	})
	require.NoError(t, err)
	alertID, _, err := s.InsertAlert(ctx, store.Alert{
		HostID: hostID, RuleID: "retention_test", Severity: "low",
		Title: "ret", ProcessID: procID,
	}, eventIDs)
	require.NoError(t, err)
	require.Positive(t, alertID)
}

func countEvents(t *testing.T, s *store.Store) int64 {
	t.Helper()
	n, err := s.CountEvents(t.Context())
	require.NoError(t, err)
	return n
}

func TestRun_DeletesOldEventsOnly(t *testing.T) {
	s := store.OpenTestStore(t)

	// 10 events from 40 days ago (past cutoff) + 10 from yesterday (inside window).
	seedEvents(t, s, "host-old", 40*24*time.Hour, 10)
	seedEvents(t, s, "host-new", 24*time.Hour, 10)
	require.Equal(t, int64(20), countEvents(t, s))

	r := New(s.DB(), Options{
		RetentionDays: 30,
		BatchSize:     1000,
		Logger:        slog.Default(),
	})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(10), n, "exactly the 10 old events should be deleted")
	assert.Equal(t, int64(10), countEvents(t, s), "the 10 recent events must survive")
}

func TestRun_PreservesAlertReferencedEvents(t *testing.T) {
	s := store.OpenTestStore(t)

	// 20 old events. 5 of them are referenced by an alert via alert_events. The
	// retention pass must spare those 5 even though all 20 are past the cutoff.
	ids := seedEvents(t, s, "host", 40*24*time.Hour, 20)
	insertAlertLinkingEvent(t, s, "host", ids[0:5])

	r := New(s.DB(), Options{RetentionDays: 30, Logger: slog.Default()})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(15), n)
	assert.Equal(t, int64(5), countEvents(t, s), "alert-referenced events must survive retention")
}

func TestRun_DisabledWhenRetentionDaysZero(t *testing.T) {
	s := store.OpenTestStore(t)
	seedEvents(t, s, "host", 365*24*time.Hour, 5)

	r := New(s.DB(), Options{RetentionDays: 0, Logger: slog.Default()})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
	assert.Equal(t, int64(5), countEvents(t, s),
		"RetentionDays=0 must leave the table untouched")
}

func TestRun_BatchesUntilDone(t *testing.T) {
	s := store.OpenTestStore(t)
	// Insert 25 old events with a batch size of 10. We expect 3 iterations (10 + 10 +
	// 5) and a clean exit when the last DELETE returns <batchSize rows.
	seedEvents(t, s, "host", 40*24*time.Hour, 25)

	r := New(s.DB(), Options{RetentionDays: 30, BatchSize: 10, Logger: slog.Default()})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(25), n)
	assert.Equal(t, int64(0), countEvents(t, s))
}

func TestRun_CutoffUsesFrozenClock(t *testing.T) {
	s := store.OpenTestStore(t)
	// Events dated exactly 15 days ago.
	seedEvents(t, s, "host", 15*24*time.Hour, 3)

	// Frozen clock at 20 days past the events; retention-days=5 means the 15-day-old
	// events are 5 days past the cutoff and should be deleted. This locks in that the
	// runner uses the injected clock, not wall time.
	frozen := time.Now().Add(20 * 24 * time.Hour)
	r := New(s.DB(), Options{
		RetentionDays: 5,
		Logger:        slog.Default(),
		Now:           func() time.Time { return frozen },
	})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

// stubMetrics records calls so tests can assert the OTel hook is invoked with
// the right count. Kept tiny because retention only has one metric callback.
type stubMetrics struct {
	rowsDeleted []int64
}

func (s *stubMetrics) RetentionRowsDeleted(_ context.Context, n int64) {
	s.rowsDeleted = append(s.rowsDeleted, n)
}

func TestRun_InvokesMetrics(t *testing.T) {
	s := store.OpenTestStore(t)
	seedEvents(t, s, "host", 40*24*time.Hour, 4)

	m := &stubMetrics{}
	r := New(s.DB(), Options{RetentionDays: 30, Logger: slog.Default(), Metrics: m})
	n, err := r.Run(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(4), n)
	require.Len(t, m.rowsDeleted, 1)
	assert.Equal(t, int64(4), m.rowsDeleted[0])
}

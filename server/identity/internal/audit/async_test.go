package audit_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
	"github.com/fleetdm/edr/server/identity/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newWriterWithStore stands up an AsyncWriter against a real test DB
// + the identity schema. Tests assert against either the writer's
// internal state (Dropped) or the audit_events row count after a
// Run-and-cancel cycle.
func newWriterWithStore(t *testing.T, capHint int, logger *slog.Logger) (*audit.AsyncWriter, *audit.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := audit.New(db)
	w := audit.NewAsyncWriter(store, audit.AsyncOptions{QueueCap: capHint, Logger: logger})
	return w, store, db
}

// runAndCancel starts Run in a goroutine, lets it process for `d`,
// then cancels and waits for Run to return. Tests use it to drain
// the queue under their own clock without leaking goroutines.
func runAndCancel(t *testing.T, w *audit.AsyncWriter, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	time.Sleep(d)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("AsyncWriter.Run did not return within 2s of cancel")
	}
}

// Submit accepts events up to capacity and writes them to the store
// once Run drains. End-to-end smoke test against the real DB so the
// store's INSERT shape is exercised, not just the channel plumbing.
func TestAsyncWriter_SubmitDrainsToStore(t *testing.T) {
	uid := int64(1)
	w, _, db := newWriterWithStore(t, 16, slog.Default())

	for i := range 5 {
		ok := w.Submit(t.Context(), api.AuditEvent{
			UserID: &uid,
			Action: api.AuditAction("authz.host.read"),
		})
		assert.True(t, ok, "submit %d must succeed under capacity", i)
	}
	runAndCancel(t, w, 200*time.Millisecond)

	var n int
	require.NoError(t, db.QueryRowxContext(t.Context(),
		`SELECT COUNT(*) FROM audit_events WHERE action = 'authz.host.read'`).Scan(&n))
	assert.Equal(t, 5, n)
	assert.Equal(t, uint64(0), w.Dropped())
}

// Drop policy: queue_full -> Submit returns false, slog WARN
// captures the dropped event for the dual-emit secondary backend,
// Dropped() counter increments.
func TestAsyncWriter_DropOnFull(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Capacity 1, no Run goroutine started -> first Submit fills the
	// channel, second is dropped.
	w, _, _ := newWriterWithStore(t, 1, logger)

	ok := w.Submit(t.Context(), api.AuditEvent{Action: "authz.host.read", TargetID: "first"})
	require.True(t, ok)
	ok = w.Submit(t.Context(), api.AuditEvent{Action: "authz.host.read", TargetID: "dropped"})
	assert.False(t, ok, "second submit on a full capacity-1 queue must drop")
	assert.Equal(t, uint64(1), w.Dropped())

	logs := buf.String()
	assert.Contains(t, logs, `"audit dropped (async queue)"`)
	assert.Contains(t, logs, `"reason":"queue_full"`)
	assert.Contains(t, logs, `"target_id":"dropped"`)
}

// On graceful shutdown the writer must drain queued events before
// returning. The DB row count proves the events landed.
func TestAsyncWriter_DrainOnShutdown(t *testing.T) {
	uid := int64(2)
	w, _, db := newWriterWithStore(t, 16, slog.Default())

	for range 4 {
		require.True(t, w.Submit(t.Context(), api.AuditEvent{
			UserID: &uid,
			Action: api.AuditAction("authz.alert.read"),
		}))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	cancel() // cancel BEFORE Run had a chance to drain on its own
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}

	var n int
	require.NoError(t, db.QueryRowxContext(t.Context(),
		`SELECT COUNT(*) FROM audit_events WHERE action = 'authz.alert.read'`).Scan(&n))
	assert.Equal(t, 4, n, "drain must flush queued events before Run returns")
}

// Submit after the writer has stopped must drop with a stopped
// reason, not panic. Two sources of false return are present in
// production: queue_full (transient) and writer_stopped (terminal);
// distinguishing them in the slog line lets a dashboard separate
// "we burst" from "we shut down with traffic still arriving."
func TestAsyncWriter_SubmitAfterStopDrops(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	w, _, _ := newWriterWithStore(t, 8, logger)

	// Run + immediate cancel so the stopped channel closes.
	runAndCancel(t, w, 50*time.Millisecond)

	ok := w.Submit(t.Context(), api.AuditEvent{Action: "authz.host.read"})
	assert.False(t, ok)
	assert.Equal(t, uint64(1), w.Dropped())
	assert.Contains(t, buf.String(), `"reason":"writer_stopped"`)
}

// Concurrent Submit from many goroutines must not panic and the
// total accepted + dropped count must equal the offered count.
// This guards against a future race when someone "optimises" the
// queue full path.
func TestAsyncWriter_ConcurrentSubmit(t *testing.T) {
	w, _, _ := newWriterWithStore(t, 32, slog.Default())

	const goroutines, perGoroutine = 8, 100
	var accepted, dropped atomic.Uint64
	done := make(chan struct{})
	for range goroutines {
		go func() {
			for range perGoroutine {
				if w.Submit(t.Context(), api.AuditEvent{Action: "authz.host.read"}) {
					accepted.Add(1)
				} else {
					dropped.Add(1)
				}
			}
			done <- struct{}{}
		}()
	}
	for range goroutines {
		<-done
	}
	assert.Equal(t, uint64(goroutines*perGoroutine), accepted.Load()+dropped.Load())
}

// NewAsyncWriter panics on a nil store. A writer that buffers events
// with nowhere to send them is a programming error; the panic
// surfaces it at construction time rather than on the first Submit.
func TestAsyncWriter_NilStorePanics(t *testing.T) {
	assert.Panics(t, func() {
		_ = audit.NewAsyncWriter(nil, audit.AsyncOptions{})
	})
}

// Zero values for QueueCap + Logger fall through to the documented
// defaults; the writer constructs without ceremony for cmd/main's
// "use the defaults" path.
func TestAsyncWriter_ZeroOptionsUsesDefaults(t *testing.T) {
	store := audit.New(testdb.Open(t))
	w := audit.NewAsyncWriter(store, audit.AsyncOptions{})
	assert.NotNil(t, w)
}

// Sanity: the dropped slog line carries the payload so post-incident
// log scraping can reconstruct what didn't land in the DB.
func TestAsyncWriter_DropPreservesPayload(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&loggerWriter{&buf}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	w, _, _ := newWriterWithStore(t, 1, logger)

	require.True(t, w.Submit(t.Context(), api.AuditEvent{Action: "authz.host.read"}))
	w.Submit(t.Context(), api.AuditEvent{
		Action:  "authz.host.read",
		Payload: map[string]any{"reason": "granted", "host_id": "h-1"},
	})

	out := buf.String()
	assert.Contains(t, out, `"payload"`)
	assert.Contains(t, out, "h-1")
}

type loggerWriter struct{ b *strings.Builder }

func (w *loggerWriter) Write(p []byte) (int, error) { w.b.Write(p); return len(p), nil }

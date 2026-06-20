package audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
)

// slowRecorder is an auditRecorder whose Record blocks for a fixed duration, simulating a degraded DB. Used to make the shutdown drain
// overrun a tiny global deadline deterministically so the spill-to-slog tail (logUndrainedTail) fires without a real slow MySQL.
type slowRecorder struct {
	block time.Duration
	calls atomic.Int64
}

func (s *slowRecorder) Record(_ context.Context, _ api.AuditEvent) error {
	s.calls.Add(1)
	// Bounded sleep, not an unbounded block: shutdown() calls drain() synchronously, so Record MUST return for the drain loop to advance
	// past the first event and reach the deadline check that spills the rest.
	time.Sleep(s.block)
	return nil
}

// The global drain deadline path: when the shutdown drain runs out of wall-clock with events still queued, logUndrainedTail emits one
// "drain_deadline_exceeded" slog WARN per still-queued event, each carrying the event payload so post-incident log scraping can
// reconstruct what never reached the DB. This is the dual-emit fallback for the case the package-level shutdownDrainGlobal const guards
// in production. The test injects a tiny DrainDeadline plus a slow recorder so the first drained event overruns the budget and the rest
// spill, deterministically and in milliseconds rather than the 30s production default. shutdown() is invoked directly (not via Run +
// ctx cancel) because Run's select over ctx.Done() and the queue is intentionally non-deterministic; driving the drain directly is the
// only way to pin exactly which events remain queued when the deadline expires.
func TestAsyncWriter_DrainGlobalDeadline_SpillsToSlog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// 1ms budget vs a 40ms-per-event recorder: the first drained event alone overruns the deadline, so every event behind it spills.
	rec := &slowRecorder{block: 40 * time.Millisecond}
	w := newAsyncWriter(rec, AsyncOptions{
		QueueCap:      8,
		Logger:        logger,
		DrainDeadline: time.Millisecond,
	})

	const queued = 4
	payload := map[string]any{"marker": "undrained-payload", "host_id": "h-spill"}
	for range queued {
		require.True(t, w.Submit(context.Background(), api.AuditEvent{
			Action:  "authz.host.read",
			Payload: payload,
		}))
	}

	// shutdown() flips closed under the write lock and then drains synchronously. With a 1ms deadline the loop drains at most the first
	// event (the recorder makes it take 40ms) before the deadline check trips and the tail spills.
	w.shutdown()

	spilled := w.Dropped()
	assert.Positive(t, spilled, "at least one queued event must spill once the drain deadline is exceeded")
	assert.LessOrEqual(t, spilled, uint64(queued), "cannot spill more than were queued")
	assert.LessOrEqual(t, rec.calls.Load(), int64(1),
		"a 1ms deadline against a 40ms recorder must drain at most one event before spilling the rest")

	logs := buf.String()
	assert.Contains(t, logs, `"undrained-payload"`, "the spill line must carry the undrained event payload")
	assert.Contains(t, logs, "h-spill", "the spill line must carry the undrained payload fields")
	// logUndrainedTail emits one drain_deadline_exceeded record PER still-queued event, so the count of spill lines must equal Dropped().
	// Counting (rather than a single Contains) pins the per-event semantics: a regression that logged only the first undrained event, or
	// logged the tail once in aggregate, would still satisfy a bare Contains but fail this equality.
	spillLines := strings.Count(logs, `"reason":"drain_deadline_exceeded"`)
	assert.Equal(t, int(spilled), spillLines, //nolint:gosec // spilled <= queued (4), no overflow
		"each still-queued event must emit its own drain_deadline_exceeded slog record")
}

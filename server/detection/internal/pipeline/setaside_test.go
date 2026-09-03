package pipeline

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/setting-events-aside-is-counted-and-logged
//
// TestReportSetAside covers the visibility half of issue #836, which is the half that was unambiguously wrong before.
//
// Bounding the retries stops a host stalling forever; it does not tell anyone it happened. Without a counter and a log, a host with
// events withdrawn is indistinguishable from a quiet host, the backlog gauge does not separate them, and the only symptom
// is an absence of detections nobody is watching for.
//
// The zero case is asserted as carefully as the non-zero one. Every ordinary retryable nack passes through here, so a report that
// fired on zero would log and count on the common path and drown the signal it exists to raise.
func TestReportSetAside(t *testing.T) {
	t.Parallel()

	newProcessor := func() (*Processor, *bytes.Buffer, *capturingRecorder) {
		var logged bytes.Buffer
		rec := &capturingRecorder{}
		return &Processor{
			logger:  slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelError})),
			metrics: rec,
		}, &logged, rec
	}

	t.Run("counts and logs when events are set aside", func(t *testing.T) {
		t.Parallel()
		p, logged, rec := newProcessor()

		p.reportSetAside(t.Context(), "host-wedged", 7, "detection", errors.New("insert alert: Error 1406: Data too long"))

		require.Len(t, rec.setAside, 1, "the counter is what an operator alerts on")
		assert.Equal(t, "host-wedged", rec.setAside[0].hostID,
			"attributed per host: a fleet-wide total cannot say which host has the gap")
		assert.Equal(t, int64(7), rec.setAside[0].n)

		out := logged.String()
		assert.Contains(t, out, "host-wedged", "the log has to name the host, or the counter says only that it happened somewhere")
		assert.Contains(t, out, "detection", "and the stage that failed, so there is somewhere to look")
		assert.Contains(t, out, "never evaluated by detection rules",
			"and what that stage actually cost: the builder already folded these events in, so claiming a graph gap is false")
		assert.NotContains(t, out, "gap in its process graph",
			"the graph-gap consequence belongs to a builder-stage withdrawal only")
		assert.Contains(t, out, "Data too long",
			"and the failure itself: the retries that led here log at DEBUG, so without this the ERROR names a gap and no cause")
		assert.Contains(t, out, "level=ERROR",
			"a gap in a host's process graph is not a condition to notice in aggregate later")
	})

	t.Run("stays silent when nothing was set aside", func(t *testing.T) {
		t.Parallel()
		p, logged, rec := newProcessor()

		p.reportSetAside(t.Context(), "host-fine", 0, "builder", errors.New("transient"))

		assert.Empty(t, rec.setAside, "an ordinary retryable nack must not touch the counter")
		assert.Empty(t, logged.String(),
			"every retryable nack reaches here, so logging on zero would bury the signal under the common case")
	})

	t.Run("survives an unwired metrics recorder", func(t *testing.T) {
		t.Parallel()
		var logged bytes.Buffer
		p := &Processor{logger: slog.New(slog.NewTextHandler(&logged, nil))}

		// The recorder is installed after construction (the two-phase setup cmd/main uses), so a nil one is a real state and not
		// a defensive hypothetical.
		assert.NotPanics(t, func() { p.reportSetAside(t.Context(), "host-x", 3, "detection", errors.New("boom")) })
		assert.Contains(t, logged.String(), "host-x", "the log still fires, since it is the half that needs no wiring")
	})
}

// TestHostOf pins where the log's host attribute comes from.
//
// The processor claims per host, so every event in a batch carries the same one and the first is as good as any. The empty case is
// unreachable through the nack paths, since an empty batch never fails, and is covered because returning a host from an empty
// slice is the kind of thing a refactor turns into a panic.
func TestHostOf(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "host-a", hostOf([]visibilityapi.Event{{HostID: "host-a"}, {HostID: "host-a"}}))
	assert.Empty(t, hostOf(nil))
}

// TestQueuePruneRunner_PassesRetentionToTheSetAsideSweep covers the runner-to-store hop for the retention window.
//
// The acked-row sweep ignores retention entirely, so a runner built with a zero window still looks like it is working: it prunes
// acked rows on every tick and reports them. The set-aside half is the part that goes quiet, and quiet is exactly what a
// retention-disabled deployment is supposed to look like, so nothing else distinguishes "configured to keep them" from "the
// window was never plumbed through" (issue #836).
func TestQueuePruneRunner_PassesRetentionToTheSetAsideSweep(t *testing.T) {
	t.Parallel()

	log := &fakeEventLog{}
	runner := NewQueuePrune(log, QueuePruneOptions{RetentionDays: 30, Logger: discardLogger()})

	_, err := runner.Run(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []int{30}, log.setAsidePruned,
		"the sweep must hand the store the deployment's window; a zero here keeps set-aside rows for the life of the deployment")
}

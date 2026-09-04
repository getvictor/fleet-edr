package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// scriptedEventLog is an EventLog fake that hands ProcessOnce a fixed batch and records which IDs were acked vs nacked. Only the
// methods the processor's single-cycle path touches (PendingHosts, ClaimForHost, Ack, Nack) do anything; the rest are inert.
// PendingHosts reports the batch's own host so the processor's host-scoped cycle reaches ClaimForHost, and ClaimForHost serves the
// batch once so a drain loop terminates instead of re-serving the same events forever.
type scriptedEventLog struct {
	// setAside is what Nack reports as withdrawn, so a test can drive the reporting path without a real queue.
	setAside int64
	batch    []visibilityapi.Event
	acked    []string
	nacked   []string
	claimed  bool
	claimReq []string // hosts ClaimForHost was asked for, in order
	// ackErr makes Ack fail, which is the only way to exercise the branch where a batch was evaluated but NOT durably accepted.
	ackErr error
	// ackNotHeld makes Ack report that this claim no longer held the rows (issue #817), which is how the lost-claim branch is
	// reached without waiting out a real five-minute lease.
	ackNotHeld bool
	// ackStamps records the claim stamp each Ack was given, so a test can assert the processor passes back what it was handed
	// rather than a zero or a fresh value.
	ackStamps []int64
}

// scriptedClaimStamp is the stamp the scripted claim hands out. Non-zero so a test can tell it apart from an unset field.
const scriptedClaimStamp = int64(1_700_000_000_000_000_000)

func (s *scriptedEventLog) Append(context.Context, []visibilityapi.Event) error { return nil }
func (s *scriptedEventLog) PendingHosts(context.Context, int) ([]string, error) {
	if len(s.batch) == 0 || s.claimed {
		return nil, nil
	}
	return []string{s.batch[0].HostID}, nil
}

func (s *scriptedEventLog) ClaimForHost(_ context.Context, hostID string, _ int) ([]visibilityapi.Event, int64, error) {
	s.claimReq = append(s.claimReq, hostID)
	if s.claimed {
		return nil, 0, nil
	}
	s.claimed = true
	// A fixed non-zero stamp: the processor must pass back whatever it was handed, and zero would not distinguish "the stamp was
	// threaded through" from "the field was never set".
	return s.batch, scriptedClaimStamp, nil
}
func (s *scriptedEventLog) Ack(_ context.Context, ids []string, stamp int64) (bool, error) {
	s.ackStamps = append(s.ackStamps, stamp)
	if s.ackErr != nil {
		return false, s.ackErr
	}
	if s.ackNotHeld {
		return false, nil
	}
	s.acked = append(s.acked, ids...)
	return true, nil
}
func (s *scriptedEventLog) Nack(_ context.Context, ids []string) (int64, error) {
	s.nacked = append(s.nacked, ids...)
	return s.setAside, nil
}
func (s *scriptedEventLog) CountPending(context.Context) (int64, error)        { return 0, nil }
func (s *scriptedEventLog) PruneProcessed(context.Context, int) (int64, error) { return 0, nil }
func (s *scriptedEventLog) PruneSetAside(context.Context, int, int) (int64, error) {
	return 0, nil
}

// stubBuilder / stubEvaluator return a scripted error so a processor test can drive each nack/ack branch without a graph store.
type stubBuilder struct{ err error }

func (b stubBuilder) ProcessBatch(context.Context, []visibilityapi.Event) error { return b.err }

type stubEvaluator struct {
	err   error
	tally rulesapi.MonitorTally
}

func (e stubEvaluator) Evaluate(context.Context, []visibilityapi.Event) (rulesapi.MonitorTally, error) {
	return e.tally, e.err
}

// capturingLogHandler records every emitted record (at any level, so a debug line is observable) for level assertions.
type capturingLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *capturingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingLogHandler) WithGroup(string) slog.Handler      { return h }

// levelOf returns the level of the first record whose message contains substr, and whether one was found.
func (h *capturingLogHandler) levelOf(substr string) (slog.Level, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if strings.Contains(r.Message, substr) {
			return r.Level, true
		}
	}
	return 0, false
}

// singleCycleOpts is the shared wiring of the single-cycle tests below: one worker, batch of one, and no interval, so ProcessOnce
// drives exactly one claim/fold/evaluate cycle and each case asserts on what that cycle logged and counted. A handler per case keeps
// the captured records isolated under t.Parallel.
func singleCycleOpts(h slog.Handler) ProcessorOptions {
	return ProcessorOptions{Logger: slog.New(h), Interval: 0, Batch: 1, Concurrency: 1}
}

// newTestProcessor builds a processor for the single-cycle tests below and fails fast if construction refuses the options. Every
// case here wires a one-worker, no-coordinator processor, so the constructor error is never the property under test: folding it into a
// helper keeps each case's ProcessorOptions literal on one readable line.
func newTestProcessor(t *testing.T, log visibilityapi.EventLog, b batchBuilder, det batchEvaluator, opts ProcessorOptions) *Processor {
	t.Helper()
	p, err := NewProcessor(log, b, det, opts)
	require.NoError(t, err)
	return p
}

func oneEventBatch() []visibilityapi.Event {
	return []visibilityapi.Event{{EventID: "evt-1", HostID: "host-a", EventType: "network_connect"}}
}

// spec:observability-instrumentation/detection-materialization-miss-retries-are-bounded-in-log-volume/a-materialization-miss-retry-is-debug-logged-and-counted
// spec:observability-instrumentation/detection-materialization-miss-retries-are-bounded-in-log-volume/a-genuine-detection-failure-still-warn-logs
//
// The processor's classification of a nacked detection batch: a not-yet-materialized subject/flow process (the retryable
// ErrProcessNotYetMaterialized class, issue #631) is an expected transient race, so it must debug-log and increment the
// materialization-retry counter rather than warn-log per retry; any other failure keeps its warn line and does not count.
func TestProcessor_DetectionRetryClassification(t *testing.T) {
	t.Parallel()

	t.Run("materialization miss debug-logs and counts", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		// A wrapped sentinel mirrors how the engine returns it (fmt.Errorf("rule %s: %w", ...)).
		eval := stubEvaluator{err: fmt.Errorf("rule dns_c2_beacon: %w", rulesapi.ErrProcessNotYetMaterialized)}
		p := newTestProcessor(t, log, stubBuilder{}, eval, singleCycleOpts(handler))
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("awaiting process materialization")
		require.True(t, ok, "the materialization-miss retry must be logged")
		assert.Equal(t, slog.LevelDebug, lvl, "a materialization miss logs at debug, not warn")
		_, warned := handler.levelOf("detection failure, will retry batch")
		assert.False(t, warned, "a materialization miss must not emit the warn line")
		assert.Equal(t, int64(1), rec.materializationRetries, "the retry is counted")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "the batch is nacked for retry")
		assert.Empty(t, log.acked, "a failed batch is never acked")
	})

	t.Run("genuine failure warn-logs and does not count", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		eval := stubEvaluator{err: errors.New("persist detection alert: db down")}
		p := newTestProcessor(t, log, stubBuilder{}, eval, singleCycleOpts(handler))
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("detection failure, will retry batch")
		require.True(t, ok, "a genuine failure must be logged")
		assert.Equal(t, slog.LevelWarn, lvl, "a genuine failure logs at warn")
		assert.Zero(t, rec.materializationRetries, "a genuine failure is not counted as a materialization retry")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "the batch is nacked for retry")
	})

	t.Run("materialization miss is nil-metrics safe", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		eval := stubEvaluator{err: fmt.Errorf("rule x: %w", rulesapi.ErrProcessNotYetMaterialized)}
		p := newTestProcessor(t, log, stubBuilder{}, eval, singleCycleOpts(&capturingLogHandler{}))
		// No SetMetrics: the retry path must not dereference a nil recorder.
		assert.NotPanics(t, func() { p.ProcessOnce(context.Background()) })
		assert.Equal(t, []string{"evt-1"}, log.nacked)
	})
}

// TestProcessor_BuilderFailureAndHappyPath covers the two non-detection outcomes of a cycle: a graph-builder failure nacks + warns
// (its log is unchanged by issue #631), and a fully successful cycle acks the batch and counts no retry.
func TestProcessor_BuilderFailureAndHappyPath(t *testing.T) {
	t.Parallel()

	t.Run("builder failure nacks and warn-logs", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		handler := &capturingLogHandler{}
		rec := &capturingRecorder{}
		p := newTestProcessor(t, log, stubBuilder{err: errors.New("graph write failed")}, stubEvaluator{}, singleCycleOpts(handler))
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		lvl, ok := handler.levelOf("graph builder failure, will retry batch")
		require.True(t, ok, "a builder failure must be logged")
		assert.Equal(t, slog.LevelWarn, lvl, "a builder failure logs at warn")
		assert.Equal(t, []string{"evt-1"}, log.nacked)
		assert.Zero(t, rec.materializationRetries, "a builder failure is not a materialization retry")
	})

	t.Run("successful cycle acks and counts no retry", func(t *testing.T) {
		t.Parallel()
		log := &scriptedEventLog{batch: oneEventBatch()}
		rec := &capturingRecorder{}
		p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{}, singleCycleOpts(&capturingLogHandler{}))
		p.SetMetrics(rec)

		p.ProcessOnce(context.Background())

		assert.Equal(t, []string{"evt-1"}, log.acked, "a clean batch is acked")
		assert.Empty(t, log.nacked, "a clean batch is never nacked")
		assert.Zero(t, rec.materializationRetries)
	})
}

// recordingMonitorRecorder captures what the processor persists, and can be made to fail.
type recordingMonitorRecorder struct {
	calls []rulesapi.MonitorTally
	err   error
}

func (r *recordingMonitorRecorder) RecordMonitorMatches(_ context.Context, tally rulesapi.MonitorTally) error {
	r.calls = append(r.calls, tally)
	return r.err
}

// countingMonitorMetrics sums the counts passed to MonitorMatched.
type countingMonitorMetrics struct {
	capturingRecorder
	total int
}

func (m *countingMonitorMetrics) MonitorMatched(_ context.Context, _, _ string, n int) { m.total += n }

// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/a-monitor-match-is-counted-once-for-a-batch-that-is-retried
// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/a-recording-failure-does-not-fail-the-batch
//
// TestProcessor_RecordsMonitorMatchesOnlyAfterTheAck pins WHEN the counts are written, which is the whole reason the engine hands
// a tally back instead of writing one itself.
//
// A batch that fails detection is nacked and replayed whole, so a count written during evaluation is written again by every
// retry. Issue #631 measured roughly 130 materialization retries a minute from one host under a sustained condition, which is
// enough to make a promotion decision read as far more expensive than it is.
func TestProcessor_RecordsMonitorMatchesOnlyAfterTheAck(t *testing.T) {
	t.Parallel()

	tally := rulesapi.MonitorTally{{RuleID: "imported", HostID: "host-a", Severity: "high", Count: 2}}

	t.Run("a nacked batch records nothing", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		log := &scriptedEventLog{batch: oneEventBatch()}
		// The evaluator reports a tally AND fails, which is the shape a real retryable miss takes: some rules matched before
		// another asked for the batch to come round again.
		eval := stubEvaluator{tally: tally, err: errors.New("persist detection alert: db down")}
		p := newTestProcessor(t, log, stubBuilder{}, eval, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(context.Background())

		assert.Empty(t, rec.calls, "the batch was nacked and will be replayed; recording now would count it twice")
		assert.Zero(t, metrics.total, "and the counter must not move either, for the same reason")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "the batch really was nacked, so the assertions above are about that path")
	})

	t.Run("an acked batch records once", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		log := &scriptedEventLog{batch: oneEventBatch()}
		p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{tally: tally}, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(context.Background())

		require.Len(t, rec.calls, 1)
		assert.Equal(t, tally, rec.calls[0])
		assert.Equal(t, 2, metrics.total, "the counter is added in the same place, so the two series cannot disagree")
		assert.Equal(t, []string{"evt-1"}, log.acked)
	})

	t.Run("the counter still moves when no durable recorder is wired", func(t *testing.T) {
		t.Parallel()
		// Two independent consumers of the same tally. A deployment without the rules-context store (ModeIntake, or a test)
		// still emits the OTel series, because monitor mode's observability signal is not conditional on the durable table
		// existing. Ordering the nil check before the counter would silence it everywhere the store is absent, which is exactly
		// the deployment least likely to notice.
		metrics := &countingMonitorMetrics{}
		log := &scriptedEventLog{batch: oneEventBatch()}
		p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{tally: tally}, singleCycleOpts(&capturingLogHandler{}))
		p.SetMetrics(metrics)

		p.ProcessOnce(context.Background())

		assert.Equal(t, 2, metrics.total)
	})

	t.Run("a failed ack records nothing, in either sink", func(t *testing.T) {
		t.Parallel()
		// The guarantee is "recorded once the batch is ACCEPTED", and an Ack that errors means it was not: the events stay leased
		// and will be re-served. Without this case the suite cannot tell "records after a successful ack" from "records after
		// evaluation regardless of the ack", because the only ack in the other tests always succeeds.
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		log := &scriptedEventLog{batch: oneEventBatch(), ackErr: errors.New("queue unavailable")}
		p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{tally: tally}, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(context.Background())

		assert.Empty(t, rec.calls, "the batch was not durably accepted, so its matches are not this attempt's to record")
		assert.Zero(t, metrics.total, "and the counter must not move either, or the re-served batch counts twice")
	})

	t.Run("a recording failure does not nack the acked batch", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{err: errors.New("db down")}
		handler := &capturingLogHandler{}
		log := &scriptedEventLog{batch: oneEventBatch()}
		p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{tally: tally}, singleCycleOpts(handler))
		p.SetMonitorMatchRecorder(rec)

		p.ProcessOnce(context.Background())

		assert.Empty(t, log.nacked,
			"the events are already acknowledged; replaying real detection work to save a counter is the wrong trade")
		_, logged := handler.levelOf("record monitor matches")
		assert.True(t, logged, "the failure is dropped, but not silently")
	})
}

// spec:server-detection-rules-engine/rule-failure-isolation-batch-retry-on-persistence-failure/a-failed-process-graph-read-retries-the-batch-instead-of-acknowledging-it
//
// TestProcessor_FailedGraphReadIsNackedNotAcked joins the two halves of issue #798's fix.
//
// The engine test proves a failed graph read comes back as a retryable error; the processor tests above prove a retryable error is
// nacked. Nothing joined them, and "the two halves are covered separately" is exactly how #836's withdrawal stamp shipped
// untested. This drives the error in the SHAPE the read decorator actually produces, wrapped the way a rule then wraps it, and
// asserts the outcome that matters: the events go back on the queue instead of being acknowledged and never evaluated again.
//
// It also pins the classification the other way. A read failure must NOT be counted as a materialization retry: that counter is
// how an operator spots a replica falling behind on graph materialization, and a database outage is a different condition with a
// different response.
func TestProcessor_FailedGraphReadIsNackedNotAcked(t *testing.T) {
	t.Parallel()

	log := &scriptedEventLog{batch: oneEventBatch()}
	handler := &capturingLogHandler{}
	rec := &capturingRecorder{}
	// The decorator's shape (graph read <name> unavailable: <cause>: ErrRetryBatch), wrapped again by the rule and the engine.
	readFailure := fmt.Errorf("rule dns_c2_beacon: get network events for pid 42: graph read GetNetworkEventsForProcess "+
		"unavailable: dial tcp: connect: connection refused: %w", rulesapi.ErrRetryBatch)
	p := newTestProcessor(t, log, stubBuilder{}, stubEvaluator{err: readFailure}, singleCycleOpts(handler))
	p.SetMetrics(rec)

	p.ProcessOnce(context.Background())

	assert.Equal(t, []string{"evt-1"}, log.nacked,
		"a failed graph read must return the batch to the queue; acking it loses the detections for every event in flight")
	assert.Empty(t, log.acked, "and must never acknowledge it")
	assert.Zero(t, rec.materializationRetries,
		"a dependency outage is not a materialization race, and must not inflate the counter that tracks one")
}

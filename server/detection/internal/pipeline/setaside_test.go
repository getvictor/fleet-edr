package pipeline

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/setting-events-aside-is-counted-and-logged
//
// TestReportSetAside covers the visibility half of issue #836, which is the half that was unambiguously wrong before.
//
// Bounding the retries stops a host stalling forever; it does not tell anyone it happened. Without a counter and a log, a host that
// has given up part of its activity is indistinguishable from a quiet host, the backlog gauge does not separate them, and the only
// symptom is an absence of detections nobody is watching for.
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

		p.reportSetAside(t.Context(), "host-wedged", 7, stageDetection)

		require.Len(t, rec.setAside, 1, "the counter is what an operator alerts on")
		assert.Equal(t, "host-wedged", rec.setAside[0].hostID,
			"attributed per host: a fleet-wide total cannot say which host stopped contributing")
		assert.Equal(t, int64(7), rec.setAside[0].n)

		out := logged.String()
		assert.Contains(t, out, "host-wedged", "the log has to name the host, or the counter says only that it happened somewhere")
		assert.Contains(t, out, "detection", "and the stage that failed, so there is somewhere to look")
		assert.Contains(t, out, "level=ERROR",
			"losing events from a host's processing is not a condition to notice in aggregate later")
	})

	t.Run("stays silent when nothing was set aside", func(t *testing.T) {
		t.Parallel()
		p, logged, rec := newProcessor()

		p.reportSetAside(t.Context(), "host-fine", 0, stageBuilder)

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
		assert.NotPanics(t, func() { p.reportSetAside(t.Context(), "host-x", 3, stageDetection) })
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

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/the-record-states-the-consequence-for-its-stage
//
// TestSetAsideConsequenceMatchesTheStage is what the record is FOR: it tells an operator what to go and look at.
//
// Both stages reported a gap in the process graph, and for detection that is false. processHost returns before evaluation when
// the fold failed, so evaluateAndAck only ever runs on an already-materialised batch: one withdrawn there IS in the graph, and the
// claim sent an operator to inspect a process tree that was intact, which is worse than saying nothing.
//
// Driven through ProcessOnce rather than by calling reportSetAside directly, and review was right to insist on the difference. The
// stage now SELECTS the consequence, so the thing that can go wrong is a call site passing the other one; calling the reporter
// directly tests the lookup while leaving both call sites unexercised, and transposing them there would keep such a test green
// while recreating the operator-facing defect exactly.
//
// The failures are the two that reach a withdrawal: a graph builder that cannot write, and a detection error. Nack is scripted to
// report a non-zero withdrawal so the reporting path is reached without waiting out a real attempt bound.
func TestSetAsideConsequenceMatchesTheStage(t *testing.T) {
	t.Parallel()

	// withdrawnBy runs one full cycle whose named stage fails, and returns the set-aside record the pipeline emitted.
	withdrawnBy := func(t *testing.T, buildErr, detectErr error) (msg, stage, consequence string) {
		t.Helper()
		h := &capturingLogHandler{}
		log := &scriptedEventLog{setAside: 3, batch: []visibilityapi.Event{{EventID: "e-1", HostID: "host-a"}}}
		p := newTestProcessor(t, log, stubBuilder{err: buildErr}, stubEvaluator{err: detectErr}, singleCycleOpts(h))
		p.ProcessOnce(t.Context())
		return setAsideRecord(t, h)
	}

	t.Run("a batch withdrawn while the graph was being built reports a possible graph gap", func(t *testing.T) {
		t.Parallel()
		_, stage, consequence := withdrawnBy(t, errors.New("graph store unavailable"), nil)

		assert.Equal(t, "builder", stage)
		assert.Equal(t, "this host may have a gap in its process graph", consequence,
			"the fold failed on this attempt, and an earlier attempt may already have folded these events, so the definite form "+
				"is not something this record can claim")
	})

	t.Run("a batch withdrawn at detection does not claim a graph gap", func(t *testing.T) {
		t.Parallel()
		_, stage, consequence := withdrawnBy(t, nil, errors.New("alert store unavailable"))

		assert.Equal(t, "detection", stage)
		assert.NotContains(t, consequence, "process graph",
			"the builder completed before detection ran, so this host's process tree is intact")
		assert.Equal(t, "detection did not complete for these events, so alerts they would have raised may be missing", consequence)
	})

	t.Run("the detection consequence does not blame a step it cannot identify", func(t *testing.T) {
		t.Parallel()
		_, _, consequence := withdrawnBy(t, nil, errors.New("insert alert: deadlock"))

		// A rule's own non-retryable error never leaves the engine: evaluateRule logs it and returns nil for per-rule isolation.
		// What does leave is an alert-persistence error, returned from inside routeFinding's loop so the batch aborts at the
		// finding it happened on, or a retryable miss that ran out of attempts. Naming rule evaluation would point a responder
		// at rule execution while the failure was in alert storage: the graph-gap defect again, one layer down.
		assert.NotContains(t, consequence, "rule evaluation",
			"a persistence failure withdraws the batch without any rule having failed")
		assert.NotContains(t, consequence, "never evaluated",
			"evaluation ran, so claiming none happened would be a second false statement")
		assert.Contains(t, consequence, "may be missing",
			"alerts written before the failure are durable, so overstating the loss sends someone hunting for alerts that exist")
	})

	t.Run("the message stays fixed so the line remains greppable", func(t *testing.T) {
		t.Parallel()
		fromBuilder, _, _ := withdrawnBy(t, errors.New("graph store unavailable"), nil)
		fromDetection, _, _ := withdrawnBy(t, nil, errors.New("alert store unavailable"))

		// Equality, not containment. A stage-specific suffix would still contain the common prefix, and an alert or a saved
		// search authored on the exact line is what the fixed message exists to keep working.
		assert.Equal(t, "queued events set aside after repeated failure", fromBuilder)
		assert.Equal(t, fromBuilder, fromDetection,
			"the consequence rides on an attribute precisely so the message can stay constant")
	})
}

// replayingEventLog serves one host's batch on EVERY cycle, which scriptedEventLog deliberately does not: it serves once so a
// drain loop terminates. A batch that is retried and eventually withdrawn is served many times, and a test about what the
// withdrawal says cannot reach the interesting sequences with a log that only answers once.
//
// withdrawOn is the cycle whose Nack reports the withdrawal, which stands in for the attempt and duration bounds a real queue row
// carries. Those bounds accrue on the ROW, not on the stage that nacked it, which is the property the test below turns on.
type replayingEventLog struct {
	batch      []visibilityapi.Event
	withdrawOn int
	nacks      int
}

func (l *replayingEventLog) Append(context.Context, []visibilityapi.Event) error { return nil }
func (l *replayingEventLog) PendingHosts(context.Context, int) ([]string, error) {
	return []string{l.batch[0].HostID}, nil
}

func (l *replayingEventLog) ClaimForHost(context.Context, string, int) ([]visibilityapi.Event, int64, error) {
	return l.batch, scriptedClaimStamp, nil
}
func (l *replayingEventLog) Ack(context.Context, []string, int64) (bool, error) { return true, nil }
func (l *replayingEventLog) Nack(context.Context, []string, int64) (int64, error) {
	l.nacks++
	if l.nacks < l.withdrawOn {
		return 0, nil
	}
	return int64(len(l.batch)), nil
}
func (l *replayingEventLog) CountPending(context.Context) (int64, error)            { return 0, nil }
func (l *replayingEventLog) PruneProcessed(context.Context, int) (int64, error)     { return 0, nil }
func (l *replayingEventLog) PruneSetAside(context.Context, int, int) (int64, error) { return 0, nil }

// failOnCycle is a builder that succeeds until the given cycle, so a test can fold a batch first and fail its fold later.
//
// folded counts the SUCCESSFUL folds, which is the number a caller has to assert on. Counting calls does not distinguish a fixture
// that folded once and then failed from one that failed both times, and the second reaches the same record while proving nothing.
type failOnCycle struct {
	failFrom int
	cycles   int
	folded   int
}

func (b *failOnCycle) ProcessBatch(context.Context, []visibilityapi.Event) error {
	b.cycles++
	if b.cycles < b.failFrom {
		b.folded++
		return nil
	}
	return errors.New("graph store unavailable")
}

// spec:server-event-ingestion/a-batch-that-cannot-be-processed-does-not-stall-its-host/the-record-states-the-consequence-for-its-stage
//
// TestSetAsideAtTheBuilderDoesNotClaimACertainGap covers the sequence that makes the DEFINITE form of the builder consequence
// false, which review found and which the first version of this fix would have shipped.
//
// The bounds that withdraw a batch accrue on the queue row and count every attempt, whichever stage nacked it. So a batch can fold
// successfully, fail at detection, and be withdrawn later on an attempt whose fold is what failed. Those events are in the graph,
// put there by the first attempt, and nothing on the row records that they got that far. The record cannot distinguish that from a
// batch that never folded at all, so it must not claim it can.
//
// Asserted as the absence of the definite claim rather than only the presence of the hedged one, because the point is what the
// record must NOT tell a responder. A future wording that hedges differently should still pass; one that goes back to asserting a
// gap should not.
func TestSetAsideAtTheBuilderDoesNotClaimACertainGap(t *testing.T) {
	t.Parallel()

	h := &capturingLogHandler{}
	log := &replayingEventLog{
		batch:      []visibilityapi.Event{{EventID: "e-1", HostID: "host-a"}},
		withdrawOn: 2,
	}
	// Cycle 1 folds and fails at detection; cycle 2 fails at the fold and is the one that withdraws.
	builder := &failOnCycle{failFrom: 2}
	p := newTestProcessor(t, log, builder, stubEvaluator{err: errors.New("alert store unavailable")}, singleCycleOpts(h))
	p.ProcessOnce(t.Context())
	p.ProcessOnce(t.Context())

	// Pinned, because the whole point is the sequence and not the outcome: a fixture that failed the fold on BOTH cycles would
	// reach the same record while proving nothing, and would keep passing after the wording went back to a definite claim.
	require.Equal(t, 2, builder.cycles, "the fold ran on both cycles")
	require.Equal(t, 1, builder.folded,
		"cycle 1 must have folded SUCCESSFULLY: a fixture that failed both folds reaches the same record and proves nothing")
	require.Equal(t, 2, log.nacks, "cycle 1 nacked at detection and cycle 2 at the fold")

	_, stage, consequence := setAsideRecord(t, h)
	require.Equal(t, "builder", stage, "the withdrawing attempt is the one whose fold failed")
	assert.NotContains(t, consequence, "has a gap",
		"the first attempt folded these events, so the graph is not necessarily missing them")
	assert.Contains(t, consequence, "may have a gap",
		"the record still has to send someone to look, since it cannot tell this from a batch that never folded")
}

// setAsideRecord returns the message, stage and consequence of the one set-aside record a cycle emitted.
//
// Selects on a fragment of the message and then asserts the whole of it in the caller, which is deliberate: the selector has to
// keep finding the record for a message that grew a suffix, or the assertion that would catch the suffix never runs.
func setAsideRecord(t *testing.T, h *capturingLogHandler) (msg, stage, consequence string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()

	var found []slog.Record
	for _, r := range h.records {
		if r.Level == slog.LevelError && strings.Contains(r.Message, "set aside") {
			found = append(found, r)
		}
	}
	require.Len(t, found, 1, "one withdrawal emits exactly one record")

	found[0].Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "stage":
			stage = a.Value.String()
		case "consequence":
			consequence = a.Value.String()
		}
		return true
	})
	return found[0].Message, stage, consequence
}

// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/a-withdrawn-batch-is-counted-once-not-lost
// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/a-partly-withdrawn-batch-is-not-counted-yet
// spec:observability-instrumentation/monitor-mode-matches-are-recorded-durably-per-rule/a-withdrawal-before-evaluation-records-nothing
//
// TestMonitorMatchesRecordedWhenTheBatchIsWithdrawn covers the gap #842 left and #843 names: a monitor-mode match resolved before
// a batch failed was recorded nowhere if that batch was ultimately set aside.
//
// Discarding the tally on every retryable error is right and stays right: the batch comes back and produces the same matches
// again, so recording per attempt counts a retried batch once per retry. The gap is the terminal case, where there is no later
// attempt to be counted on, and it under-reports for exactly the hosts that had processing trouble. The count is what the
// detection-tuning table shows an operator deciding whether to promote a monitor-mode rule, and imported rules default to monitor,
// so under-reporting biases that decision toward "this rule is quiet".
//
// The partial case is asserted alongside, because it is the reason the condition compares against the batch rather than against
// zero. The withdrawal predicate is per ROW, so a partially withdrawn batch leaves rows that are claimed and evaluated again,
// while the tally covers all of them.
func TestMonitorMatchesRecordedWhenTheBatchIsWithdrawn(t *testing.T) {
	t.Parallel()

	tally := rulesapi.MonitorTally{{RuleID: "imported", HostID: "host-a", Severity: "high", Count: 2}}
	// Fails the way a real withdrawal is reached: the rules matched, and then something asked for the batch to come round again
	// until its bounds ran out.
	failing := stubEvaluator{tally: tally, err: errors.New("persist detection alert: db down")}

	twoEvents := []visibilityapi.Event{
		{EventID: "evt-1", HostID: "host-a", EventType: "network_connect"},
		{EventID: "evt-2", HostID: "host-a", EventType: "network_connect"},
	}

	t.Run("a withdrawn batch records what it matched", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		log := &scriptedEventLog{batch: oneEventBatch(), setAside: 1}
		p := newTestProcessor(t, log, stubBuilder{}, failing, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(t.Context())

		require.Len(t, rec.calls, 1, "the batch will never be evaluated again, so this attempt is the last word on what it matched")
		assert.Equal(t, tally, rec.calls[0])
		// Only that both moved on this path. The counter is incremented BEFORE the durable write, so a recorder failure leaves
		// them different by design, and claiming they cannot disagree would be a stronger promise than the code makes.
		assert.Equal(t, 2, metrics.total, "the counter moves on the same path as the durable record")
		assert.Equal(t, []string{"evt-1"}, log.nacked, "and it really was the withdrawal path, not the ack")
		assert.Empty(t, log.acked)
	})

	t.Run("a withdrawal before evaluation records nothing, and does not reach back", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		log := &replayingEventLog{batch: oneEventBatch(), withdrawOn: 2}
		// Cycle 1 evaluates and fails at detection; cycle 2 fails at the FOLD, and is the attempt that withdraws.
		builder := &failOnCycle{failFrom: 2}
		p := newTestProcessor(t, log, builder, failing, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(t.Context())
		p.ProcessOnce(t.Context())

		require.Equal(t, 1, builder.folded, "cycle 1 must have folded and reached detection, or this proves nothing")
		assert.Empty(t, rec.calls,
			"the withdrawing attempt never evaluated, and cycle 1's matches were discarded when cycle 1 was retried")
		assert.Zero(t, metrics.total)
	})

	t.Run("a partly withdrawn batch records nothing, and its survivor is counted by the attempt that finishes it", func(t *testing.T) {
		t.Parallel()
		rec := &recordingMonitorRecorder{}
		metrics := &countingMonitorMetrics{}
		// One of the two rows passed its bounds; the other is still coming back.
		log := &scriptedEventLog{batch: twoEvents, setAside: 1}
		p := newTestProcessor(t, log, stubBuilder{}, failing, singleCycleOpts(&capturingLogHandler{}))
		p.SetMonitorMatchRecorder(rec)
		p.SetMetrics(metrics)

		p.ProcessOnce(t.Context())

		require.Empty(t, rec.calls,
			"the surviving row is evaluated again and this tally covers it, so recording now would count it twice")
		require.Zero(t, metrics.total)

		// The other half of the scenario, and the half that makes the first half acceptable rather than merely safe. Stopping at
		// the nack would pass just as well against a processor that had stopped counting the survivor at all, which is the same
		// loss this whole change is about.
		survivor := &scriptedEventLog{batch: twoEvents[1:]}
		finishing := newTestProcessor(t, survivor, stubBuilder{}, stubEvaluator{tally: tally}, singleCycleOpts(&capturingLogHandler{}))
		finishing.SetMonitorMatchRecorder(rec)
		finishing.SetMetrics(metrics)

		finishing.ProcessOnce(t.Context())

		require.Len(t, rec.calls, 1, "the survivor's own attempt acknowledges and records, exactly once")
		assert.Equal(t, tally, rec.calls[0])
		assert.Equal(t, 2, metrics.total)
		assert.Equal(t, []string{"evt-2"}, survivor.acked)
	})
}

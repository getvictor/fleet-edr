package detectionconfig_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
)

// countingRecorder stands in for the durable store, and records what it was asked to write rather than writing it.
type countingRecorder struct {
	mu      sync.Mutex
	calls   int
	written []api.RuleEvalStats
	failFor int // fail this many calls before succeeding, which is how a transient database problem is modelled
}

func (r *countingRecorder) RecordRuleEvalStats(_ context.Context, stats api.RuleEvalStats) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.failFor > 0 {
		r.failFor--
		return errors.New("write failed")
	}
	r.written = append(r.written, stats)
	return nil
}

func (r *countingRecorder) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// lastWritten returns the most recent write as a map keyed by rule id, which is how the assertions want it: a flush writes one
// entry per rule in map order, so comparing slices would pin an order the type does not promise.
func (r *countingRecorder) lastWritten() map[string]api.RuleEvalStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.written) == 0 {
		return nil
	}
	out := map[string]api.RuleEvalStat{}
	for _, s := range r.written[len(r.written)-1] {
		out[s.RuleID] = s
	}
	return out
}

// spec:server-detection-rules-engine/evaluation-statistics-are-aggregated-in-process-and-written-periodically/processing-a-batch-performs-no-statistics-write
//
// TestBufferedEvalStats_RecordTouchesNoDatabase is issue #837's first acceptance criterion, and the whole point of the change: the
// drain path performs no write for evaluation statistics.
//
// Asserted by call count rather than by timing, so it states the property instead of a proxy for it.
func TestBufferedEvalStats_RecordTouchesNoDatabase(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)

	for range 100 {
		require.NoError(t, b.RecordRuleEvalStats(t.Context(), api.RuleEvalStats{
			{RuleID: "r1", Evaluations: 1, EvalNs: 10},
			{RuleID: "r2", Evaluations: 1, EvalNs: 20},
		}))
	}

	assert.Zero(t, inner.callCount(), "recording a batch must not reach the store; that was the ingest cap")
	assert.Equal(t, 2, b.PendingRules(), "and the map is keyed by rule, so 100 batches over 2 rules hold 2 entries")
}

// spec:server-detection-rules-engine/evaluation-statistics-are-aggregated-in-process-and-written-periodically/a-flush-writes-the-exact-aggregate
//
// TestBufferedEvalStats_FlushWritesTheAggregate covers the counters' exactness, which is the criterion that keeps this from being
// a lossy shortcut: a flush must write what the per-batch writes would have accumulated.
func TestBufferedEvalStats_FlushWritesTheAggregate(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)

	batches := []api.RuleEvalStats{
		{{RuleID: "slow", Evaluations: 1, RetryableMisses: 0, EvalNs: 500, MaxEvalNs: 500}},
		{{RuleID: "slow", Evaluations: 1, RetryableMisses: 1, EvalNs: 100, MaxEvalNs: 100}},
		{{RuleID: "slow", Evaluations: 1, RetryableMisses: 0, EvalNs: 300, MaxEvalNs: 300}},
		{{RuleID: "fast", Evaluations: 1, RetryableMisses: 0, EvalNs: 7, MaxEvalNs: 7}},
	}
	for _, batch := range batches {
		require.NoError(t, b.RecordRuleEvalStats(t.Context(), batch))
	}
	require.NoError(t, b.Flush(t.Context()))

	written := inner.lastWritten()
	require.Len(t, written, 2)
	assert.Equal(t, api.RuleEvalStat{RuleID: "slow", Evaluations: 3, RetryableMisses: 1, EvalNs: 900, MaxEvalNs: 500},
		written["slow"], "sums add and the worst single evaluation takes the larger, not the latest")
	assert.Equal(t, api.RuleEvalStat{RuleID: "fast", Evaluations: 1, EvalNs: 7, MaxEvalNs: 7}, written["fast"])
	assert.Zero(t, b.PendingRules(), "a successful flush leaves nothing behind to double-count")
}

// TestBufferedEvalStats_FlushIsAggregationOverAnyBatchSequence is the same property over an input space no table covers.
//
// PBT rather than more rows because the invariant is algebraic: for any sequence of batches over any set of rules, one flush
// writes the fold of them, sums added and the maximum taken. That is the property that makes buffering equivalent to the
// per-batch write it replaces, so it is worth stating over the space rather than at four points.
func TestBufferedEvalStats_FlushIsAggregationOverAnyBatchSequence(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		inner := &countingRecorder{}
		b := detectionconfig.NewBufferedEvalStats(inner, nil)

		ruleIDs := rapid.SliceOfNDistinct(
			rapid.SampledFrom([]string{"r1", "r2", "r3", "r4"}), 1, 4, func(s string) string { return s },
		).Draw(t, "rules")

		// The expected fold, computed independently of the implementation.
		want := map[string]api.RuleEvalStat{}
		batches := rapid.IntRange(1, 12).Draw(t, "batches")
		for range batches {
			var batch api.RuleEvalStats
			for _, id := range ruleIDs {
				if !rapid.Bool().Draw(t, "ran") {
					// A rule the batch handed no event to is ABSENT rather than zero, which the type's own doc requires.
					continue
				}
				s := api.RuleEvalStat{
					RuleID:          id,
					Evaluations:     int64(rapid.IntRange(1, 5).Draw(t, "evals")),
					RetryableMisses: int64(rapid.IntRange(0, 2).Draw(t, "misses")),
					EvalNs:          int64(rapid.IntRange(0, 1_000_000).Draw(t, "ns")),
				}
				s.MaxEvalNs = s.EvalNs
				batch = append(batch, s)

				agg := want[id]
				agg.RuleID = id
				agg.Evaluations += s.Evaluations
				agg.RetryableMisses += s.RetryableMisses
				agg.EvalNs += s.EvalNs
				agg.MaxEvalNs = max(agg.MaxEvalNs, s.MaxEvalNs)
				want[id] = agg
			}
			require.NoError(t, b.RecordRuleEvalStats(context.Background(), batch))
		}

		require.NoError(t, b.Flush(context.Background()))
		if len(want) == 0 {
			assert.Zero(t, inner.callCount(), "nothing accumulated means nothing to write")
			return
		}
		assert.Equal(t, want, inner.lastWritten())
		assert.Equal(t, 1, inner.callCount(), "however many batches accumulated, the store sees one write")
	})
}

// spec:server-detection-rules-engine/evaluation-statistics-are-aggregated-in-process-and-written-periodically/a-failed-flush-discards-that-window-and-reports-it
//
// TestBufferedEvalStats_AFailedWriteDiscardsThatWindow pins the choice made in review after two rounds spent narrowing what a
// retry could promise.
//
// The write is an additive upsert, so retrying it is at-least-once: it can double a window's contribution and, because later work
// merges in between attempts, move the derived mean. Neither retrying nor discarding gives exact totals once the database is
// failing, so this takes the one that can be stated in a sentence. Losing a window is what issue #837 says buffering costs.
func TestBufferedEvalStats_AFailedWriteDiscardsThatWindow(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{failFor: 1}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)

	require.NoError(t, b.RecordRuleEvalStats(t.Context(), api.RuleEvalStats{
		{RuleID: "r1", Evaluations: 2, EvalNs: 40, MaxEvalNs: 30},
	}))
	require.Error(t, b.Flush(t.Context()), "the write fails")
	assert.Zero(t, b.PendingRules(), "and the window goes with it rather than being held for a retry")

	// Work after the failure is unaffected, which is the property that matters: a failed window costs that window and nothing
	// beyond it.
	require.NoError(t, b.RecordRuleEvalStats(t.Context(), api.RuleEvalStats{
		{RuleID: "r1", Evaluations: 1, EvalNs: 5, MaxEvalNs: 5},
	}))
	require.NoError(t, b.Flush(t.Context()))
	assert.Equal(t, api.RuleEvalStat{RuleID: "r1", Evaluations: 1, EvalNs: 5, MaxEvalNs: 5}, inner.lastWritten()["r1"],
		"the second window is written whole, with nothing carried over from the first")
}

// spec:server-detection-rules-engine/evaluation-statistics-are-aggregated-in-process-and-written-periodically/a-graceful-shutdown-writes-what-it-had-accumulated
//
// TestBufferedEvalStats_FlushLoopWritesOnShutdown covers the graceful-shutdown criterion. The final write deliberately does not
// use the cancelled context, which would fail it immediately, so this also pins that the flush actually reaches the store.
func TestBufferedEvalStats_FlushLoopWritesOnShutdown(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)
	require.NoError(t, b.RecordRuleEvalStats(t.Context(), api.RuleEvalStats{
		{RuleID: "r1", Evaluations: 4, EvalNs: 99, MaxEvalNs: 60},
	}))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// An interval far longer than the test, so what is measured is the shutdown flush and never a tick.
		b.FlushLoop(ctx, time.Hour)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("FlushLoop did not return after its context was cancelled")
	}

	assert.Equal(t, api.RuleEvalStat{RuleID: "r1", Evaluations: 4, EvalNs: 99, MaxEvalNs: 60}, inner.lastWritten()["r1"],
		"a graceful shutdown must not lose the window it had accumulated")
	assert.Zero(t, b.PendingRules())
}

// TestBufferedEvalStats_FlushLoopWritesOnTheInterval is the other half: the loop must actually write without a shutdown, or the
// table would only ever update when a replica stopped.
func TestBufferedEvalStats_FlushLoopWritesOnTheInterval(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)
	require.NoError(t, b.RecordRuleEvalStats(t.Context(), api.RuleEvalStats{{RuleID: "r1", Evaluations: 1}}))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go b.FlushLoop(ctx, 10*time.Millisecond)

	require.Eventually(t, func() bool { return inner.callCount() > 0 }, 5*time.Second, 10*time.Millisecond,
		"the ticker must write without waiting for a shutdown")
}

// TestBufferedEvalStats_FlushWithNothingPendingWritesNothing keeps an idle replica off the database entirely. A deployment with
// several idle replicas would otherwise write one no-op statement each per interval, forever.
func TestBufferedEvalStats_FlushWithNothingPendingWritesNothing(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)
	require.NoError(t, b.Flush(t.Context()))
	assert.Zero(t, inner.callCount())
}

// TestBufferedEvalStats_ConcurrentRecordersAgree runs the drain path the way production does, from several workers at once, and
// checks the total rather than only that the race detector stays quiet.
func TestBufferedEvalStats_ConcurrentRecordersAgree(t *testing.T) {
	t.Parallel()

	inner := &countingRecorder{}
	b := detectionconfig.NewBufferedEvalStats(inner, nil)

	const workers, perWorker = 6, 50
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perWorker {
				_ = b.RecordRuleEvalStats(context.Background(), api.RuleEvalStats{
					{RuleID: "r1", Evaluations: 1, EvalNs: 2, MaxEvalNs: 2},
				})
			}
		})
	}
	wg.Wait()
	require.NoError(t, b.Flush(t.Context()))

	assert.Equal(t, int64(workers*perWorker), inner.lastWritten()["r1"].Evaluations,
		"six workers is what a replica actually runs, and no count may be dropped between them")
}

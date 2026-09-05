package detectionconfig

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// DefaultEvalStatsFlushInterval is how often a replica writes its accumulated per-rule evaluation statistics.
//
// Chosen against what the numbers are FOR rather than for freshness of its own sake. They answer "which rule is costing me
// lately", read from the detection-tuning table by a person deciding whether to promote a rule out of monitor mode, and no such
// decision turns on the last half minute. Matching the corpus refresh interval keeps one cadence to reason about in a deployment.
//
// The cost side is what makes the exact value uninteresting: one write per replica per interval, against one per batch before.
const DefaultEvalStatsFlushInterval = 30 * time.Second

// BufferedEvalStats accumulates per-rule evaluation statistics in memory and writes them on a ticker instead of on the drain path.
//
// Issue #837. The counters were correct and their cadence was not: RecordRuleEvalStats ran synchronously once per event batch, and
// measured against the test MySQL it saturated near 1800 writes/sec with p95 climbing to 41ms at thirty-two writers. Every replica
// contends on the same instance, so that bounded batches/sec for a whole deployment however many replicas were added, and an
// observability feature must not bound the data plane. The write also cost more than the work it measured: a 73-rule batch on the
// dev server evaluated in about 1.2ms in total against a ~1.5ms write.
//
// Row-lock contention was NOT the mechanism, and that was tested rather than assumed. A host-derived shard column moved p50 not at
// all (3.58ms against 3.98ms at eight writers) and left throughput flat, so it was reverted. Do not re-add one without a
// measurement showing something different.
//
// Per-replica perf cache, safe to lose. ADR-0010's carve-out applies as written: nothing here is state a peer needs to serve the
// next request, each replica aggregates only the work it did itself, and the durable table remains the only thing a reader sees.
//
// Buffering is acceptable HERE and would not be for monitor matches, which the spec already separates rather than leaving to be
// re-argued. A monitor match is a fact about the world that drives a promotion decision, so losing one makes a rule look quiet and
// misleads the operator, which is why those are written only after the batch is acknowledged. An evaluation cost sample is one of
// thousands and losing a window changes no decision.
type BufferedEvalStats struct {
	inner  api.RuleEvalStatsRecorder
	logger *slog.Logger

	// flushing serialises Flush against itself, so a periodic tick and the shutdown flush cannot run at once. Review found the
	// race: shutdown cancelled the loop while a tick was already inside the write, and the shutdown flush then found an empty
	// pending set and reported nothing lost while the tick's window went with its cancelled context.
	//
	// Separate from mu, and held for the whole write rather than instead of it: mu protects the map for the microseconds a merge
	// or a drain takes, and taking it across the database call is what this whole change exists to avoid.
	flushing sync.Mutex

	mu sync.Mutex
	// pending is a per-replica perf cache, safe to lose: it holds only this replica's own unwritten counts, and the durable
	// table is the only thing a reader sees.
	//
	// Keyed by rule id, so its SIZE is bounded by the rule count no matter how many batches accumulate into it. That is what
	// makes returning a failed write's stats to it safe: a database that stays down grows the counters, never the map.
	pending map[string]*api.RuleEvalStat
}

// NewBufferedEvalStats wraps a durable recorder so writes happen on a flush rather than per batch.
//
// It satisfies the same api.RuleEvalStatsRecorder the engine already consumes, so nothing in the detection context changes: the
// engine keeps calling RecordRuleEvalStats once per batch and that call stops touching the database.
func NewBufferedEvalStats(inner api.RuleEvalStatsRecorder, logger *slog.Logger) *BufferedEvalStats {
	if logger == nil {
		logger = slog.Default()
	}
	return &BufferedEvalStats{inner: inner, logger: logger, pending: map[string]*api.RuleEvalStat{}}
}

// RecordRuleEvalStats merges a batch's statistics into the pending set. It performs no database work and returns no error the
// caller could act on, which is why it always reports success.
//
// The engine calls this from a defer on every exit path, including ones that have already decided to nack, so it must stay cheap
// and must not fail the batch. What it costs now is a mutex and one map update per rule.
func (b *BufferedEvalStats) RecordRuleEvalStats(_ context.Context, stats api.RuleEvalStats) error {
	if len(stats) == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mergeLocked(stats)
	return nil
}

// mergeLocked adds stats into pending. Sums add and the maximum takes the larger, matching the store's own upsert
// (`evaluations + VALUES(...)`, `GREATEST(eval_ns_max, ...)`), which is what keeps a flush's COUNTERS identical to what the
// per-batch writes would have accumulated.
//
// The counters only, and the exception is worth stating because the store derives the rest from its own clock at write time. The
// day bucket, first_seen and last_seen now come from the flush rather than from the evaluation, so up to one flush interval of
// work is attributed that much later, and work in the last seconds of a day can land in the next one. Bounded by the interval
// against a window read in days, so it changes no decision the numbers are for, but it is a real difference and not covered by
// the word "identical".
func (b *BufferedEvalStats) mergeLocked(stats api.RuleEvalStats) {
	for _, s := range stats {
		existing, ok := b.pending[s.RuleID]
		if !ok {
			// Copied rather than aliased: the caller owns the slice it passed and may reuse its backing array.
			row := s
			b.pending[s.RuleID] = &row
			continue
		}
		existing.Evaluations += s.Evaluations
		existing.RetryableMisses += s.RetryableMisses
		existing.EvalNs += s.EvalNs
		if s.MaxEvalNs > existing.MaxEvalNs {
			existing.MaxEvalNs = s.MaxEvalNs
		}
	}
}

// Flush writes everything accumulated so far, and is safe to call with nothing pending.
//
// A failed write DISCARDS that window rather than retrying it, and the reasoning is worth stating because an earlier version of
// this did retry. The write is an additive upsert, so a retry is at-least-once: a commit whose result never reaches the client is
// added again, repeated failures are not bounded to one window, and because further work merges in between attempts the derived
// mean moves rather than staying put. Neither choice gives the exact totals #837 asks for once the database is failing, so the
// tie goes to the one whose behaviour can be stated in a sentence. #837's own rationale for buffering is that losing a window
// changes no decision.
//
// Issue #868 tracks making the write idempotent, which is the only thing that would make it exact under failure, and it is a
// schema question rather than a retry question.
func (b *BufferedEvalStats) Flush(ctx context.Context) (err error) {
	b.flushing.Lock()
	defer b.flushing.Unlock()

	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return nil
	}
	drained := make(api.RuleEvalStats, 0, len(b.pending))
	for _, s := range b.pending {
		drained = append(drained, *s)
	}
	b.pending = map[string]*api.RuleEvalStat{}
	b.mu.Unlock()

	// Written outside the lock, so a slow write does not block the drain path that is still recording into pending. The drained
	// counts are gone either way: see above for why a retry is not the improvement it looks like.
	if err := b.inner.RecordRuleEvalStats(ctx, drained); err != nil {
		// Wrapped with what was lost, because the caller can no longer count it: pending has already been replaced, so a caller
		// asking the buffer afterwards is told zero. Review caught the shutdown warning reporting exactly that.
		return fmt.Errorf("flush %d rule aggregates: %w", len(drained), err)
	}
	return nil
}

// FlushLoop writes on the interval and once more when ctx is cancelled, so a graceful shutdown writes the window it had rather
// than discarding it.
//
// Not "loses nothing": that final write can itself fail, within its own short budget, and then the window IS lost. That is one of
// the loss conditions the requirement enumerates, and flushOnShutdown below reports it with the count.
//
// The final flush deliberately does NOT use ctx, which is already cancelled by then and would fail the write immediately. It gets
// a short budget of its own instead, long enough for one statement and short enough not to hold up a shutdown.
func (b *BufferedEvalStats) FlushLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		// Defaulted here rather than at the wiring, so there is one place that decides it and a caller holding a zero value
		// cannot panic a background goroutine. A hand-built Rules in a test does exactly that, and NewTicker panics on a
		// non-positive interval rather than failing the call.
		interval = DefaultEvalStatsFlushInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			b.flushOnShutdown()
			return
		case <-ticker.C:
			if err := b.Flush(ctx); err != nil {
				// Logged rather than returned: this loop is the only caller, and giving up would turn a transient database
				// problem into a permanent stop. That window is gone, and the error says how many rules' statistics went with
				// it; the next tick starts from whatever has accumulated since.
				b.logger.ErrorContext(ctx, "flush rule eval stats", "err", err)
			}
		}
	}
}

// shutdownFlushTimeout bounds the last write. One statement against a reachable database is milliseconds; this is the point at
// which a shutdown stops waiting for an unreachable one.
const shutdownFlushTimeout = 5 * time.Second

// Deliberately does not inherit the loop's context, which is why contextcheck is silenced here rather than satisfied: this runs
// BECAUSE that context was cancelled, so passing it through would fail the write instantly and lose the very window this exists
// to save.
//
//nolint:contextcheck // the parent context is cancelled; a detached one with its own timeout is the requirement.
func (b *BufferedEvalStats) flushOnShutdown() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), shutdownFlushTimeout)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		// The error carries how many rule aggregates were lost; PendingRules would report zero here, because Flush has already
		// replaced the map.
		b.logger.WarnContext(ctx, "rule eval stats lost on shutdown", "err", err)
	}
}

// PendingRules is how many rules currently hold unflushed statistics. Exposed for the shutdown log and for tests, which need to
// distinguish "accumulated" from "written" without reaching into the lock.
func (b *BufferedEvalStats) PendingRules() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

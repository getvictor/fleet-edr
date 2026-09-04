package detectionconfig

import (
	"context"
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

	mu sync.Mutex
	// pending is keyed by rule id, so its SIZE is bounded by the rule count no matter how many batches accumulate into it. That
	// is what makes returning a failed write's stats to it safe: a database that stays down grows the counters, never the map.
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
// On a write failure the drained statistics go BACK into pending and the next flush retries them, so a transient database problem
// costs no counts. That is why the documented loss window is an ungraceful shutdown alone: nothing else discards a count. The map
// is keyed by rule id, so a database that stays down cannot grow it past the rule count.
func (b *BufferedEvalStats) Flush(ctx context.Context) error {
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

	// Written outside the lock, so a slow write does not block the drain path that is still recording into pending.
	if err := b.inner.RecordRuleEvalStats(ctx, drained); err != nil {
		b.mu.Lock()
		b.mergeLocked(drained)
		b.mu.Unlock()
		return err
	}
	return nil
}

// FlushLoop writes on the interval and once more when ctx is cancelled, so a graceful shutdown writes the window it had rather
// than discarding it.
//
// Not "loses nothing": that final write can itself fail, within its own short budget, and then the window IS lost. That is the
// one documented loss window and flushOnShutdown below reports it.
//
// The final flush deliberately does NOT use ctx, which is already cancelled by then and would fail the write immediately. It gets
// a short budget of its own instead, long enough for one statement and short enough not to hold up a shutdown.
func (b *BufferedEvalStats) FlushLoop(ctx context.Context, interval time.Duration) {
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
				// problem into a permanent stop. The counts are still pending and the next tick retries them.
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
		// The one documented loss window. Reported at WARN with the count, so an operator reading a gap in the table can tell
		// whether this is why.
		b.logger.WarnContext(ctx, "rule eval stats lost on shutdown", "err", err, "rules", b.PendingRules())
	}
}

// PendingRules is how many rules currently hold unflushed statistics. Exposed for the shutdown log and for tests, which need to
// distinguish "accumulated" from "written" without reaching into the lock.
func (b *BufferedEvalStats) PendingRules() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

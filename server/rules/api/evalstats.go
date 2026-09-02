package api

import (
	"context"
	"time"
)

// RuleEvalStat is one rule's evaluation work within a batch: how many attempts, how long they took, and how many could not decide.
//
// Separate from MonitorTally because it answers a different question and, crucially, obeys the OPPOSITE recording rule. A monitor
// match is a fact about the world (this rule matched this host on this day) so a replayed batch must not count it twice, which is
// why the tally is handed back to be written only after the acknowledgement. An evaluation is a fact about work the server
// performed, and a replayed batch genuinely did evaluate again, so every attempt counts.
//
// That is not the retry-inflation mistake MonitorTally's doc warns about, and the difference is worth being able to state: the
// figures a reader derives are unaffected by replay, because Evaluations and EvalNs inflate by the same factor and the mean they
// produce together does not move. Recording only on acknowledgement would additionally make RetryableMisses unreachable, since a
// batch that ends in a retryable miss is never acknowledged. That counter is the whole point of the type: it names the rule whose
// misses are driving the churn, which the fleet-wide edr.detection.materialization_retries counter cannot.
type RuleEvalStat struct {
	RuleID string
	// Evaluations is attempts, so it is at least 1 for any rule that ran.
	Evaluations int64
	// RetryableMisses is how many of those attempts ended in a retryable error rather than a decision. Not a subset that reduces
	// Evaluations: an attempt that missed still cost its time and still counts as an attempt.
	RetryableMisses int64
	// EvalNs is the total wall time across those attempts, and MaxEvalNs the worst single one. Wall time rather than CPU time
	// because a rule that is slow through graph reads is exactly as much of an operator problem as one slow through matching,
	// and the reader is trying to find the rule holding up the drain loop.
	EvalNs    int64
	MaxEvalNs int64
}

// RuleEvalStats is one batch's per-rule evaluation work, one entry per rule that actually ran.
//
// A rule the batch never handed an event to is ABSENT rather than present with zero. The engine skips a rule whose declared event
// types are not in the batch and does not open a span for it, because reporting work that did not happen is worse than reporting
// nothing, and the same reasoning applies to the counters.
type RuleEvalStats []RuleEvalStat

// RuleEvalStatsRecorder is the narrow write surface the engine uses to persist a batch's evaluation statistics.
//
// A nil recorder records nothing, which is the correct behaviour for a test or a deployment with no rules-context store wired:
// evaluation is unaffected, and the fixture corpus and replay harness never wire one.
type RuleEvalStatsRecorder interface {
	// RecordRuleEvalStats persists stats, adding to whatever is already recorded for each (rule, day).
	//
	// Called on the evaluation path rather than after an acknowledgement, and called on the failure path too, so it MUST NOT be
	// able to fail the batch: the caller logs an error and moves on. The batch's real work is the detection, and replaying it to
	// save a counter would cost more than the counter is worth.
	RecordRuleEvalStats(ctx context.Context, stats RuleEvalStats) error
}

// RuleEvalSummary is what a rule's evaluation work looks like over a window, aggregated across days.
//
// Carries `db` tags alongside `json` for the same reason RuleMatchCount does: the aggregate is read straight into this shape by the
// rules store and served in it.
type RuleEvalSummary struct {
	RuleID string `db:"rule_id" json:"rule_id"`
	// Evaluations and RetryableMisses are totals over the window. Their ratio is the churn rate, which is the figure that
	// identifies a rule whose misses are driving retries.
	Evaluations     int64 `db:"evaluations" json:"evaluations"`
	RetryableMisses int64 `db:"retryable_misses" json:"retryable_misses"`
	// MeanEvalNs and MaxEvalNs are the mean and worst-case wall time. The mean is computed in SQL from the stored sum and count
	// rather than stored, so it stays correct as days are added to the window and as the retention sweep removes them.
	MeanEvalNs int64 `db:"mean_eval_ns" json:"mean_eval_ns"`
	MaxEvalNs  int64 `db:"max_eval_ns" json:"max_eval_ns"`
	// LastSeen is the most recent evaluation in the window. Always set, for the same reason RuleMatchCount.LastSeen is: a rule
	// that never evaluated is absent from the result rather than present with a zero row.
	LastSeen time.Time `db:"last_seen" json:"last_seen"`
}

// EvalStatsWindow is how far back an evaluation-statistics read looks, in days. Distinct from MatchCountWindow so the two reads can
// diverge: they are pruned by the same retention knob today, but they answer different questions and nothing requires that the
// window an operator wants for "is this rule expensive" match the one for "is this rule noisy".
type EvalStatsWindow int

const (
	// DefaultEvalStatsWindow matches DefaultMatchCountWindow so the two figures a reader sees side by side describe the same
	// period unless one is asked for explicitly. A mean latency over a week next to a fire count over a day would invite
	// exactly the wrong comparison.
	DefaultEvalStatsWindow EvalStatsWindow = 7
	// MaxEvalStatsWindow caps the request so a reader cannot ask for a window the retention sweep has already emptied and read
	// the resulting silence as a cheap rule.
	MaxEvalStatsWindow EvalStatsWindow = 30
)

// EffectiveEvalStatsCap is the furthest back a read can honestly reach in a deployment retaining retentionDays days of statistics.
//
// Same reasoning as EffectiveMatchCountCap: the rows are pruned with the deployment's own EDR_RETENTION_DAYS, which is 7 in the
// quickstart compose, so a fixed 30-day cap would report a 30-day window over whatever survived a 7-day prune and tell the caller
// a period the data does not cover.
func EffectiveEvalStatsCap(retentionDays int) EvalStatsWindow {
	if retentionDays <= 0 || EvalStatsWindow(retentionDays) > MaxEvalStatsWindow {
		return MaxEvalStatsWindow
	}
	return EvalStatsWindow(retentionDays)
}

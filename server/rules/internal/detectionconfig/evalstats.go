package detectionconfig

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/sqlhelpers"
)

// RecordRuleEvalStats adds a batch's per-rule evaluation work to the per-(rule, day) counters.
//
// One statement for the whole batch rather than one per rule: a batch evaluates every rule whose declared event types it carries,
// which at a thousand rules is a great many, and this runs on the drain path after every batch.
//
// Unlike RecordMonitorMatches, this is called whether or not the batch was acknowledged, and a replayed batch adds again. That is
// not the retry inflation the sibling avoids, it is a different quantity: a monitor match is a fact about the world, so a replay
// must not make it two, whereas an evaluation is work the server actually performed and a replay really did perform it again. The
// figures a reader derives survive it, because evaluations and eval_ns_sum inflate by the same factor and their ratio does not
// move. Recording only after an acknowledgement would also put retryable_misses out of reach, since a batch that ends in a
// retryable miss is never acknowledged, and that counter is what names the rule driving the churn.
//
// The day comes from the SERVER's clock (UTC), for the same reason the sibling takes it from there: the counters answer "what is
// this rule costing lately", a question about now, and attributing work to an event's own timestamp would let a skewed host clock
// or a long queue backlog write into a day the operator has already read past.
//
// eval_ns_max is a MAX rather than last-write-wins, and the timestamps are extrema, because these calls are not serialised: the
// per-host claim lock is released before detection runs, so two batches can be in this write concurrently across workers and
// across replicas. Under last-write-wins a slower attempt arriving first would be overwritten by a faster one and the worst case,
// which is the number a reader is looking for, would be whichever landed last.
func (s *Store) RecordRuleEvalStats(ctx context.Context, stats api.RuleEvalStats) error {
	folded := foldEvalStats(stats)
	if len(folded) == 0 {
		return nil
	}

	// Sorted for the same lock-ordering reason as the sibling: map iteration order is randomised per range in Go, so building the
	// VALUES list straight from the map lets two overlapping upserts take the same row locks in opposite orders and deadlock.
	// Unlike the sibling this call CAN be retried by its caller in principle, but it is not, because the caller has no path that
	// re-runs detection to save a counter.
	//
	// NOTE ON COVERAGE: removing this sort is a MISSED mutation and always will be, exactly as in the sibling. Lock ordering is
	// observable only under concurrent statements contending for the same rows, which a test in this package cannot stage
	// against a shared MySQL without becoming a load test.
	ruleIDs := make([]string, 0, len(folded))
	for id := range folded {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	now := time.Now().UTC()
	day := now.Format(time.DateOnly)
	placeholders := make([]string, 0, len(ruleIDs))
	args := make([]any, 0, len(ruleIDs)*8)
	for _, id := range ruleIDs {
		st := folded[id]
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?)")
		args = append(args, id, day, st.Evaluations, st.RetryableMisses, st.EvalNs, st.MaxEvalNs, now, now)
	}
	query := `
		INSERT INTO detection_rule_eval_stats
			(rule_id, day, evaluations, retryable_misses, eval_ns_sum, eval_ns_max, first_seen, last_seen)
		VALUES ` + strings.Join(placeholders, ", ") + `
		ON DUPLICATE KEY UPDATE
			evaluations      = evaluations + VALUES(evaluations),
			retryable_misses = retryable_misses + VALUES(retryable_misses),
			eval_ns_sum      = eval_ns_sum + VALUES(eval_ns_sum),
			eval_ns_max      = GREATEST(eval_ns_max, VALUES(eval_ns_max)),
			first_seen       = LEAST(first_seen, VALUES(first_seen)),
			last_seen        = GREATEST(last_seen, VALUES(last_seen))`

	err := sqlhelpers.WithDeadlockRetry(ctx, matchCountDeadlockAttempts, matchCountDeadlockStep, func() error {
		_, execErr := s.db.ExecContext(ctx, query, args...)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("record rule eval stats: %w", err)
	}
	return nil
}

// foldEvalStats collapses a batch's entries to one per rule, dropping entries that name no rule or report no attempt.
//
// Folding first means the statement carries one row per key, since MySQL applies ON DUPLICATE KEY UPDATE per row and two rows with
// the same key would take the same lock twice to reach the same total. It also means MaxEvalNs is folded with a max rather than
// summed, which summing the struct field for field would get wrong.
func foldEvalStats(stats api.RuleEvalStats) map[string]api.RuleEvalStat {
	folded := make(map[string]api.RuleEvalStat, len(stats))
	for _, st := range stats {
		if st.RuleID == "" || st.Evaluations <= 0 {
			continue
		}
		cur := folded[st.RuleID]
		cur.Evaluations += st.Evaluations
		cur.RetryableMisses += st.RetryableMisses
		cur.EvalNs += st.EvalNs
		cur.MaxEvalNs = max(cur.MaxEvalNs, st.MaxEvalNs)
		folded[st.RuleID] = cur
	}
	return folded
}

// EvalStats reports what each rule's evaluations have cost over the last `days` days, one row per rule that evaluated at all.
//
// `days` is the ALREADY-RESOLVED window, not a raw request: the operator handler bounds it with api.EffectiveEvalStatsCap before
// calling, because only that layer knows the deployment's retention.
//
// The mean is computed here from the stored sum and count rather than stored, so it stays correct as the window widens and as the
// retention sweep removes days. Averaging stored per-day means would weight a quiet day equally with a busy one.
//
// Integer division truncates, which is right for a figure rendered as a duration: a mean of 1.9us reads as 1us rather than
// rounding up to 2us and overstating the cost. NULLIF guards the divide even though a stored row cannot have zero evaluations
// (foldEvalStats drops those), because SUM over an empty group is NULL rather than 0 and a future caller filtering rows harder
// should not get a division error instead of no rows.
func (s *Store) EvalStats(ctx context.Context, days api.EvalStatsWindow) ([]api.RuleEvalSummary, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -int(days)+1).Format(time.DateOnly)

	var rows []api.RuleEvalSummary
	err := s.db.SelectContext(ctx, &rows, `
		SELECT rule_id,
		       SUM(evaluations)                                  AS evaluations,
		       SUM(retryable_misses)                             AS retryable_misses,
		       SUM(eval_ns_sum) DIV NULLIF(SUM(evaluations), 0)   AS mean_eval_ns,
		       MAX(eval_ns_max)                                  AS max_eval_ns,
		       MAX(last_seen)                                    AS last_seen
		FROM detection_rule_eval_stats
		WHERE day >= ?
		GROUP BY rule_id
		ORDER BY mean_eval_ns DESC, rule_id`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("read rule eval stats: %w", err)
	}
	return rows, nil
}

// PruneRuleEvalStats deletes statistic rows for days older than retentionDays, and reports how many it removed.
//
// Same shape and same reasoning as PruneMatchCounts: run from every replica on a plain ticker rather than behind a leader lock,
// because each RunIfLeader loop holds a pooled connection for the life of the process and paying that to serialise an idempotent
// DELETE would be the wrong trade. Batched so one pass after a retention reduction cannot hold a large row-lock and undo-log
// footprint while every replica contends on the same range.
//
// retentionDays <= 0 prunes nothing, matching the sibling and the process-record retention runner.
func (s *Store) PruneRuleEvalStats(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.DateOnly)
	var total int64
	for {
		var deleted int64
		err := sqlhelpers.WithDeadlockRetry(ctx, matchCountDeadlockAttempts, matchCountDeadlockStep, func() error {
			res, execErr := s.db.ExecContext(ctx,
				`DELETE FROM detection_rule_eval_stats WHERE day < ? ORDER BY day LIMIT ?`, cutoff, matchCountPruneBatch)
			if execErr != nil {
				return execErr
			}
			deleted, execErr = res.RowsAffected()
			return execErr
		})
		if err != nil {
			return total, fmt.Errorf("prune rule eval stats: %w", err)
		}
		total += deleted
		if deleted < matchCountPruneBatch {
			return total, nil
		}
	}
}

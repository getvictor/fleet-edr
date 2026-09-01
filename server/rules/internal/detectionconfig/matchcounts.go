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

const (
	// matchCountDeadlockAttempts and matchCountDeadlockStep bound the retry on a deadlocked upsert. Short and few: the statement is
	// idempotent in the sense that retrying it applies the same additions, and the caller has already acknowledged the batch, so a
	// long retry would hold the drain loop for a counter.
	matchCountDeadlockAttempts = 3
	matchCountDeadlockStep     = 20 * time.Millisecond
	// matchCountPruneBatch bounds one DELETE's row-lock and undo-log footprint, the same reason the retention runner batches its
	// prune. Every replica runs this sweep, so an unbounded delete after a retention reduction would have them all contending on
	// one large range at once.
	matchCountPruneBatch = 1000
)

// RecordMonitorMatches adds a batch's monitor matches to the per-(rule, host, day) counters.
//
// One statement for the whole tally rather than one per entry: a batch can carry matches for several rules, and the pipeline calls
// this on the drain path after every batch that had any.
//
// The day comes from the SERVER's clock (UTC), not from the event timestamps. The counters answer "how often is this firing
// lately", which is a question about now; attributing a match to an event's own timestamp would let a host with a skewed clock, or
// a batch replayed after a long queue backlog, write into a day the operator has already read past.
//
// The timestamps are extrema, not last-write-wins, so the row records the window it covers rather than whichever call landed last.
// That matters because these calls are NOT serialised per host: the per-host claim lock is released before detection runs, so two
// batches for one (rule, host) can be in this write concurrently, across workers and across replicas. Under last-write-wins an
// older call arriving second would drag `last_seen` backwards, and a newer call that inserted the row first would leave
// `first_seen` too late, in both cases describing a narrower window than was actually observed.
//
// Severity is deliberately NOT part of the key: it belongs to the OTel series, where it exists to line up with
// `edr.alerts.created`, whereas this table answers how often and how widely, and splitting rows by a severity that an override can
// change mid-window would fragment both answers.
func (s *Store) RecordMonitorMatches(ctx context.Context, tally api.MonitorTally) error {
	folded := foldTally(tally)
	if len(folded) == 0 {
		return nil
	}

	// Sorted, so every concurrent statement locks these rows in the SAME order. Map iteration order is randomised per range in Go,
	// so building the VALUES list straight from the map let two overlapping upserts take the same row locks in opposite orders and
	// deadlock each other. That is worth more care here than in most places: this runs AFTER the batch is acknowledged, so an error
	// is not retried by the pipeline and the counts are gone for good.
	//
	// NOTE ON COVERAGE: removing this sort is a MISSED mutation and always will be. Lock ordering is only observable under
	// concurrent statements contending for the same rows, which a test in this package cannot stage against a shared MySQL without
	// being a load test. The retry below is what makes the residual survivable; the ordering is what makes it rare.
	keys := make([]matchKey, 0, len(folded))
	for k := range folded {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ruleID != keys[j].ruleID {
			return keys[i].ruleID < keys[j].ruleID
		}
		return keys[i].hostID < keys[j].hostID
	})

	now := time.Now().UTC()
	day := now.Format(time.DateOnly)
	placeholders := make([]string, 0, len(keys))
	args := make([]any, 0, len(keys)*6)
	for _, k := range keys {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?)")
		args = append(args, k.ruleID, k.hostID, day, folded[k], now, now)
	}
	query := `
		INSERT INTO detection_rule_match_counts (rule_id, host_id, day, match_count, first_seen, last_seen)
		VALUES ` + strings.Join(placeholders, ", ") + `
		ON DUPLICATE KEY UPDATE
			match_count = match_count + VALUES(match_count),
			first_seen  = LEAST(first_seen, VALUES(first_seen)),
			last_seen   = GREATEST(last_seen, VALUES(last_seen))`

	// Sorting makes a deadlock unlikely rather than impossible: InnoDB can still deadlock two statements against gap or index
	// locks. Retried because the addition is the same on every attempt.
	err := sqlhelpers.WithDeadlockRetry(ctx, matchCountDeadlockAttempts, matchCountDeadlockStep, func() error {
		_, execErr := s.db.ExecContext(ctx, query, args...)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("record monitor matches: %w", err)
	}
	return nil
}

// matchKey is the table's identity within a day: severity is not part of it, so entries differing only by severity fold together.
type matchKey struct{ ruleID, hostID string }

// foldTally collapses a tally to one count per (rule, host), dropping entries that name neither or count nothing.
//
// Folding first means the statement carries one row per key. MySQL applies ON DUPLICATE KEY UPDATE per row, so two rows with the
// same key in one statement would both apply and reach the same total, but only after taking the same lock twice.
func foldTally(tally api.MonitorTally) map[matchKey]int {
	folded := make(map[matchKey]int, len(tally))
	for _, m := range tally {
		if m.RuleID == "" || m.HostID == "" || m.Count <= 0 {
			continue
		}
		folded[matchKey{m.RuleID, m.HostID}] += m.Count
	}
	return folded
}

// PruneMatchCounts deletes counter rows for days older than retentionDays, and reports how many it removed.
//
// Called on a plain ticker from every replica rather than from a leader-gated sweep. Each RunIfLeader loop holds its advisory lock,
// and therefore a pooled connection, for the life of the process, and the processor sizes itself against what those leave behind
// (issue #722). Paying a permanently held connection to serialise a DELETE that is idempotent would be the wrong trade: replicas
// racing on it simply delete rows the others already deleted.
//
// Batched for the same reason the retention runner batches: one pass after a retention reduction, or on a large fleet, can match a
// great many rows, and an unbounded DELETE would hold a correspondingly large row-lock and undo-log footprint while every replica
// contends on the same range.
//
// retentionDays <= 0 prunes nothing, matching how the same knob disables the process-record retention runner.
func (s *Store) PruneMatchCounts(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.DateOnly)
	var total int64
	for {
		var deleted int64
		err := sqlhelpers.WithDeadlockRetry(ctx, matchCountDeadlockAttempts, matchCountDeadlockStep, func() error {
			// ORDER BY day so concurrent replicas walk the range the same way rather than meeting in the middle of it.
			res, execErr := s.db.ExecContext(ctx,
				`DELETE FROM detection_rule_match_counts WHERE day < ? ORDER BY day LIMIT ?`, cutoff, matchCountPruneBatch)
			if execErr != nil {
				return execErr
			}
			deleted, execErr = res.RowsAffected()
			return execErr
		})
		if err != nil {
			return total, fmt.Errorf("prune monitor match counts: %w", err)
		}
		total += deleted
		if deleted < matchCountPruneBatch {
			return total, nil
		}
	}
}

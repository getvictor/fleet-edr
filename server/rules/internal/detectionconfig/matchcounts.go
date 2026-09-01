package detectionconfig

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// RecordMonitorMatches adds a batch's monitor matches to the per-(rule, host, day) counters.
//
// One statement for the whole tally rather than one per entry: a batch can carry matches for several rules, and the pipeline calls
// this on the drain path after every batch that had any.
//
// The day comes from the SERVER's clock (UTC), not from the event timestamps. The counters answer "how often is this firing lately",
// which is a question about now; attributing a match to an event's own timestamp would let a host with a skewed clock, or a batch
// replayed after a long queue backlog, write into a day the operator has already read past.
//
// The timestamps are extrema, not last-write-wins, so the row records the window it covers rather than whichever call landed last.
// That matters because these calls are NOT serialised per host: the per-host claim lock is released before detection runs, so two
// batches for one (rule, host) can be in this write concurrently, across workers and across replicas. Under last-write-wins an
// older call arriving second would drag `last_seen` backwards, and a newer call that inserted the row first would leave
// `first_seen` too late, in both cases describing a narrower window than was actually observed. Severity is deliberately NOT part of the key: it belongs to the OTel series, where it exists to line up with
// `edr.alerts.created`, whereas this table answers how often and how widely, and splitting rows by a severity that an override can
// change mid-window would fragment both answers.
func (s *Store) RecordMonitorMatches(ctx context.Context, tally api.MonitorTally) error {
	if len(tally) == 0 {
		return nil
	}
	// Several entries can share a (rule, host) and differ only by severity, which this table does not key on, so fold them first:
	// MySQL applies ON DUPLICATE KEY UPDATE per row, and two rows with the same key in one statement would both be applied, which
	// is correct here but does more work than folding once.
	type key struct{ ruleID, hostID string }
	folded := make(map[key]int, len(tally))
	for _, m := range tally {
		if m.RuleID == "" || m.HostID == "" || m.Count <= 0 {
			continue
		}
		folded[key{m.RuleID, m.HostID}] += m.Count
	}
	if len(folded) == 0 {
		return nil
	}

	now := time.Now().UTC()
	placeholders := make([]string, 0, len(folded))
	args := make([]any, 0, len(folded)*5)
	for k, count := range folded {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?)")
		args = append(args, k.ruleID, k.hostID, now.Format(time.DateOnly), count, now, now)
	}
	query := `
		INSERT INTO detection_rule_match_counts (rule_id, host_id, day, match_count, first_seen, last_seen)
		VALUES ` + strings.Join(placeholders, ", ") + `
		ON DUPLICATE KEY UPDATE
			match_count = match_count + VALUES(match_count),
			first_seen  = LEAST(first_seen, VALUES(first_seen)),
			last_seen   = GREATEST(last_seen, VALUES(last_seen))`
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("record monitor matches: %w", err)
	}
	return nil
}

// PruneMatchCounts deletes counter rows for days older than retentionDays, and reports how many it removed.
//
// Called on a plain ticker from every replica rather than from a leader-gated sweep. Each RunIfLeader loop holds its advisory lock,
// and therefore a pooled connection, for the life of the process, and the processor sizes itself against what those leave behind
// (issue #722). Paying a permanently held connection to serialise a DELETE that is idempotent would be the wrong trade: replicas
// racing on it simply delete rows the others already deleted.
//
// retentionDays <= 0 prunes nothing, matching how the same knob disables the process-record retention runner.
func (s *Store) PruneMatchCounts(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.DateOnly)
	res, err := s.db.ExecContext(ctx, `DELETE FROM detection_rule_match_counts WHERE day < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune monitor match counts: %w", err)
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune monitor match counts: rows affected: %w", err)
	}
	return deleted, nil
}

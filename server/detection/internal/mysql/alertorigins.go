package mysql

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jmoiron/sqlx"
)

// BackfillAlertOrigins credits alerts that were raised before attribution was recorded, for the vendored rules named in origins.
//
// Issue #827, the follow-up #824 deliberately left open. `alerts.origin` (migration 00012) has been populated going forward since
// attribution shipped, and was never backfilled, so an operator who promoted a vendored rule and then upgraded keeps alerts
// displaying no credit at all. That is the Detection Rule License obligation unmet for exactly those rows.
//
// #824 measured the affected population at ZERO across both dev lanes and did not build this, which was the right trade then: the
// set is empty in practice because vendored rules ship in monitor mode (#764), monitor resolution returns before persistence, and
// promotion only became possible in #814. It is not empty by CONSTRUCTION though, and #814 is now shipping, so the population
// stops being hypothetical with the release that first puts promotion in an operator's hands.
//
// The caller decides which rules are in scope, and two exclusions matter enough to state here because getting either wrong is
// worse than not running at all:
//
//   - OUR OWN rules must not be backfilled. Filling them with the project's own name would erase the distinction migration 00012
//     deliberately preserves, between an alert raised before attribution existed and one raised by us.
//   - PROJECTIONS must not be backfilled. An application-control block stores an empty origin on purpose, because its rule_id is
//     the operator's own policy entry; crediting this project for an operator's blocklist would be the bug review caught in #824.
//
// Both fall out of asking rulesapi.AlertOriginOf for each rule and skipping the empty and project answers, which is why this takes
// a prepared map rather than reaching for the catalog itself.
//
// Only rows with an EMPTY origin are touched, so this cannot overwrite an attribution already recorded, and re-running it is a
// no-op rather than a rewrite. That is what makes it safe to run on every boot of a replica that wins the leader lock.
//
// Known limit, tracked as #871 and worth stating because it is silent: the caller builds origins from the rules the deployment
// RUNS, so alerts from a vendored rule that has since been removed from the corpus stay uncredited. Crediting them would mean
// keeping a record of every rule that ever shipped, which is a larger thing than this pass, and the alternative of guessing an
// author is worse than leaving the field empty.
func (s *Store) BackfillAlertOrigins(ctx context.Context, origins map[string]string) (int64, error) {
	if len(origins) == 0 {
		return 0, nil
	}

	// Sorted so the statement is deterministic, which keeps it readable in a slow-query log and keeps two replicas that both
	// somehow reach it taking row locks in the same order.
	ruleIDs := make([]string, 0, len(origins))
	for id := range origins {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	// One CASE covering every rule rather than a statement per rule: the whole set is a dozen rules today, so batching them keeps
	// the round trips proportional to the ALERTS to credit rather than to the corpus, on a path that runs while the server is
	// still coming up. Both statements below share it.
	var cases strings.Builder
	caseArgs := make([]any, 0, len(ruleIDs)*2)
	cases.WriteString("UPDATE alerts SET origin = CASE rule_id")
	for _, id := range ruleIDs {
		cases.WriteString(" WHEN ? THEN ?")
		caseArgs = append(caseArgs, id, origins[id])
	}
	cases.WriteString(" END WHERE id IN (?)")
	updateSQL := cases.String()

	ruleArgs := make([]any, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		ruleArgs = append(ruleArgs, id)
	}
	selectSQL := "SELECT id FROM alerts WHERE origin = '' AND rule_id IN (?" +
		strings.Repeat(", ?", len(ruleIDs)-1) + ") AND id > ? ORDER BY id LIMIT ?"

	// Walked by PRIMARY KEY, in batches, and the cursor is the whole point. A LIMIT alone was the first attempt and it made the
	// total work WORSE, which both reviewers caught: with no usable index every statement restarts from the beginning, so N
	// batches cost N scans rather than one. Resuming from the last id turns that back into a single forward pass whose locks are
	// still bounded per statement.
	//
	// alerts carries no index this predicate can use. There is none on origin, and rule_id sits THIRD in the dedup key behind
	// source and host_id, so `origin = '' AND rule_id IN (...)` cannot be satisfied by a lookup however it is written. Walking the
	// primary key is what makes the scan happen once.
	//
	// So this reads the table once per boot, including the boot after everything is already credited, and once per replica through
	// a rolling restart: DoOnceIfLeader excludes overlapping callers, not repeated ones, so each replica takes the lock in turn.
	// Tracked as #872, whose fix is durable completion state rather than an index.
	//
	// NOT adding an index is deliberate. One on origin would not help: our own rules keep an empty origin permanently and on
	// purpose, so `origin = ''` stays a high-cardinality match forever rather than emptying out after the first pass. One on
	// rule_id would help, and would tax every alert INSERT, on the hot detection path, for the life of the deployment, to save a
	// scan on a leader-only path that runs off the request path while the server is still coming up. The scan is the cheaper side
	// of that trade.
	var total int64
	var cursor int64
	for {
		var ids []int64
		selectArgs := append(append([]any{}, ruleArgs...), cursor, backfillBatchSize)
		if err := s.db.SelectContext(ctx, &ids, selectSQL, selectArgs...); err != nil {
			return total, fmt.Errorf("backfill alert origins select: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}

		// Updated by primary key, so this statement touches exactly the rows just identified and holds nothing else.
		query, updateArgs, err := sqlx.In(updateSQL, append(append([]any{}, caseArgs...), ids)...)
		if err != nil {
			return total, fmt.Errorf("backfill alert origins expand: %w", err)
		}
		res, err := s.db.ExecContext(ctx, s.db.Rebind(query), updateArgs...)
		if err != nil {
			return total, fmt.Errorf("backfill alert origins: %w", err)
		}
		updated, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("backfill alert origins rows affected: %w", err)
		}
		total += updated
		cursor = ids[len(ids)-1]

		// Checked between batches so a cancelled start-up stops here rather than walking the rest of the table. Not a yield: the
		// batches are what bound this, and a sleep would only make a boot-time pass take longer.
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}

// backfillBatchSize bounds how many rows one statement rewrites.
//
// Large enough that a typical deployment finishes in one pass, small enough that no single statement holds a scan's worth of
// row locks.
//
// NOTE ON COVERAGE, measured rather than assumed. Three mutants, and only one is caught:
//
//   - Dropping the `origin = ”` guard FAILS the tests, which is the correctness property and the one worth pinning.
//   - Raising this bound SURVIVES. A larger batch does the same work with the same result.
//   - Pinning the cursor at 0, or dropping `id > ?`, also SURVIVES, and that is not a gap in the tests. Each batch's UPDATE
//     removes those rows from the `origin = ”` predicate, so the loop makes progress and terminates correctly either way.
//     The cursor buys ONE forward scan instead of N restarts of a scan, and total scan work is not a thing a test in this
//     package can observe. The LOOP itself IS covered, by seeding more rows than one batch holds.
const backfillBatchSize = 1000

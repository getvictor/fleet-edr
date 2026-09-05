package mysql

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
// Known limit, worth stating because it is silent: the caller builds origins from the rules the deployment RUNS, so alerts from a
// vendored rule that has since been removed from the corpus stay uncredited. Crediting them would mean keeping a record of every
// rule that ever shipped, which is a larger thing than this pass, and the alternative of guessing an author is worse than leaving
// the field empty.
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

	// One statement rather than one per rule: the whole set is a dozen rules today, and a single UPDATE keeps this to one round
	// trip on a path that runs while the server is still coming up.
	var cases strings.Builder
	args := make([]any, 0, len(ruleIDs)*2)
	cases.WriteString("UPDATE alerts SET origin = CASE rule_id")
	for _, id := range ruleIDs {
		cases.WriteString(" WHEN ? THEN ?")
		args = append(args, id, origins[id])
	}
	cases.WriteString(" END WHERE origin = '' AND rule_id IN (?" + strings.Repeat(", ?", len(ruleIDs)-1) + ")")
	for _, id := range ruleIDs {
		args = append(args, id)
	}
	fmt.Fprintf(&cases, " LIMIT %d", backfillBatchSize)

	// Batched, because this cannot use an index. alerts carries no index on origin, and rule_id sits THIRD in the dedup key
	// behind source and host_id, so `origin = '' AND rule_id IN (...)` is a table scan however it is written. One unbounded
	// UPDATE would hold row locks across that scan, at boot, on a server that may already be serving reads.
	//
	// A LIMIT bounds each statement's lock footprint instead, and the loop ends when a pass changes nothing. Total work is the
	// same; what changes is that no single statement holds the table for the length of it.
	var total int64
	for {
		res, err := s.db.ExecContext(ctx, cases.String(), args...)
		if err != nil {
			return total, fmt.Errorf("backfill alert origins: %w", err)
		}
		updated, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("backfill alert origins rows affected: %w", err)
		}
		total += updated
		if updated < backfillBatchSize {
			return total, nil
		}
		// Yield between batches so a boot-time backfill cannot monopolise a connection against live traffic.
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
}

// backfillBatchSize bounds how many rows one statement rewrites.
//
// NOTE ON COVERAGE: removing the LIMIT is a MISSED mutation and always will be. Without it the UPDATE does the same work in
// one pass and every functional assertion still holds; what changes is the lock footprint, which a test in this package
// cannot observe without measuring contention against live traffic. The LOOP around it is covered, by seeding one more row
// than a batch holds. Large enough that a typical deployment finishes in one pass,
// small enough that no single statement holds a scan's worth of row locks.
const backfillBatchSize = 1000

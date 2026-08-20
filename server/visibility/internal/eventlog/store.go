// Package eventlog is the MySQL implementation of the visibility context's EventLog: the durable work queue that decouples ingestion
// from detection processing (ADR-0015). It backs the `event_queue` table and preserves the multi-replica, lock-free, per-host-ordered
// claim of ADR-0011 (FOR UPDATE SKIP LOCKED), mirroring the proven claim the detection event store used before the store split.
//
// Since issue #717 a claim is scoped to one host (PendingHosts picks the host, ClaimForHost takes its oldest events). The queue still
// does not make a host exclusive to one claimer; the detection processor layers a per-host advisory lock on top, and the host-scoped
// claim is what keeps one lock's critical section to one host's work.
package eventlog

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/sqlhelpers"
	"github.com/fleetdm/edr/server/visibility/api"
)

const (
	// deadlockMaxAttempts / deadlockBackoffStep bound the deadlock-retry loop shared by the append and prune paths. Concurrent
	// multi-replica writes to event_queue can deadlock on secondary-index gap locks (MySQL 1213) under INSERT IGNORE or a batched
	// DELETE; a few linear-backoff retries clear it.
	deadlockMaxAttempts = 5
	deadlockBackoffStep = 5 * time.Millisecond

	// appendChunkRows caps a single multi-row INSERT at 500 events (7 placeholders each, well under MySQL's 65535-placeholder and
	// 4 MB max_allowed_packet ceilings).
	appendChunkRows = 500

	// claimLeaseNs is the visibility timeout on a claim. A worker that claims events (processed = 2) but crashes before Ack/Nack leaves
	// them in-flight; once their claim is older than the lease, a later ClaimForHost re-offers them, honoring the EventLog at-least-once
	// contract. Set well above the longest expected per-batch processing time so a live worker is never double-served.
	claimLeaseNs = int64(5 * time.Minute)

	insertPrefix = `INSERT IGNORE INTO event_queue (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload) VALUES `
)

// Store is the MySQL-backed EventLog. It holds the shared *sqlx.DB pool cmd/main opens once via server/bootstrap.OpenDB; closing the
// handle is cmd/main's responsibility, not Store's.
type Store struct {
	db *sqlx.DB
}

// Compile-time check that Store satisfies the published EventLog contract.
var _ api.EventLog = (*Store)(nil)

// New returns a Store wrapping db. Schema is applied separately via visibility/bootstrap.ApplySchema.
func New(db *sqlx.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("visibility eventlog.New: db handle must not be nil")
	}
	return &Store{db: db}, nil
}

// Append enqueues events as not-yet-processed (processed = 0). Idempotent by EventID: INSERT IGNORE drops a re-appended event_id so an
// agent retry never double-enqueues. Events are persisted with the IngestedAtNs the caller already stamped; the queue does not
// re-stamp. At-least-once safe: a partial failure surfaces as an error and the caller retries the whole batch.
func (s *Store) Append(ctx context.Context, events []api.Event) error {
	if len(events) == 0 {
		return nil
	}
	return sqlhelpers.WithDeadlockRetry(ctx, deadlockMaxAttempts, deadlockBackoffStep, func() error {
		return s.appendOnce(ctx, events)
	})
}

func (s *Store) appendOnce(ctx context.Context, events []api.Event) error {
	for start := 0; start < len(events); start += appendChunkRows {
		end := min(start+appendChunkRows, len(events))
		chunk := events[start:end]
		placeholders, args, err := appendArgs(chunk)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, insertPrefix+strings.Join(placeholders, ", "), args...); err != nil {
			return fmt.Errorf("append events chunk [%d:%d]: %w", start, end, err)
		}
	}
	return nil
}

func appendArgs(chunk []api.Event) ([]string, []any, error) {
	placeholders := make([]string, len(chunk))
	args := make([]any, 0, len(chunk)*7)
	for i := range chunk {
		payloadBytes, err := json.Marshal(chunk[i].Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal payload for %s: %w", chunk[i].EventID, err)
		}
		placeholders[i] = "(?, ?, ?, ?, ?, ?, ?)"
		args = append(args, chunk[i].EventID, chunk[i].HostID, chunk[i].TimestampNs, chunk[i].IngestedAtNs, chunk[i].EventType, chunk[i].Platform, payloadBytes)
	}
	return placeholders, args, nil
}

// PendingHosts returns up to limit hosts with claimable work, longest-waiting first. It is a plain read: no locks, no claim, so two
// callers can see the same host and must not assume exclusivity from it. Ordering by each host's oldest claimable event is what keeps
// a busy host from starving a quiet one whose backlog is older.
//
// The claimable predicate matches ClaimForHost's: never-claimed rows plus rows whose claim has expired past claimLeaseNs. The OR
// across the two claim states defeats the (processed, host_id, timestamp_ns) index, so this is a full scan plus a temporary-table
// aggregate whose cost grows with backlog depth: measured on MySQL 8.4, 66ms over a 200k-row queue across 200 hosts. The cross-host
// claim it replaced scanned the same way (54ms on the same rows), so the scan predates the per-host split rather than arriving with
// it. Making it an index read needs a (processed, timestamp_ns) index plus a UNION of the two arms, one per claim state, which is a
// schema migration and its own change.
func (s *Store) PendingHosts(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	cutoff := time.Now().UnixNano() - claimLeaseNs
	var hosts []string
	err := s.db.SelectContext(ctx, &hosts, `
		SELECT host_id
		FROM event_queue
		WHERE processed = 0 OR (processed = 2 AND claimed_at_ns < ?)
		GROUP BY host_id
		ORDER BY MIN(timestamp_ns)
		LIMIT ?`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("pending hosts: %w", err)
	}
	return hosts, nil
}

// ClaimForHost atomically claims up to limit events for hostID, ordered by timestamp, without blocking concurrent claimers
// (FOR UPDATE SKIP LOCKED, ADR-0011). It offers both never-claimed rows (processed = 0) and rows whose prior claim has expired past
// claimLeaseNs (processed = 2 with a stale claimed_at_ns), so a worker that crashed between a claim and Ack has its events
// re-delivered. Claimed rows are stamped processed = 2 with a fresh claimed_at_ns in the same transaction.
//
// The claim is scoped to one host (issue #717). Before #717 it spanned hosts ordered by (host_id, timestamp_ns), which kept each
// host's events in order WITHIN a batch but let SKIP LOCKED hand two concurrent claimers an interleaved split of one host's stream:
// the graph builder then folded a pid's exec before its fork was flushed and duplicated the row. Scoping to a host does not fix that
// by itself, it makes the fix possible: the processor takes a per-host advisory lock around claim-fold-flush, which only bounds one
// host's work if the claim cannot reach across hosts.
//
// Concurrent claimers (across replicas, and since #535 across multiple in-process workers per replica) can deadlock on the
// event_queue claim (MySQL 1213): a single-box 500-host run logged ~1.6 claim deadlocks/sec. The claim transaction runs at READ
// COMMITTED so the SKIP LOCKED scan takes no next-key/gap locks on the (processed, host_id, timestamp_ns) index, removing the
// contention at its source, and the whole transaction is wrapped in the same bounded deadlock retry the append and prune paths use
// so any residual 1213 is cleared transparently rather than surfacing to the processor loop (issue #544).
func (s *Store) ClaimForHost(ctx context.Context, hostID string, limit int) ([]api.Event, error) {
	if limit <= 0 || hostID == "" {
		return nil, nil
	}
	var events []api.Event
	err := sqlhelpers.WithDeadlockRetry(ctx, deadlockMaxAttempts, deadlockBackoffStep, func() error {
		var claimErr error
		events, claimErr = s.claimOnce(ctx, hostID, limit)
		return claimErr
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

// claimOnce runs one claim transaction for one host. Extracted so ClaimForHost can wrap it in a deadlock retry. READ COMMITTED is
// deliberate (see ClaimForHost): the SKIP LOCKED scan must not take gap locks, or concurrent claimers deadlock on the claim UPDATE.
func (s *Store) claimOnce(ctx context.Context, hostID string, limit int) ([]api.Event, error) {
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx for claim: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	cutoff := time.Now().UnixNano() - claimLeaseNs

	// Never hand out an event that sits behind an in-flight one. A row another claimer still holds (processed = 2, lease unexpired)
	// does not match the claimable predicate below, so without this bound it is a HOLE the rest of the host's stream pours through:
	// a worker that claimed a fork and died before flushing leaves that fork in flight, its advisory lock released with its
	// connection, and the next claimer would take the following exec and fold it as an exec with no fork. The builder cannot tell
	// that apart from a genuinely fork-less exec, which is the duplicate generation issue #717 exists to remove. The same hole opens
	// for a few instructions on the failure path, between a builder-failed batch releasing the lock and its Nack landing.
	//
	// So the claim stops at the oldest in-flight event: everything strictly older is safe to fold (it cannot leapfrog anything), and
	// everything at or after it waits. Waiting costs at most one claim lease, after which the abandoned rows become claimable again
	// and are re-offered in timestamp order. That bounded delay is the right trade against folding a host's stream out of order, and
	// it is why the fix is not "shorten the lease": a live claimer's rows must never be stolen, only an expired claim's.
	//
	// The trade has a cost worth naming: a batch whose Ack fails now holds its host until the lease expires, where before the host's
	// later events would have flowed past it. The redelivery re-folds an already-materialized batch, which the at-least-once contract
	// already requires consumers to absorb, so the outcome is a bounded pause rather than lost or duplicated work.
	//
	// This floor is read in its own statement, one before the claim, which looks like a race: a row could become in-flight behind the
	// bound between the two reads. The only writer of processed = 2 is the claim's own UPDATE at the end of this function, so the only
	// actor that could open that window is a second claimer for THIS host, and the caller holds that host's advisory lock across both
	// statements. The window is therefore closed a layer up rather than here, which is also why the two reads share one transaction.
	// The exception is the documented no-coordinator path: with no lock to hold, two replicas can claim one host and this bound is
	// then advisory only, which is exactly the ordering guarantee that path already disclaims.
	var inFlight sql.NullInt64
	if err := tx.GetContext(ctx, &inFlight, `
		SELECT MIN(timestamp_ns)
		FROM event_queue
		WHERE host_id = ? AND processed = 2 AND claimed_at_ns >= ?`, hostID, cutoff); err != nil {
		return nil, fmt.Errorf("claim in-flight floor: %w", err)
	}
	// Carry the bound as a flag plus a value rather than folding "nothing in flight" into a sentinel timestamp. Two sentinel attempts
	// each produced an edge on agent-supplied timestamps: an exclusive bound against math.MaxInt64 stranded a row stamped exactly
	// there, and shifting the floor a tick below the in-flight row underflowed to MaxInt64 for a row stamped math.MinInt64, which
	// silently removed the bound altogether and reopened the gap this exists to close. There is no arithmetic and no reserved
	// timestamp value here, so no input can defeat the predicate: hasFloor 0 leaves the stream unbounded, and hasFloor 1 keeps the
	// rule exactly as stated above, strictly older than the oldest in-flight event.
	hasFloor := 0
	inFlightFloor := int64(0)
	if inFlight.Valid {
		hasFloor = 1
		inFlightFloor = inFlight.Int64
	}

	var events []api.Event
	err = tx.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, platform, payload
		FROM event_queue
		WHERE host_id = ? AND (processed = 0 OR (processed = 2 AND claimed_at_ns < ?)) AND (? = 0 OR timestamp_ns < ?)
		ORDER BY timestamp_ns
		LIMIT ?
		FOR UPDATE SKIP LOCKED`, hostID, cutoff, hasFloor, inFlightFloor, limit)
	if err != nil {
		return nil, fmt.Errorf("claim select: %w", err)
	}
	if len(events) == 0 {
		return events, tx.Commit()
	}

	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	query, args, err := sqlx.In("UPDATE event_queue SET processed = 2, claimed_at_ns = ? WHERE event_id IN (?)", time.Now().UnixNano(), ids)
	if err != nil {
		return nil, fmt.Errorf("claim build update: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return nil, fmt.Errorf("claim update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim tx: %w", err)
	}
	return events, nil
}

// Ack marks claimed events fully processed (-> 1); they will not be claimed again. A separate PruneProcessed sweep removes acknowledged
// rows so the queue stays small (the archive holds the retained history).
func (s *Store) Ack(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE event_queue SET processed = 1 WHERE event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("ack build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("ack: %w", err)
	}
	return nil
}

// Nack returns claimed events to the not-yet-processed state for an immediate later ClaimForHost, clearing the claim timestamp. It is
// scoped to processed = 2 so it only reverts in-flight rows and never resurrects an already-acknowledged event.
func (s *Store) Nack(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE event_queue SET processed = 0, claimed_at_ns = 0 WHERE processed = 2 AND event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("nack build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("nack: %w", err)
	}
	return nil
}

// CountPending counts events not yet acknowledged (processed != 1): the waiting-plus-in-flight backlog. Backs the processor-backlog
// gauge.
func (s *Store) CountPending(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM event_queue WHERE processed != 1"); err != nil {
		return 0, fmt.Errorf("count pending: %w", err)
	}
	return count, nil
}

// defaultPruneBatch caps a single prune DELETE so each statement's InnoDB row-lock + undo footprint stays bounded on a large backlog,
// the same per-batch discipline the process-retention sweep uses.
const defaultPruneBatch = 10_000

// PruneProcessed deletes acked rows (processed = 1) in bounded batches until none remain, returning the total removed. Ack only marks a
// row processed (a cheap index UPDATE on the hot path); this sweep does the deletes off the hot path so a high-volume queue does not
// accumulate. The DELETE is index-driven (the claim index leads with processed) and ordered like the claim, and each batch is
// deadlock-retried since concurrent claims take gap locks on the same index. processed = 1 is terminal (Nack only reverts processed = 2),
// so a row selected here is never concurrently resurrected.
func (s *Store) PruneProcessed(ctx context.Context, batchSize int) (int64, error) {
	if batchSize <= 0 {
		batchSize = defaultPruneBatch
	}
	var total int64
	for {
		var affected int64
		if err := sqlhelpers.WithDeadlockRetry(ctx, deadlockMaxAttempts, deadlockBackoffStep, func() error {
			res, err := s.db.ExecContext(ctx,
				"DELETE FROM event_queue WHERE processed = 1 ORDER BY host_id, timestamp_ns LIMIT ?", batchSize)
			if err != nil {
				return err
			}
			affected, err = res.RowsAffected()
			return err
		}); err != nil {
			return total, fmt.Errorf("prune processed event_queue: %w", err)
		}
		total += affected
		if affected < int64(batchSize) {
			return total, nil
		}
	}
}

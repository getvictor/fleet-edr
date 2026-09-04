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
// The predicate matches ClaimForHost's in full, including that claim's in-flight floor, so a host appears here only if a claim would
// actually hand something back. Matching only the claimable-row half is not good enough, and the gap is not academic: a host stalled
// behind an unexpired in-flight event still owns never-claimed rows, so it reads as pending while every claim against it returns
// empty. Such a host would take a slot in the processor's finite candidate window, and the longest-waiting order works against us
// because its oldest claimable row sits just behind the in-flight one and therefore sorts to the FRONT, where it stays for the whole
// claim lease. One stranded batch per worker per replica is what a rolling restart leaves behind, which is enough to fill the window
// at fleet sizes we already run, and a window full of hosts that can only answer empty is a fleet-wide pause built out of pauses that
// were each supposed to be per-host and bounded.
//
// The claimable predicate matches ClaimForHost's: never-claimed rows plus rows whose claim has expired past claimLeaseNs. Written as
// one OR across the two claim states it defeats every index, because no index is ordered by timestamp across states, so it was a
// full scan plus a temp-table aggregate (issue #720). Split into one arm per claim state, each arm's predicate is a single
// `processed` value an index can serve, and the per-host MIN collapses each arm to one row per host before the floor join.
//
// Measured on MySQL 8.4 over a 200k-row queue across 200 hosts with 2k in-flight and 2k expired claims: 67.6ms before, 29.8ms after,
// returning an identical host list. The split is most of it (67.6 to 37) and the new index the rest (37 to 29.8).
//
// This stays EXACT rather than sampling, which is a deliberate reversal worth recording. A variant reading only the oldest 2000 rows
// per arm measured 3.3ms, a 20x win, and was WRONG: the row limit applies before the floor join, so one host with an unexpired
// in-flight event and 2000 rows queued behind it fills the window with rows the floor then removes, and the query returns NOTHING
// while other hosts have claimable work. That is the fleet-wide stall #719 exists to prevent, reintroduced through the back door.
// Applying the floor inside each arm restores the semantics and costs 71ms, worse than doing nothing, because the join stops the
// limit being pushed into the index read. The cheap bound and the correct answer are exclusive here, and correctness is not the
// half to trade away for 25ms.
func (s *Store) PendingHosts(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	cutoff := time.Now().UnixNano() - claimLeaseNs
	var hosts []string
	err := s.db.SelectContext(ctx, &hosts, `
		SELECT c.host_id
		FROM (
			SELECT host_id, MIN(timestamp_ns) AS oldest_ns
			FROM event_queue
			WHERE processed = 0
			GROUP BY host_id
			UNION ALL
			SELECT host_id, MIN(timestamp_ns) AS oldest_ns
			FROM event_queue
			WHERE processed = 2 AND claimed_at_ns < ?
			GROUP BY host_id
		) c
		LEFT JOIN (
			SELECT host_id, MIN(timestamp_ns) AS floor_ns
			FROM event_queue
			WHERE processed = 2 AND claimed_at_ns >= ?
			GROUP BY host_id
		) f ON f.host_id = c.host_id
		WHERE f.floor_ns IS NULL OR c.oldest_ns < f.floor_ns
		GROUP BY c.host_id
		ORDER BY MIN(c.oldest_ns)
		LIMIT ?`, cutoff, cutoff, limit)
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
func (s *Store) ClaimForHost(ctx context.Context, hostID string, limit int) ([]api.Event, int64, error) {
	if limit <= 0 || hostID == "" {
		return nil, 0, nil
	}
	var (
		events []api.Event
		stamp  int64
	)
	err := sqlhelpers.WithDeadlockRetry(ctx, deadlockMaxAttempts, deadlockBackoffStep, func() error {
		var claimErr error
		events, stamp, claimErr = s.claimOnce(ctx, hostID, limit)
		return claimErr
	})
	if err != nil {
		return nil, 0, err
	}
	return events, stamp, nil
}

// claimOnce runs one claim transaction for one host. Extracted so ClaimForHost can wrap it in a deadlock retry. READ COMMITTED is
// deliberate (see ClaimForHost): the SKIP LOCKED scan must not take gap locks, or concurrent claimers deadlock on the claim UPDATE.
func (s *Store) claimOnce(ctx context.Context, hostID string, limit int) ([]api.Event, int64, error) {
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx for claim: %w", err)
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
		return nil, 0, fmt.Errorf("claim in-flight floor: %w", err)
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
		return nil, 0, fmt.Errorf("claim select: %w", err)
	}
	if len(events) == 0 {
		return events, 0, tx.Commit()
	}

	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.EventID
	}
	// The stamp is this claim's identity, returned so Ack can prove it still holds the claim it is acknowledging (issue #817).
	// Reusing claimed_at_ns rather than adding a token column: it is already written here, already unique per claim in practice,
	// and a re-claim necessarily overwrites it, which is exactly the condition Ack needs to detect. Two claims landing in the same
	// nanosecond would both match, which is a residual rather than a guarantee; it needs a clock coarser than the one this runs on.
	stamp := time.Now().UnixNano()
	query, args, err := sqlx.In("UPDATE event_queue SET processed = 2, claimed_at_ns = ? WHERE event_id IN (?)", stamp, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("claim build update: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return nil, 0, fmt.Errorf("claim update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit claim tx: %w", err)
	}
	return events, stamp, nil
}

// Ack marks claimed events fully processed (-> 1); they will not be claimed again. A separate PruneProcessed sweep removes acknowledged
// rows so the queue stays small (the archive holds the retained history).
//
// Conditional on still holding the claim, and reports whether it did (issue #817). A claim expires after claimLeaseNs and is
// re-offered, so an evaluation that outlives its lease runs alongside its own reclaimer; before this both attempts acknowledged
// successfully and neither learned it had lost. Alert persistence was unharmed because it deduplicates on (host, rule, subject),
// but anything additive after the ack counted the batch twice, and the gap was in the queue contract rather than in the counter.
//
// held is false when the rows are no longer in this claim: either another claimer took them (claimed_at_ns moved) or they are no
// longer in flight at all. A caller that has lost the claim must skip whatever it does after acknowledging, because the attempt
// that now owns the rows will do it.
func (s *Store) Ack(ctx context.Context, eventIDs []string, claimStampNs int64) (held bool, err error) {
	if len(eventIDs) == 0 {
		return true, nil
	}
	query, args, err := sqlx.In(
		"UPDATE event_queue SET processed = 1 WHERE event_id IN (?) AND processed = 2 AND claimed_at_ns = ?", eventIDs, claimStampNs)
	if err != nil {
		return false, fmt.Errorf("ack build query: %w", err)
	}
	// In a transaction so a partial match applies NOTHING. Without it the UPDATE advances whichever rows still match, and the
	// caller is told it lost while half the batch has been acknowledged: the rows another attempt owns get re-processed by it,
	// and the rows this attempt just acked are never processed by anyone. Found by the test for the partial case, which the
	// single-event version of it could not reach.
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx for ack: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("ack: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("ack rows affected: %w", err)
	}
	// Partial is treated as lost rather than won. A subset matching means the claim covered rows another attempt has since taken,
	// so this attempt cannot claim to have processed the batch exactly once, which is the only thing the result is used for. The
	// deferred rollback is what undoes the rows that did match.
	if affected != int64(len(eventIDs)) {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit ack: %w", err)
	}
	return true, nil
}

// The `processed` column carries four states, written as literals in the SQL below and named here rather than as constants, which
// would be identifiers no Go expression reads:
//
//	0 = pending, claimable
//	1 = acknowledged, terminal, deleted by PruneProcessed
//	2 = claimed, with claimed_at_ns; re-offered once the lease expires
//	3 = SET ASIDE, withdrawn from processing after repeated failure (issue #836), stamped set_aside_at_ns, deleted by
//	    PruneSetAside once that stamp is older than the retention window
//
// Only 0 and a lease-expired 2 are claimable, so 3 is excluded from ClaimForHost by the predicate that was already there.

// setAsideAttempts and setAsideWindow are the two bounds a batch must BOTH exceed before its events are set aside.
//
// Both, because one cannot tell the two failure shapes apart. At the 500ms processor tick a failing batch is attempted roughly 120
// times a minute, so an attempt bound alone would set aside anything that failed for ten seconds. A duration bound alone would set
// aside a batch that failed once and then sat for a long time because its host went quiet, since its second attempt would already
// be outside the window.
//
// Twenty attempts is reached in about ten seconds and exists only to rule out that second shape. Fifteen minutes is the bound that
// does the work: no condition shorter than that sets anything aside, a host stalls for at most about that long rather than
// indefinitely, and it is three claim leases, which is the other timescale in this subsystem.
//
// Not configurable. They are constants with their reasoning attached, and can become configuration when a deployment needs
// different values rather than in anticipation of one.
const (
	setAsideAttempts = 20
	setAsideWindow   = 15 * time.Minute
)

// Nack returns claimed events to the not-yet-processed state for an immediate later ClaimForHost, clearing the claim timestamp, and
// counts the attempt. It reports how many events it SET ASIDE instead of returning, which is zero on all but the failing case.
//
// Scoped to processed = 2 so it only reverts in-flight rows and never resurrects an already-acknowledged event.
//
// The count and the set-aside are what keep a deterministically failing batch from stalling its host forever. The claim selects a
// host's work in timestamp order, so a nacked batch is that host's oldest pending work and the next claim takes it again; without a
// bound, nothing newer for that host is ever claimed and the host stops contributing to the graph and raising detections entirely
// (issue #836). Setting the events aside is not data loss: the archive is written before the queue and retained on its own window,
// so what is given up is those events' contribution to the graph and their evaluation by rules.
//
// A claim is identified here by state alone, not by owner, which leaves one window this does not close: a worker whose fold outran
// the 5-minute claim lease nacks rows a replacement worker has since re-claimed, resetting that claim and counting an attempt
// against it. The window is narrow by construction, since a live claim is refused to every other claimer by both the claimable
// predicate and the in-flight floor, so reaching it needs a fold slower than the whole lease. It is also pre-existing and bounded:
// the replacement's Ack still lands and the event is still processed, so the cost is an inflated attempt count rather than lost
// work, and a spurious set-aside would need that to recur twenty times across fifteen minutes on one batch. Closing it properly
// means carrying the claim stamp back to the caller and making Nack and Ack conditional on still owning it, which changes a
// cross-context interface and fixes a different defect (the same stale nack can also let two workers process one event). Tracked
// as issue #840 rather than folded in here.
func (s *Store) Nack(ctx context.Context, eventIDs []string) (setAside int64, err error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin tx for nack: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UnixNano()
	query, args, err := sqlx.In(`
		UPDATE event_queue
		SET attempts = attempts + 1,
		    first_failed_at_ns = IF(first_failed_at_ns = 0, ?, first_failed_at_ns),
		    processed = 0,
		    claimed_at_ns = 0
		WHERE processed = 2 AND event_id IN (?)`, now, eventIDs)
	if err != nil {
		return 0, fmt.Errorf("nack build query: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return 0, fmt.Errorf("nack: %w", err)
	}

	// The processed = 0 guard restricts this to rows the statement above actually reset, and so keeps a row that was NOT in flight
	// out of state 3: an event id in this batch that another worker already acked (1), or that an earlier failure already set aside
	// (3), does not match and is left alone. It is NOT protection against a concurrent claimer. The statement above holds an
	// exclusive lock on every row it modified until this transaction commits, and the claim's SELECT ... FOR UPDATE SKIP LOCKED
	// skips locked rows, so no other worker can take these rows between the two statements. (A row can still be reset by a worker
	// whose claim lease expired, which is the ownership limitation documented on Nack above and tracked as issue #840; the guard
	// here neither causes nor prevents that.)
	//
	// The duration bound is a cutoff computed here rather than arithmetic in the predicate. `? - first_failed_at_ns >= ?` would
	// have to evaluate an expression per row, where a bare column comparison can use an index; and the lint that bans a spaced
	// hyphen in prose reads SQL subtraction the same way, which is a nudge worth taking rather than suppressing.
	failingSince := now - setAsideWindow.Nanoseconds()
	query, args, err = sqlx.In(`
		UPDATE event_queue
		SET processed = 3, set_aside_at_ns = ?
		WHERE processed = 0 AND event_id IN (?) AND attempts >= ? AND first_failed_at_ns <= ?`,
		now, eventIDs, setAsideAttempts, failingSince)
	if err != nil {
		return 0, fmt.Errorf("nack set-aside build query: %w", err)
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("nack set aside: %w", err)
	}
	setAside, err = res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("nack set-aside rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit nack: %w", err)
	}
	return setAside, nil
}

// CountPending counts events still waiting to be processed or in flight (processed 0 or 2). Backs the processor-backlog gauge.
//
// Set-aside rows (3) are excluded deliberately. They are not waiting for anything, so counting them would leave the backlog gauge
// permanently elevated by a number that never drains, which is the shape an operator reads as a processor falling behind. The
// separate edr.events.set_aside counter is what reports them.
func (s *Store) CountPending(ctx context.Context) (int64, error) {
	var count int64
	if err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM event_queue WHERE processed IN (0, 2)"); err != nil {
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
	total, err := s.pruneBatched(ctx, batchSize,
		"DELETE FROM event_queue WHERE processed = 1 ORDER BY host_id, timestamp_ns LIMIT ?")
	if err != nil {
		return total, fmt.Errorf("prune processed event_queue: %w", err)
	}
	return total, nil
}

// PruneSetAside deletes set-aside rows (processed = 3) withdrawn longer ago than retentionDays, returning the total removed.
//
// Needed because PruneProcessed only deletes acked rows, so without this a set-aside row would sit in the work queue for the life
// of the deployment. Retaining them at all is deliberate: the row names the exact events a host stopped contributing, which the
// counter cannot. Retaining them forever is not, so the retention window doubles as the period an operator has to look.
//
// Aged on set_aside_at_ns, when the entry was WITHDRAWN, not on first_failed_at_ns and not on the event's own timestamp. The three
// diverge without bound: attempts accrue only while a host is online, so a batch can first fail, wait out an offline stretch longer
// than the whole retention window, and only then reach the attempt bound. Ageing on first failure would withdraw that batch and
// sweep it on the next tick, leaving no window to inspect it in, which is the opposite of what the window is for.
func (s *Store) PruneSetAside(ctx context.Context, retentionDays, batchSize int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour).UnixNano()
	total, err := s.pruneBatched(ctx, batchSize,
		"DELETE FROM event_queue WHERE processed = 3 AND set_aside_at_ns < ? ORDER BY set_aside_at_ns LIMIT ?", cutoff)
	if err != nil {
		return total, fmt.Errorf("prune set-aside event_queue: %w", err)
	}
	return total, nil
}

// pruneBatched runs one DELETE repeatedly until a batch comes back short, and reports the total.
//
// Shared by the two prune methods above rather than written twice. The batch bound, the deadlock retry and the
// stop-when-short-batch loop are identical for both and are the parts that are easy to get subtly different; only the predicate
// differs, and it is a caller-supplied constant rather than anything built from input. The query MUST end in `LIMIT ?`, since the
// batch size is appended as the final argument.
//
// This deliberately does not reach across packages: issue #818 tracks the same loop appearing in three prune paths in different
// packages, and unifying those is its own change. This keeps THIS file from becoming a fourth copy.
func (s *Store) pruneBatched(ctx context.Context, batchSize int, query string, args ...any) (int64, error) {
	if batchSize <= 0 {
		batchSize = defaultPruneBatch
	}
	var total int64
	for {
		var affected int64
		if err := sqlhelpers.WithDeadlockRetry(ctx, deadlockMaxAttempts, deadlockBackoffStep, func() error {
			res, err := s.db.ExecContext(ctx, query, append(append([]any(nil), args...), batchSize)...)
			if err != nil {
				return err
			}
			affected, err = res.RowsAffected()
			return err
		}); err != nil {
			return total, err
		}
		total += affected
		if affected < int64(batchSize) {
			return total, nil
		}
	}
}

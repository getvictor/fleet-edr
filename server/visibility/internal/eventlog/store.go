// Package eventlog is the MySQL implementation of the visibility context's EventLog: the durable work queue that decouples ingestion
// from detection processing (ADR-0015). It backs the `event_queue` table and preserves the multi-replica, lock-free, per-host-ordered
// claim of ADR-0011 (FOR UPDATE SKIP LOCKED), mirroring the proven claim the detection event store used before the store split.
package eventlog

import (
	"context"
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
	// insertMaxAttempts / insertBackoffStep bound the deadlock-retry loop. Concurrent multi-replica appends to event_queue can deadlock
	// on secondary-index gap locks under INSERT IGNORE (MySQL 1213); a few linear-backoff retries clear it.
	insertMaxAttempts = 5
	insertBackoffStep = 5 * time.Millisecond

	// appendChunkRows caps a single multi-row INSERT at 500 events (6 placeholders each, well under MySQL's 65535-placeholder and
	// 4 MB max_allowed_packet ceilings).
	appendChunkRows = 500

	// claimLeaseNs is the visibility timeout on a claim. A worker that claims events (processed = 2) but crashes before Ack/Nack leaves
	// them in-flight; once their claim is older than the lease, a later Claim re-offers them, honoring the EventLog at-least-once
	// contract. Set well above the longest expected per-batch processing time so a live worker is never double-served.
	claimLeaseNs = int64(5 * time.Minute)

	insertPrefix = `INSERT IGNORE INTO event_queue (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload) VALUES `
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
	return sqlhelpers.WithDeadlockRetry(ctx, insertMaxAttempts, insertBackoffStep, func() error {
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
	args := make([]any, 0, len(chunk)*6)
	for i := range chunk {
		payloadBytes, err := json.Marshal(chunk[i].Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal payload for %s: %w", chunk[i].EventID, err)
		}
		placeholders[i] = "(?, ?, ?, ?, ?, ?)"
		args = append(args, chunk[i].EventID, chunk[i].HostID, chunk[i].TimestampNs, chunk[i].IngestedAtNs, chunk[i].EventType, payloadBytes)
	}
	return placeholders, args, nil
}

// Claim atomically claims up to limit events for this worker, ordered per host by timestamp, without blocking concurrent claimers
// (FOR UPDATE SKIP LOCKED, ADR-0011). It offers both never-claimed rows (processed = 0) and rows whose prior claim has expired past
// claimLeaseNs (processed = 2 with a stale claimed_at_ns), so a worker that crashed between Claim and Ack has its events re-delivered.
// Claimed rows are stamped processed = 2 with a fresh claimed_at_ns in the same transaction.
func (s *Store) Claim(ctx context.Context, limit int) ([]api.Event, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx for claim: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	cutoff := time.Now().UnixNano() - claimLeaseNs
	var events []api.Event
	err = tx.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
		FROM event_queue
		WHERE processed = 0 OR (processed = 2 AND claimed_at_ns < ?)
		ORDER BY host_id, timestamp_ns
		LIMIT ?
		FOR UPDATE SKIP LOCKED`, cutoff, limit)
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

// Ack marks claimed events fully processed (-> 1); they will not be claimed again. A separate retention sweep removes acknowledged
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

// Nack returns claimed events to the not-yet-processed state for an immediate later Claim, clearing the claim timestamp. Scoped to
// processed = 2 so it only reverts in-flight rows and never resurrects an already-acknowledged event.
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

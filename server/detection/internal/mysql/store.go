package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/api"
)

// mysqlErrDeadlock is MySQL error 1213: "Deadlock found when trying to get lock; try restarting transaction". The server-error
// documentation explicitly tells callers to retry, and INSERT IGNORE under concurrent batch load can trip gap locks on secondary
// indexes even when primary keys do not collide.
const mysqlErrDeadlock = 1213

// isDeadlockErr reports whether err wraps a MySQL deadlock (error 1213). Surface-level signal only: the caller decides whether
// retrying is safe (which depends on whether the transaction is idempotent).
func isDeadlockErr(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDeadlock
}

// Store is the persistence handle for the detection bounded context. Holds the shared *sqlx.DB pool that cmd/main opens once via
// server/bootstrap.OpenDB and shares across every context.
type Store struct {
	db *sqlx.DB
}

// New returns a Store wrapping the provided db handle. Schema is
// applied separately via detection/bootstrap.ApplySchema; New just
// hands back the read/write surface.
//
// Closing the db handle is cmd/main's responsibility, not Store's.
func New(db *sqlx.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("detection mysql.New: db handle must not be nil")
	}
	return &Store{db: db}, nil
}

// DB returns the underlying *sqlx.DB. Used by integration tests that
// need raw access (e.g. assertion queries that bypass the typed API).
func (s *Store) DB() *sqlx.DB { return s.db }

// PingContext verifies connectivity to the underlying database.
// Used by the readiness probe.
func (s *Store) PingContext(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// Close is a no-op. The db handle is shared across bounded contexts and owned by cmd/main; closing it here would yank the pool out
// from under sibling contexts.
func (s *Store) Close() error { return nil }

// InsertEvents upserts a batch of events. Duplicates (by event_id) are ignored. Each row is stamped with a server-controlled
// ingested_at_ns; the caller's Event.IngestedAtNs is ignored so agents can't set it.
func (s *Store) InsertEvents(ctx context.Context, events []api.Event) error {
	return s.insertEventsAt(ctx, events, time.Now().UnixNano())
}

// InsertEventsAt is a test-only variant that takes a deterministic ingest timestamp. Production callers go through InsertEvents. This
// path exists so cross-source correlation tests can simulate the ES/NE clock-drift scenario (issue #7) without relying on wall-clock
// timing.
func (s *Store) InsertEventsAt(ctx context.Context, events []api.Event, ingestedAtNs int64) error {
	return s.insertEventsAt(ctx, events, ingestedAtNs)
}

// insertMaxAttempts and insertBackoffStep size the deadlock-retry loop. Five attempts at 5ms*attempt linear backoff is short on
// purpose: MySQL deadlock detection fires in sub-millisecond windows, and waiting longer just bottlenecks throughput under the
// concurrent-batch shape that the 25-host enrollHostsBatch e2e fixture exercises.
const (
	insertMaxAttempts = 5
	insertBackoffStep = 5 * time.Millisecond

	// eventInsertChunkRows caps rows per multi-row INSERT so we stay well under MySQL's 65535-placeholder limit (6 cols/row) and
	// the default 4MB max_allowed_packet once JSON payloads are included.
	eventInsertChunkRows = 500
	// eventStampChunkRows caps event_ids per SELECT-back IN(...) clause on the duplicate path.
	eventStampChunkRows = 1000
)

func (s *Store) insertEventsAt(ctx context.Context, events []api.Event, ingestedAtNs int64) error {
	if len(events) == 0 {
		return nil
	}
	// INSERT IGNORE on the events table can deadlock under concurrent batch load: each transaction takes gap locks on the secondary
	// indexes (idx_events_host_id, idx_events_host_type_ingested, etc.) and unrelated concurrent inserts on different host_ids can
	// still hit lock-order inversion. The transaction is fully idempotent (INSERT IGNORE skips duplicates and we re-stamp
	// ingested_at_ns only on rows actually inserted), so we retry on error 1213.
	return withDeadlockRetry(ctx, insertMaxAttempts, insertBackoffStep, func() error {
		return s.insertEventsAtOnce(ctx, events, ingestedAtNs)
	})
}

// withDeadlockRetry runs fn up to maxAttempts times, retrying on MySQL deadlock errors (1213) with a linear backoff of attempt*step.
// Returns immediately on success or on a non-deadlock error. Respects ctx cancellation during backoff. Callers must guarantee fn is
// idempotent (running it after a rolled-back attempt must produce the same final state); this helper does not enforce that property.
func withDeadlockRetry(ctx context.Context, maxAttempts int, step time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isDeadlockErr(lastErr) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * step):
		}
	}
	return lastErr
}

func (s *Store) insertEventsAtOnce(ctx context.Context, events []api.Event, ingestedAtNs int64) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	// Insert the whole batch with a handful of multi-row INSERT IGNORE statements rather than one statement per event. At fleet
	// scale a batch carries hundreds of events, and one round-trip per event dominated ingest latency (a ~100-event batch was
	// ~100 sequential round-trips, seconds of wall time). Chunked to stay under MySQL's placeholder + max_allowed_packet limits.
	// INSERT IGNORE keeps the statement idempotent, so withDeadlockRetry can re-run it safely.
	allInserted := true
	for start := 0; start < len(events); start += eventInsertChunkRows {
		end := min(start+eventInsertChunkRows, len(events))
		chunk := events[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)*6)
		for i := range chunk {
			payloadBytes, err := json.Marshal(chunk[i].Payload)
			if err != nil {
				return fmt.Errorf("marshal payload for %s: %w", chunk[i].EventID, err)
			}
			placeholders[i] = "(?, ?, ?, ?, ?, ?)"
			args = append(args, chunk[i].EventID, chunk[i].HostID, chunk[i].TimestampNs, ingestedAtNs, chunk[i].EventType, payloadBytes)
		}
		res, err := tx.ExecContext(ctx, `INSERT IGNORE INTO events (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload) VALUES `+
			strings.Join(placeholders, ", "), args...)
		if err != nil {
			return fmt.Errorf("insert events chunk [%d:%d]: %w", start, end, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("rows affected: %w", err)
		}
		if int(affected) != len(chunk) {
			allInserted = false // at least one duplicate event_id was IGNOREd in this chunk
		}
	}

	// Stamp the caller's slice with the persisted ingested_at_ns (the graph builder reads it). Fast path: when every row was newly
	// inserted, they all carry this batch's ingestedAtNs, so no extra query is needed. Slow path: a duplicate event_id keeps the
	// ingested_at_ns from its first insert, so read the real values back. Resolve inside the tx but write to the slice only after a
	// successful commit, so a rolled-back / retried attempt never leaves the caller's slice half-stamped.
	var persisted map[string]int64
	if !allInserted {
		persisted, err = selectIngestedAt(ctx, tx, events)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	if allInserted {
		for i := range events {
			events[i].IngestedAtNs = ingestedAtNs
		}
		return nil
	}
	for i := range events {
		if ts, ok := persisted[events[i].EventID]; ok {
			events[i].IngestedAtNs = ts
		}
	}
	return nil
}

// selectIngestedAt reads the persisted ingested_at_ns for each event_id, chunked to stay under MySQL's placeholder limit. Used on
// the duplicate path, where a row that already existed retains the ingested_at_ns from its first insert and so no longer matches
// this batch's ingestedAtNs.
func selectIngestedAt(ctx context.Context, tx *sqlx.Tx, events []api.Event) (map[string]int64, error) {
	persisted := make(map[string]int64, len(events))
	for start := 0; start < len(events); start += eventStampChunkRows {
		end := min(start+eventStampChunkRows, len(events))
		if err := scanIngestedAtChunk(ctx, tx, events[start:end], persisted); err != nil {
			return nil, err
		}
	}
	return persisted, nil
}

// scanIngestedAtChunk reads one IN(...) chunk into out. Split from selectIngestedAt so `defer rows.Close()` fires per chunk
// rather than accumulating until the whole batch is read.
func scanIngestedAtChunk(ctx context.Context, tx *sqlx.Tx, chunk []api.Event, out map[string]int64) error {
	placeholders := make([]string, len(chunk))
	ids := make([]any, len(chunk))
	for i := range chunk {
		placeholders[i] = "?"
		ids[i] = chunk[i].EventID
	}
	rows, err := tx.QueryxContext(ctx, `SELECT event_id, ingested_at_ns FROM events WHERE event_id IN (`+
		strings.Join(placeholders, ", ")+`)`, ids...)
	if err != nil {
		return fmt.Errorf("select ingested_at_ns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var ts int64
		if err := rows.Scan(&id, &ts); err != nil {
			return fmt.Errorf("scan ingested_at_ns: %w", err)
		}
		out[id] = ts
	}
	return rows.Err()
}

// CountEvents returns the total number of events.
func (s *Store) CountEvents(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM events")
	return count, err
}

// CountUnprocessed returns the number of events that have not been fully processed (state 0 or 2). Used by the OTel unprocessed-events
// gauge.
func (s *Store) CountUnprocessed(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM events WHERE processed != 1")
	return count, err
}

// FetchUnprocessed atomically claims up to limit unprocessed events for the graph builder. Uses SELECT ... FOR UPDATE SKIP LOCKED
// to prevent concurrent processors from claiming the same rows, and transitions events from state 0 (unprocessed) to 2 (processing)
// within the same transaction. Events are ordered by host_id and timestamp to ensure correct per-host ordering.
func (s *Store) FetchUnprocessed(ctx context.Context, limit int) ([]api.Event, error) {
	if limit <= 0 {
		return nil, nil
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx for fetch unprocessed: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	var events []api.Event
	err = tx.SelectContext(ctx, &events, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
		FROM events
		WHERE processed = 0
		ORDER BY host_id, timestamp_ns
		LIMIT ?
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed select: %w", err)
	}

	if len(events) == 0 {
		return events, tx.Commit()
	}

	eventIDs := make([]string, len(events))
	for i, e := range events {
		eventIDs[i] = e.EventID
	}

	claimQuery, args, err := sqlx.In("UPDATE events SET processed = 2 WHERE event_id IN (?)", eventIDs)
	if err != nil {
		return nil, fmt.Errorf("fetch unprocessed build claim query: %w", err)
	}
	if _, err := tx.ExecContext(ctx, claimQuery, args...); err != nil {
		return nil, fmt.Errorf("fetch unprocessed claim: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit fetch unprocessed tx: %w", err)
	}
	return events, nil
}

// MarkProcessed marks the given events as fully processed (state 2 -> 1).
func (s *Store) MarkProcessed(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE events SET processed = 1 WHERE event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("mark processed build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("mark processed: %w", err)
	}
	return nil
}

// UnclaimEvents transitions events from processing (state 2) back
// to unprocessed (state 0) so they can be retried.
func (s *Store) UnclaimEvents(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 {
		return nil
	}
	query, args, err := sqlx.In("UPDATE events SET processed = 0 WHERE processed = 2 AND event_id IN (?)", eventIDs)
	if err != nil {
		return fmt.Errorf("unclaim events build query: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("unclaim events: %w", err)
	}
	return nil
}

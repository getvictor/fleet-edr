// Package queue provides a durable SQLite WAL-based event queue for the EDR agent.
//
// The queue enforces a byte-size cap (EDR_AGENT_QUEUE_MAX_BYTES). When an
// Enqueue would push the main DB file past the cap, the queue drops oldest rows to
// stay bounded. Uploaded rows are dropped first (lossless — they've already reached
// the server); if the cap is still exceeded, non-uploaded rows are dropped lossy and
// a warn log is emitted so the operator sees the backpressure.
//
// At this layer, MaxBytes=0 disables the cap (unbounded growth). The agent-level
// config (`EDR_AGENT_QUEUE_MAX_BYTES`) defaults that knob to 500 MiB, so bounded
// queueing is on by default in a stock agent; set `EDR_AGENT_QUEUE_MAX_BYTES=0`
// to disable the cap entirely.
package queue

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	// Register the CGo-free modernc.org/sqlite driver under the name "sqlite" so sql.Open("sqlite", ...) below finds it. Blank import is
	// required because database/sql drivers register themselves in an init() function.
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	event_json TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	uploaded   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_uploaded ON events(uploaded, id);
`

// migrationsClientErrorCount lazily adds the client_error_count column to the events table on Open. The column is the
// per-row counter the uploader bumps on every drain-tick that returns a non-401 4xx for the row's batch; once the value
// crosses the operator-configured quarantine threshold the row is set uploaded=1 so it stops being dequeued
// (#253: permanent-client-errors-are-not-infinitely-retained). The migration is conditional via `PRAGMA table_info` +
// ALTER TABLE so existing on-disk queues from older agent versions upgrade in place without losing pending events.
const migrationsClientErrorCount = `client_error_count`

// QueuedEvent is an event read from the queue.
type QueuedEvent struct {
	ID        int64
	EventJSON []byte
	CreatedAt time.Time
}

// Options tune the queue at Open time. Leave zero for the default behaviour.
type Options struct {
	// MaxBytes is the soft cap on the SQLite main-file size. 0 disables the cap.
	// When an Enqueue observes the DB file past MaxBytes, trim() drops oldest rows.
	MaxBytes int64
	// Logger receives queue-cap warn messages when lossy drops happen. Nil uses
	// slog.Default().
	Logger *slog.Logger
}

// MetricsRecorder is the optional OTel hook. Nil is fine.
type MetricsRecorder interface {
	// QueueDropped is invoked when trim() removed rows. `lossy=true` means non-uploaded
	// rows were dropped (events lost forever); operators care about this count.
	QueueDropped(ctx context.Context, n int64, lossy bool)
}

// Queue is a durable event queue backed by SQLite in WAL mode.
type Queue struct {
	db       *sql.DB
	maxBytes int64
	logger   *slog.Logger
	metrics  MetricsRecorder
}

// Open creates or opens a SQLite queue at the given path. opts may be the zero
// value for unbounded behaviour.
func Open(ctx context.Context, dbPath string, opts Options) (*Queue, error) {
	// Set busy_timeout + journal_size_limit via DSN so they apply to every connection in the pool. journal_size_limit=32MB keeps the WAL
	// file itself from growing without bound and silently busting the main-file cap.
	dsn := dbPath +
		"?_pragma=busy_timeout%3d5000" +
		"&_pragma=journal_mode%3dwal" +
		"&_pragma=journal_size_limit%3d33554432"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// SQLite only supports one writer at a time. Limiting to a single connection
	// avoids SQLITE_BUSY contention between pooled connections.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	if err := migrateClientErrorCount(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate client_error_count: %w", err)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Queue{db: db, maxBytes: opts.MaxBytes, logger: logger}, nil
}

// migrateClientErrorCount adds the client_error_count column to existing events tables. SQLite's ALTER TABLE ADD COLUMN
// is online for a column with a DEFAULT, so the migration is safe to run on an agent that's been queuing events for
// months. The PRAGMA table_info pre-check makes the migration idempotent across Open calls.
func migrateClientErrorCount(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(events)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == migrationsClientErrorCount {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx,
		"ALTER TABLE events ADD COLUMN client_error_count INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

// RecordClientError increments the client_error_count for every id in `ids` and, when the post-increment value reaches
// `quarantineThreshold`, sets uploaded=1 so the row stops being dequeued. Returns the subset of ids that crossed the
// threshold on THIS call so the caller (the uploader) can emit one audit-log line per newly-quarantined batch.
//
// The contract the uploader relies on: a row is quarantined exactly once. Subsequent RecordClientError calls against
// the same id are no-ops because the row's uploaded column is already 1 and the DequeueBatch query filters on
// uploaded=0. quarantineThreshold <= 0 disables quarantine (counter still bumps so operators can read it via the
// debug surface, but no row is sealed).
func (q *Queue) RecordClientError(ctx context.Context, ids []int64, quarantineThreshold int) ([]int64, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	bumpStmt, err := tx.PrepareContext(ctx,
		"UPDATE events SET client_error_count = client_error_count + 1 WHERE id = ? AND uploaded = 0")
	if err != nil {
		return nil, err
	}
	defer bumpStmt.Close()

	var quarantineStmt *sql.Stmt
	if quarantineThreshold > 0 {
		quarantineStmt, err = tx.PrepareContext(ctx,
			"UPDATE events SET uploaded = 1 WHERE id = ? AND client_error_count >= ? AND uploaded = 0")
		if err != nil {
			return nil, err
		}
		defer quarantineStmt.Close()
	}

	newlyQuarantined, err := bumpAndQuarantineRows(ctx, ids, bumpStmt, quarantineStmt, quarantineThreshold)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return newlyQuarantined, nil
}

// bumpAndQuarantineRows is the inner loop extracted from RecordClientError to keep cognitive complexity under Sonar's S3776
// budget. For each id, bumps the per-row counter; when quarantineStmt is non-nil, applies the quarantine UPDATE and collects
// ids that flipped uploaded=0->1 on THIS call so the caller can audit them.
func bumpAndQuarantineRows(ctx context.Context, ids []int64, bumpStmt, quarantineStmt *sql.Stmt, threshold int) ([]int64, error) {
	var newlyQuarantined []int64
	for _, id := range ids {
		if _, err := bumpStmt.ExecContext(ctx, id); err != nil {
			return nil, err
		}
		if quarantineStmt == nil {
			continue
		}
		res, err := quarantineStmt.ExecContext(ctx, id, threshold)
		if err != nil {
			return nil, err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if affected > 0 {
			newlyQuarantined = append(newlyQuarantined, id)
		}
	}
	return newlyQuarantined, nil
}

// SetMetrics installs the OTel hook. Safe to call after Open; nil clears.
func (q *Queue) SetMetrics(m MetricsRecorder) { q.metrics = m }

// Close closes the underlying database.
func (q *Queue) Close() error {
	return q.db.Close()
}

// Enqueue inserts an event into the queue. When MaxBytes is set, it also enforces the cap by trimming oldest rows before insert.
// Trimming is best-effort: a transient error from the trim step doesn't block the insert (we'd rather accept an over-cap insert than
// drop the event entirely).
func (q *Queue) Enqueue(ctx context.Context, eventJSON []byte) error {
	if q.maxBytes > 0 {
		if err := q.enforceCap(ctx); err != nil {
			// Log and continue — the insert itself might still succeed and the queue
			// will self-heal on the next Enqueue.
			q.logger.WarnContext(ctx, "queue cap enforcement failed", "err", err)
		}
	}
	_, err := q.db.ExecContext(ctx,
		"INSERT INTO events (event_json, created_at) VALUES (?, ?)",
		string(eventJSON), time.Now().UnixNano(),
	)
	return err
}

// dbSizeBytes returns the logical SQLite size as used-pages * page_size.
//
// We deliberately subtract freelist_count from page_count rather than returning
// the allocated file size: SQLite (without auto_vacuum) keeps deleted pages on
// a freelist for reuse, so `page_count * page_size` stays pinned at the high-
// water mark even after a DELETE. If enforceCap keyed off that value it would
// keep triggering lossy drops forever once the file ever grew past the cap,
// even though the freelist can absorb every subsequent insert without growth.
//
// We still avoid os.Stat: (a) the WAL file is tracked separately via
// `journal_size_limit`, and (b) stat can lag while WAL is flushing, producing
// spurious cap trips.
func (q *Queue) dbSizeBytes(ctx context.Context) (int64, error) {
	var pageCount, freelistCount, pageSize int64
	if err := q.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("page_count: %w", err)
	}
	if err := q.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freelistCount); err != nil {
		return 0, fmt.Errorf("freelist_count: %w", err)
	}
	if err := q.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("page_size: %w", err)
	}
	return max(pageCount-freelistCount, 0) * pageSize, nil
}

// trimBatch is the DELETE cap per iteration. Keeps the transaction bounded so we don't hold the single writer lock for an unreasonable
// stretch under sustained enqueue pressure.
const trimBatch = 500

// enforceCap drops rows until the DB is under maxBytes or there is nothing left to drop. Uploaded rows go first (lossless); if still
// over, non-uploaded rows go next with a warn log. Returns nil even when nothing was dropped — the cap was not exceeded in that case.
func (q *Queue) enforceCap(ctx context.Context) error {
	size, err := q.dbSizeBytes(ctx)
	if err != nil {
		return err
	}
	if size <= q.maxBytes {
		return nil
	}

	// Drop uploaded rows first (lossless), then non-uploaded rows if still over cap.
	if _, _, err = q.dropUntilUnderCap(ctx, q.deleteOldestUploaded, false); err != nil {
		return err
	}
	lossyDropped, size, err := q.dropUntilUnderCap(ctx, q.deleteOldestPending, true)
	if err != nil {
		return err
	}

	// Emit ONE warn per enforceCap call (not one per batch) so a sustained overflow
	// doesn't spam logs.
	if lossyDropped > 0 {
		q.logger.WarnContext(ctx, "queue cap reached: dropped non-uploaded events",
			"dropped", lossyDropped, "db_bytes", size, "cap_bytes", q.maxBytes,
		)
	}
	return nil
}

// dropUntilUnderCap calls deleter in a loop until the DB is under cap or deleter returns 0 rows. Returns total rows dropped and the
// final size. The lossy flag is passed through to the metrics hook unchanged.
func (q *Queue) dropUntilUnderCap(
	ctx context.Context,
	deleter func(context.Context, int) (int64, error),
	lossy bool,
) (int64, int64, error) {
	var dropped int64
	for {
		size, err := q.dbSizeBytes(ctx)
		if err != nil {
			return dropped, 0, err
		}
		if size <= q.maxBytes {
			return dropped, size, nil
		}
		n, err := deleter(ctx, trimBatch)
		if err != nil {
			return dropped, size, err
		}
		if n == 0 {
			return dropped, size, nil
		}
		dropped += n
		if q.metrics != nil {
			q.metrics.QueueDropped(ctx, n, lossy)
		}
	}
}

// deleteOldestUploaded removes up to batch already-uploaded rows, oldest first. Split into two fixed-SQL helpers (rather than
// one parameterised by a WHERE string) so the queries are static — gosec flags string-concat SQL even when every component is a
// compile-time literal, and "uploaded = 1" vs "uploaded = 0" is the only variation.
func (q *Queue) deleteOldestUploaded(ctx context.Context, batch int) (int64, error) {
	res, err := q.db.ExecContext(ctx, `
		DELETE FROM events
		WHERE id IN (
			SELECT id FROM events WHERE uploaded = 1 ORDER BY id LIMIT ?
		)
	`, batch)
	if err != nil {
		return 0, fmt.Errorf("delete oldest uploaded: %w", err)
	}
	return res.RowsAffected()
}

// deleteOldestPending removes up to batch not-yet-uploaded rows, oldest first. Lossy drop path: caller only invokes when the
// uploaded-first phase could not free enough space.
func (q *Queue) deleteOldestPending(ctx context.Context, batch int) (int64, error) {
	res, err := q.db.ExecContext(ctx, `
		DELETE FROM events
		WHERE id IN (
			SELECT id FROM events WHERE uploaded = 0 ORDER BY id LIMIT ?
		)
	`, batch)
	if err != nil {
		return 0, fmt.Errorf("delete oldest pending: %w", err)
	}
	return res.RowsAffected()
}

// DequeueBatch reads up to limit events that have not been uploaded, ordered by id.
func (q *Queue) DequeueBatch(ctx context.Context, limit int) ([]QueuedEvent, error) {
	rows, err := q.db.QueryContext(ctx,
		"SELECT id, event_json, created_at FROM events WHERE uploaded = 0 ORDER BY id LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []QueuedEvent
	for rows.Next() {
		var e QueuedEvent
		var createdNs int64
		if err := rows.Scan(&e.ID, &e.EventJSON, &createdNs); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(0, createdNs)
		events = append(events, e)
	}
	return events, rows.Err()
}

// MarkUploaded marks the given event IDs as uploaded.
func (q *Queue) MarkUploaded(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // Rollback after commit is a no-op.

	stmt, err := tx.PrepareContext(ctx, "UPDATE events SET uploaded = 1 WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Prune deletes uploaded events older than the given duration.
func (q *Queue) Prune(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UnixNano()
	result, err := q.db.ExecContext(ctx,
		"DELETE FROM events WHERE uploaded = 1 AND created_at < ?",
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Depth returns the number of events that have not been uploaded.
func (q *Queue) Depth(ctx context.Context) (int64, error) {
	var count int64
	err := q.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE uploaded = 0").Scan(&count)
	return count, err
}

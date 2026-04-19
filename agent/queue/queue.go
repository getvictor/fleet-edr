// Package queue provides a durable SQLite WAL-based event queue for the EDR agent.
//
// Phase 4: the queue enforces a byte-size cap (EDR_AGENT_QUEUE_MAX_BYTES). When an
// Enqueue would push the main DB file past the cap, the queue drops oldest rows to
// stay bounded. Uploaded rows are dropped first (lossless — they've already reached
// the server); if the cap is still exceeded, non-uploaded rows are dropped lossy and
// a warn log is emitted so the operator sees the backpressure. The default is
// "unbounded" (MaxBytes=0) so pre-Phase-4 behaviour is preserved unless the operator
// opts in.
package queue

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

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

// DroppedMetrics is the optional OTel hook. Nil is fine.
type DroppedMetrics interface {
	// QueueDropped is invoked when trim() removed rows. `lossy=true` means non-uploaded
	// rows were dropped (events lost forever); operators care about this count.
	QueueDropped(ctx context.Context, n int64, lossy bool)
}

// Queue is a durable event queue backed by SQLite in WAL mode.
type Queue struct {
	db       *sql.DB
	maxBytes int64
	logger   *slog.Logger
	metrics  DroppedMetrics
}

// Open creates or opens a SQLite queue at the given path. opts may be the zero
// value for unbounded behaviour.
func Open(ctx context.Context, dbPath string, opts Options) (*Queue, error) {
	// Set busy_timeout + journal_size_limit via DSN so they apply to every connection
	// in the pool. journal_size_limit=32MB keeps the WAL file itself from growing
	// without bound and silently busting the main-file cap.
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

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Queue{db: db, maxBytes: opts.MaxBytes, logger: logger}, nil
}

// SetMetrics installs the OTel hook. Safe to call after Open; nil clears.
func (q *Queue) SetMetrics(m DroppedMetrics) { q.metrics = m }

// Close closes the underlying database.
func (q *Queue) Close() error {
	return q.db.Close()
}

// Enqueue inserts an event into the queue. When MaxBytes is set, it also enforces
// the cap by trimming oldest rows before insert. Trimming is best-effort: a
// transient error from the trim step doesn't block the insert (we'd rather accept
// an over-cap insert than drop the event entirely).
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

// dbSizeBytes returns the main SQLite file's on-disk size. We multiply page_count by
// page_size rather than os.Stat'ing the file path so the metric matches what SQLite
// itself considers allocated (stat can lag while WAL is flushing).
func (q *Queue) dbSizeBytes(ctx context.Context) (int64, error) {
	var pageCount, pageSize int64
	if err := q.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("page_count: %w", err)
	}
	if err := q.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("page_size: %w", err)
	}
	return pageCount * pageSize, nil
}

// trimBatch is the DELETE cap per iteration. Keeps the transaction bounded so we
// don't hold the single writer lock for an unreasonable stretch under sustained
// enqueue pressure.
const trimBatch = 500

// enforceCap drops rows until the DB is under maxBytes or there is nothing left to
// drop. Uploaded rows go first (lossless); if still over, non-uploaded rows go next
// with a warn log. Returns nil even when nothing was dropped — the cap was not
// exceeded in that case.
func (q *Queue) enforceCap(ctx context.Context) error {
	size, err := q.dbSizeBytes(ctx)
	if err != nil {
		return err
	}
	if size <= q.maxBytes {
		return nil
	}

	// Drop uploaded rows first. Repeat until either we're under the cap or there are
	// no more uploaded rows to delete.
	for size > q.maxBytes {
		n, err := q.deleteOldestUploaded(ctx, trimBatch)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		if q.metrics != nil {
			q.metrics.QueueDropped(ctx, n, false)
		}
		size, err = q.dbSizeBytes(ctx)
		if err != nil {
			return err
		}
	}

	// Still over cap? Lossy phase: drop non-uploaded rows. Emit ONE warn per
	// enforceCap call (not one per batch) so a sustained overflow doesn't spam logs.
	var lossyDropped int64
	for size > q.maxBytes {
		n, err := q.deleteOldestPending(ctx, trimBatch)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		lossyDropped += n
		if q.metrics != nil {
			q.metrics.QueueDropped(ctx, n, true)
		}
		size, err = q.dbSizeBytes(ctx)
		if err != nil {
			return err
		}
	}
	if lossyDropped > 0 {
		q.logger.WarnContext(ctx, "queue cap reached: dropped non-uploaded events",
			"dropped", lossyDropped, "db_bytes", size, "cap_bytes", q.maxBytes,
		)
	}
	return nil
}

// deleteOldestUploaded removes up to batch already-uploaded rows, oldest first. Split
// into two fixed-SQL helpers (rather than one parameterised by a WHERE string) so the
// queries are static — gosec flags string-concat SQL even when every component is a
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

// deleteOldestPending removes up to batch not-yet-uploaded rows, oldest first. Lossy
// drop path: caller only invokes when the uploaded-first phase could not free enough
// space.
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

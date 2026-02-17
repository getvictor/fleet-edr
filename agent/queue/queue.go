// Package queue provides a durable SQLite WAL-based event queue for the EDR agent.
package queue

import (
	"database/sql"
	"fmt"
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

// Queue is a durable event queue backed by SQLite in WAL mode.
type Queue struct {
	db *sql.DB
}

// Open creates or opens a SQLite queue at the given path.
func Open(dbPath string) (*Queue, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Enable WAL mode for crash safety and concurrent reads.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	// Reasonable defaults for an embedded queue.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy_timeout: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &Queue{db: db}, nil
}

// Close closes the underlying database.
func (q *Queue) Close() error {
	return q.db.Close()
}

// Enqueue inserts an event into the queue.
func (q *Queue) Enqueue(eventJSON []byte) error {
	_, err := q.db.Exec(
		"INSERT INTO events (event_json, created_at) VALUES (?, ?)",
		string(eventJSON), time.Now().UnixNano(),
	)
	return err
}

// DequeueBatch reads up to limit events that have not been uploaded, ordered by id.
func (q *Queue) DequeueBatch(limit int) ([]QueuedEvent, error) {
	rows, err := q.db.Query(
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
func (q *Queue) MarkUploaded(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("UPDATE events SET uploaded = 1 WHERE id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.Exec(id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Prune deletes uploaded events older than the given duration.
func (q *Queue) Prune(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UnixNano()
	result, err := q.db.Exec(
		"DELETE FROM events WHERE uploaded = 1 AND created_at < ?",
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Depth returns the number of events that have not been uploaded.
func (q *Queue) Depth() (int64, error) {
	var count int64
	err := q.db.QueryRow("SELECT COUNT(*) FROM events WHERE uploaded = 0").Scan(&count)
	return count, err
}

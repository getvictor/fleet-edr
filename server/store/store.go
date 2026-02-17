// Package store provides PostgreSQL-backed event storage for the EDR ingestion server.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/lib/pq"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	event_id     TEXT PRIMARY KEY,
	host_id      TEXT NOT NULL,
	timestamp_ns BIGINT NOT NULL,
	event_type   TEXT NOT NULL,
	payload      JSONB NOT NULL,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ns);
`

// Event represents the canonical event envelope.
type Event struct {
	EventID     string          `json:"event_id"`
	HostID      string          `json:"host_id"`
	TimestampNs int64           `json:"timestamp_ns"`
	EventType   string          `json:"event_type"`
	Payload     json.RawMessage `json:"payload"`
}

// Store manages event persistence in PostgreSQL.
type Store struct {
	db *sql.DB
}

// New opens a connection to PostgreSQL and ensures the schema exists.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// InsertEvents upserts a batch of events. Duplicates (by event_id) are ignored.
func (s *Store) InsertEvents(events []Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO events (event_id, host_id, timestamp_ns, event_type, payload)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (event_id) DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		payloadBytes, err := json.Marshal(e.Payload)
		if err != nil {
			return fmt.Errorf("marshal payload for %s: %w", e.EventID, err)
		}
		if _, err := stmt.Exec(e.EventID, e.HostID, e.TimestampNs, e.EventType, payloadBytes); err != nil {
			return fmt.Errorf("insert %s: %w", e.EventID, err)
		}
	}

	return tx.Commit()
}

// CountEvents returns the total number of events.
func (s *Store) CountEvents() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

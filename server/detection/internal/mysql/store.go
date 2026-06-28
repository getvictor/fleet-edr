package mysql

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jmoiron/sqlx"

	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// Store is the persistence handle for the detection bounded context. Holds the shared *sqlx.DB pool that cmd/main opens once via
// server/bootstrap.OpenDB and shares across every context, plus the visibility EventArchive the detection read paths delegate event
// lookups to (ADR-0015): per-process network correlation and self-contained alert evidence both read the durable archive, not MySQL.
type Store struct {
	db      *sqlx.DB
	archive visibilityapi.EventArchive
	logger  *slog.Logger
}

// New returns a Store wrapping the provided db handle and event archive. Schema is applied separately via detection/bootstrap.ApplySchema;
// New just hands back the read/write surface. archive is required: post-cutover the detection store has no MySQL events table to read, so
// correlation and evidence reads delegate to it. Tests pass an in-memory archive (visibility/testkit.MemArchive). logger is used for the
// rare diagnostic paths the store owns (e.g. a poison row dropped by the batch-flush per-row fallback, issue #535); nil defaults to
// slog.Default().
//
// Closing the db handle is cmd/main's responsibility, not Store's.
func New(db *sqlx.DB, archive visibilityapi.EventArchive, logger *slog.Logger) (*Store, error) {
	if db == nil {
		return nil, errors.New("detection mysql.New: db handle must not be nil")
	}
	if archive == nil {
		return nil, errors.New("detection mysql.New: event archive must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{db: db, archive: archive, logger: logger}, nil
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

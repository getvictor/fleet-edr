// Package clickhouse is the ClickHouse implementation of the visibility context's EventArchive: the durable, append-mostly event lake
// (ADR-0015), the source of truth for per-process correlation and (in v0.5.0) hunting. It backs the `events` table.
//
// Payload is stored as raw JSON text with the hot fields materialized for filtering (pid today); the native ClickHouse JSON type and
// more typed columns are a v0.5.0 hunting optimization. Writes use the native batch protocol; reads use FINAL so at-least-once
// re-deliveries collapsed by ReplacingMergeTree never surface as duplicates.
package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/ClickHouse/clickhouse-go/v2" // registers the "clickhouse" database/sql driver
	"github.com/XSAM/otelsql"
	"github.com/jmoiron/sqlx"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"github.com/fleetdm/edr/server/httpserver"
	"github.com/fleetdm/edr/server/visibility/api"
)

// Open dials the ClickHouse event archive through the same otelsql wrapper MySQL uses (server/bootstrap.OpenDB), so every archive
// query and insert gets a span plus the connection-pool / db.sql.* RED metrics with no bespoke code (ADR-0006, OTel only). dsn is a
// clickhouse-go DSN, e.g. "clickhouse://default:@127.0.0.1:9000/edr". Closing the handle is the caller's responsibility.
func Open(ctx context.Context, dsn string) (*sqlx.DB, error) {
	sqldb, err := otelsql.Open("clickhouse", dsn, otelsql.WithAttributes(semconv.DBSystemNameClickHouse))
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	if _, err := otelsql.RegisterDBStatsMetrics(sqldb, otelsql.WithAttributes(semconv.DBSystemNameClickHouse)); err != nil {
		if cerr := sqldb.Close(); cerr != nil {
			return nil, fmt.Errorf("register clickhouse stats metrics: %w (close: %w)", err, cerr)
		}
		return nil, fmt.Errorf("register clickhouse stats metrics: %w", err)
	}
	db := sqlx.NewDb(sqldb, "clickhouse")
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping clickhouse: %w", err)
	}
	return db, nil
}

// Store is the ClickHouse-backed EventArchive. It holds the connection pool opened by Open; closing it is the caller's responsibility.
type Store struct {
	db *sqlx.DB
}

// Compile-time check that Store satisfies the published EventArchive contract.
var _ api.EventArchive = (*Store)(nil)

// New returns a Store wrapping db. Schema is applied separately via visibility/bootstrap.ApplySchema.
func New(db *sqlx.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("visibility clickhouse.New: db handle must not be nil")
	}
	return &Store{db: db}, nil
}

// Insert durably stores events in the archive using ClickHouse's native batch protocol (one prepared INSERT, a row per event, one
// committed block). Idempotent by event_id: ReplacingMergeTree(ingested_at_ns) collapses a re-inserted event to its latest version on
// merge, and reads use FINAL, so at-least-once delivery never surfaces a duplicate. Events are stored with the IngestedAtNs the caller
// already stamped; the archive does not re-stamp.
func (s *Store) Insert(ctx context.Context, events []api.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin clickhouse batch: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO events (event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload)")
	if err != nil {
		return fmt.Errorf("prepare clickhouse insert: %w", err)
	}
	defer stmt.Close() //nolint:errcheck
	for i := range events {
		payload := events[i].Payload
		if len(payload) == 0 {
			payload = []byte("null") // events.payload is non-empty JSON text; an empty envelope stores as the JSON null literal
		}
		if _, err := stmt.ExecContext(ctx, events[i].EventID, events[i].HostID, events[i].TimestampNs,
			events[i].IngestedAtNs, events[i].EventType, string(payload)); err != nil {
			return fmt.Errorf("append clickhouse row %s: %w", events[i].EventID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit clickhouse batch: %w", err)
	}
	return nil
}

// NetworkEventsForProcess returns the network_connect and dns_query events attributed to (hostID, pid) within tr, ordered by
// timestamp. FINAL collapses ReplacingMergeTree duplicates so a re-delivered event is not double-counted. The filter mirrors the
// detection correlation read it replaces: server-stamped ingested_at_ns bounds the window (clock-drift tolerant) and pid is the
// materialized column extracted from the payload.
func (s *Store) NetworkEventsForProcess(ctx context.Context, hostID string, pid int, tr httpserver.TimeRange) ([]api.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, host_id, timestamp_ns, ingested_at_ns, event_type, payload
		FROM events FINAL
		WHERE host_id = ? AND event_type IN ('network_connect', 'dns_query') AND pid = ?
		  AND ingested_at_ns >= ? AND ingested_at_ns <= ?
		ORDER BY timestamp_ns`, hostID, pid, tr.FromNs, tr.ToNs)
	if err != nil {
		return nil, fmt.Errorf("clickhouse network events for process: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var events []api.Event
	for rows.Next() {
		// Scan payload into a string: the ClickHouse driver returns a String column as a Go string, which database/sql cannot assign
		// straight into json.RawMessage. Convert explicitly.
		var e api.Event
		var payload string
		if err := rows.Scan(&e.EventID, &e.HostID, &e.TimestampNs, &e.IngestedAtNs, &e.EventType, &payload); err != nil {
			return nil, fmt.Errorf("scan clickhouse event: %w", err)
		}
		e.Payload = json.RawMessage(payload)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clickhouse network events for process: %w", err)
	}
	return events, nil
}

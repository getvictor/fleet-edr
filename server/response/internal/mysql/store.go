package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/response/api"
)

// Store owns the commands table. All public methods take the row's
// fields directly (rather than a pre-constructed struct) so callers
// don't need to import a row type.
type Store struct {
	db *sqlx.DB
}

// NewStore returns a Store over an existing sqlx.DB handle.
func NewStore(db *sqlx.DB) *Store {
	if db == nil {
		panic("response mysql.NewStore: db must not be nil")
	}
	return &Store{db: db}
}

// commandRow mirrors a row in the commands table; held internal to
// the package so api.Command stays the public contract. Result uses
// nullRawJSON because the column is JSON NULL until the agent
// completes / fails the command.
type commandRow struct {
	ID          int64           `db:"id"`
	HostID      string          `db:"host_id"`
	CommandType string          `db:"command_type"`
	Payload     json.RawMessage `db:"payload"`
	Status      string          `db:"status"`
	CreatedAt   time.Time       `db:"created_at"`
	AckedAt     *time.Time      `db:"acked_at"`
	CompletedAt *time.Time      `db:"completed_at"`
	Result      nullRawJSON     `db:"result"`
}

// toAPI converts the row into the public api.Command. Result is
// emitted as nil when the column is NULL; the api type uses
// json.RawMessage with omitempty so the JSON wire shape preserves
// the previous "result missing means in-flight" semantics.
func (r commandRow) toAPI() api.Command {
	cmd := api.Command{
		ID:          r.ID,
		HostID:      r.HostID,
		CommandType: r.CommandType,
		Payload:     r.Payload,
		Status:      api.Status(r.Status),
		CreatedAt:   r.CreatedAt,
		AckedAt:     r.AckedAt,
		CompletedAt: r.CompletedAt,
	}
	if len(r.Result) > 0 {
		cmd.Result = json.RawMessage(r.Result)
	}
	return cmd
}

// Insert appends a command row. Returns the new id.
func (s *Store) Insert(ctx context.Context, hostID, commandType string, payload []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO commands (host_id, command_type, payload)
		VALUES (?, ?, ?)`,
		hostID, commandType, payload,
	)
	if err != nil {
		return 0, fmt.Errorf("insert command: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert command last id: %w", err)
	}
	return id, nil
}

// ListForHost returns commands for a host, optionally filtered by
// status (empty string returns every status). Order: created_at
// DESC (newest first), matching the previous store.ListCommands
// behaviour.
func (s *Store) ListForHost(ctx context.Context, hostID, status string) ([]api.Command, error) {
	query := `SELECT id, host_id, command_type, payload, status, created_at, acked_at, completed_at, result
		FROM commands WHERE host_id = ?`
	args := []any{hostID}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC"

	var rows []commandRow
	if err := s.db.SelectContext(ctx, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("list commands: %w", err)
	}
	out := make([]api.Command, len(rows))
	for i := range rows {
		out[i] = rows[i].toAPI()
	}
	return out, nil
}

// Get returns a single command by id. Returns api.ErrCommandNotFound
// when the row doesn't exist.
func (s *Store) Get(ctx context.Context, id int64) (api.Command, error) {
	var r commandRow
	err := s.db.GetContext(ctx, &r,
		`SELECT id, host_id, command_type, payload, status, created_at, acked_at, completed_at, result
		 FROM commands WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Command{}, api.ErrCommandNotFound
	}
	if err != nil {
		return api.Command{}, fmt.Errorf("get command %d: %w", id, err)
	}
	return r.toAPI(), nil
}

// UpdateStatus transitions a command's status atomically. Both the
// host_id AND the expected current status are part of the WHERE
// clause, so a concurrent request that already advanced the row
// produces zero rows affected here -- the lifecycle matrix is
// enforced at the DB level, not just at the service layer.
//
// Returns:
//   - nil on a successful transition.
//   - api.ErrCommandNotFound when (id, hostID) doesn't match a row
//     (unknown id or wrong host -- collapsed so a malicious agent
//     can't probe other hosts' command_ids).
//   - api.ErrInvalidStatusTransition when (id, hostID) match but the
//     current status no longer equals expectedFrom (race: a
//     concurrent agent already advanced the row).
func (s *Store) UpdateStatus(ctx context.Context, id int64, hostID string, expectedFrom, status api.Status, result json.RawMessage) error {
	var (
		res sql.Result
		err error
	)
	switch status { //nolint:exhaustive // pending is intentionally rejected as a target -- caller can only move FORWARD.
	case api.StatusAcked:
		res, err = s.db.ExecContext(ctx,
			"UPDATE commands SET status = ?, acked_at = NOW(6) WHERE id = ? AND host_id = ? AND status = ?",
			string(status), id, hostID, string(expectedFrom))
	case api.StatusCompleted, api.StatusFailed:
		res, err = s.db.ExecContext(ctx,
			"UPDATE commands SET status = ?, completed_at = NOW(6), result = ? WHERE id = ? AND host_id = ? AND status = ?",
			string(status), result, id, hostID, string(expectedFrom))
	default:
		return fmt.Errorf("%w: status %q is not a valid update target", api.ErrInvalidStatusTransition, status)
	}
	if err != nil {
		return fmt.Errorf("update command status %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Disambiguate "wrong (id, host)" from "lost the race": one
		// SELECT settles it. The cost is paid only on the failure
		// path; the happy path stays a single UPDATE.
		var owner string
		err := s.db.GetContext(ctx, &owner,
			"SELECT host_id FROM commands WHERE id = ?", id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != hostID) {
			return api.ErrCommandNotFound
		}
		if err != nil {
			return fmt.Errorf("disambiguate update miss for command %d: %w", id, err)
		}
		// Same (id, host_id) but UPDATE matched 0 rows: status
		// changed under us. Caller's pre-read saw expectedFrom; a
		// concurrent caller advanced the row.
		return api.ErrInvalidStatusTransition
	}
	return nil
}

// CountPending returns the number of rows with status='pending'.
// Used by the OTel metrics gauge.
func (s *Store) CountPending(ctx context.Context) (int, error) {
	var n int
	if err := s.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM commands WHERE status = 'pending'`); err != nil {
		return 0, fmt.Errorf("count pending commands: %w", err)
	}
	return n, nil
}

// nullRawJSON is a json.RawMessage that correctly scans NULL from
// MySQL JSON columns. Mirrors store.NullRawJSON; defined locally so
// response/internal/mysql doesn't drag a cross-context import for
// one type. Phase 5 may move both to a shared sqlx-helper package.
type nullRawJSON json.RawMessage

func (n *nullRawJSON) Scan(value any) error {
	if value == nil {
		*n = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("nullRawJSON.Scan: unsupported type %T", value)
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	*n = nullRawJSON(cp)
	return nil
}

func (n nullRawJSON) Value() (driver.Value, error) {
	// Treat both an empty payload AND the JSON literal "null" as SQL
	// NULL -- mirrors store.NullRawJSON's intent. If we let "null"
	// land in the column, toAPI's len-check would still emit
	// `result: null` on the wire instead of omitting the field, and
	// callers that round-trip via JSON would see drift between
	// requests. Keep the column NULL so the wire shape stays clean.
	if len(n) == 0 || string(n) == "null" {
		return nil, nil
	}
	return []byte(n), nil
}

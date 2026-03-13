package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Command represents a server-to-agent command (e.g., kill_process).
type Command struct {
	ID          int64           `db:"id" json:"id"`
	HostID      string          `db:"host_id" json:"host_id"`
	CommandType string          `db:"command_type" json:"command_type"`
	Payload     json.RawMessage `db:"payload" json:"payload"`
	Status      string          `db:"status" json:"status"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	AckedAt     *time.Time      `db:"acked_at" json:"acked_at,omitempty"`
	CompletedAt *time.Time      `db:"completed_at" json:"completed_at,omitempty"`
	Result      NullRawJSON     `db:"result" json:"result,omitempty"`
}

// InsertCommand creates a new command for the given host.
func (s *Store) InsertCommand(ctx context.Context, c Command) (int64, error) {
	payloadBytes, err := json.Marshal(c.Payload)
	if err != nil {
		return 0, fmt.Errorf("marshal command payload: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO commands (host_id, command_type, payload)
		VALUES (?, ?, ?)`,
		c.HostID, c.CommandType, payloadBytes,
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

// ListCommands returns commands for a host, optionally filtered by status.
func (s *Store) ListCommands(ctx context.Context, hostID, status string) ([]Command, error) {
	query := `SELECT id, host_id, command_type, payload, status, created_at, acked_at, completed_at, result
		FROM commands WHERE host_id = ?`
	args := []any{hostID}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	query += " ORDER BY created_at DESC"

	var commands []Command
	if err := s.db.SelectContext(ctx, &commands, query, args...); err != nil {
		return nil, fmt.Errorf("list commands: %w", err)
	}
	return commands, nil
}

// GetCommand returns a single command by ID, or nil if not found.
func (s *Store) GetCommand(ctx context.Context, id int64) (*Command, error) {
	var c Command
	err := s.db.GetContext(ctx, &c,
		`SELECT id, host_id, command_type, payload, status, created_at, acked_at, completed_at, result
		 FROM commands WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get command %d: %w", id, err)
	}
	return &c, nil
}

// UpdateCommandStatus transitions a command to a new status with optional result data.
// Automatically sets acked_at or completed_at timestamps based on the new status.
func (s *Store) UpdateCommandStatus(ctx context.Context, id int64, status string, result json.RawMessage) error {
	var res sql.Result
	var err error

	switch status {
	case "acked":
		res, err = s.db.ExecContext(ctx, "UPDATE commands SET status = ?, acked_at = NOW() WHERE id = ?", status, id)
	case "completed", "failed":
		res, err = s.db.ExecContext(ctx,
			"UPDATE commands SET status = ?, completed_at = NOW(), result = ? WHERE id = ?", status, result, id)
	default:
		res, err = s.db.ExecContext(ctx, "UPDATE commands SET status = ? WHERE id = ?", status, id)
	}

	if err != nil {
		return fmt.Errorf("update command status %d: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

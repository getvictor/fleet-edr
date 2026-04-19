package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

// Alert represents a detection alert linked to a process and triggering events.
type Alert struct {
	ID          int64      `db:"id" json:"id"`
	HostID      string     `db:"host_id" json:"host_id"`
	RuleID      string     `db:"rule_id" json:"rule_id"`
	Severity    string     `db:"severity" json:"severity"`
	Title       string     `db:"title" json:"title"`
	Description string     `db:"description" json:"description"`
	ProcessID   int64      `db:"process_id" json:"process_id"`
	Status      string     `db:"status" json:"status"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at" json:"updated_at"`
	ResolvedAt  *time.Time `db:"resolved_at" json:"resolved_at,omitempty"`
}

// AlertFilter controls which alerts are returned by ListAlerts.
type AlertFilter struct {
	HostID    string
	Status    string
	Severity  string
	ProcessID int64
	Limit     int
}

// InsertAlert creates an alert and links it to the given event IDs.
// If a duplicate alert exists (same host_id, rule_id, process_id), the insert is skipped and the existing alert ID is
// returned. Returns the alert ID and whether it was newly created.
func (s *Store) InsertAlert(ctx context.Context, a Alert, eventIDs []string) (int64, bool, error) {
	// Deduplicate event IDs to prevent primary key violations.
	eventIDs = deduplicateStrings(eventIDs)

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin tx for insert alert: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (host_id, rule_id, severity, title, description, process_id)
		VALUES (?, ?, ?, ?, ?, ?)`,
		a.HostID, a.RuleID, a.Severity, a.Title, a.Description, a.ProcessID,
	)
	if err != nil {
		if isDuplicateKeyErr(err) {
			return s.attachEventsToExistingAlert(ctx, tx, a, eventIDs)
		}
		return 0, false, fmt.Errorf("insert alert: %w", err)
	}

	alertID, err := res.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("insert alert last id: %w", err)
	}

	for _, eid := range eventIDs {
		if _, err := tx.ExecContext(ctx, "INSERT INTO alert_events (alert_id, event_id) VALUES (?, ?)", alertID, eid); err != nil {
			return 0, false, fmt.Errorf("insert alert_event (%d, %s): %w", alertID, eid, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit insert alert: %w", err)
	}
	return alertID, true, nil
}

// isDuplicateKeyErr matches MySQL error 1062 (duplicate primary/unique key).
func isDuplicateKeyErr(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}

// attachEventsToExistingAlert handles the "alert already exists for this
// (host_id, rule_id, process_id)" branch. Extracted from InsertAlert to keep the main
// path under the cognitive complexity limit.
func (s *Store) attachEventsToExistingAlert(ctx context.Context, tx *sqlx.Tx, a Alert, eventIDs []string) (int64, bool, error) {
	var existingID int64
	if err := tx.GetContext(ctx, &existingID,
		"SELECT id FROM alerts WHERE host_id = ? AND rule_id = ? AND process_id = ?",
		a.HostID, a.RuleID, a.ProcessID,
	); err != nil {
		return 0, false, fmt.Errorf("lookup duplicate alert: %w", err)
	}
	for _, eid := range eventIDs {
		if _, err := tx.ExecContext(ctx,
			"INSERT IGNORE INTO alert_events (alert_id, event_id) VALUES (?, ?)", existingID, eid,
		); err != nil {
			return 0, false, fmt.Errorf("link event to existing alert (%d, %s): %w", existingID, eid, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit duplicate alert lookup: %w", err)
	}
	return existingID, false, nil
}

// ListAlerts returns alerts matching the given filter, ordered by created_at DESC.
func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	query := "SELECT id, host_id, rule_id, severity, title, description, process_id, status, created_at, updated_at, resolved_at FROM alerts WHERE 1=1"
	var args []any

	if f.HostID != "" {
		query += " AND host_id = ?"
		args = append(args, f.HostID)
	}
	if f.Status != "" {
		query += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.ProcessID != 0 {
		query += " AND process_id = ?"
		args = append(args, f.ProcessID)
	}

	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, f.Limit)

	var alerts []Alert
	if err := s.db.SelectContext(ctx, &alerts, query, args...); err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	return alerts, nil
}

// GetAlert returns a single alert by ID, or nil if not found.
func (s *Store) GetAlert(ctx context.Context, id int64) (*Alert, error) {
	var a Alert
	err := s.db.GetContext(ctx, &a,
		`SELECT id, host_id, rule_id, severity, title, description, process_id, status, created_at, updated_at, resolved_at
		 FROM alerts WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get alert %d: %w", id, err)
	}
	return &a, nil
}

// GetAlertEventIDs returns the event IDs linked to an alert.
func (s *Store) GetAlertEventIDs(ctx context.Context, alertID int64) ([]string, error) {
	var eventIDs []string
	err := s.db.SelectContext(ctx, &eventIDs, "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id", alertID)
	if err != nil {
		return nil, fmt.Errorf("get alert event ids %d: %w", alertID, err)
	}
	return eventIDs, nil
}

// UpdateAlertStatus changes the status of an alert. If the new status is "resolved", resolved_at is set
// (only on the first resolve — subsequent resolves preserve the original timestamp). userID is the id
// of the authenticated user making the change (from Phase 3 session auth); pass 0 to leave updated_by
// untouched (e.g. an internal backfill). userID is written to alerts.updated_by so SOC forensics can
// reconstruct who resolved what.
func (s *Store) UpdateAlertStatus(ctx context.Context, id int64, status string, userID int64) error {
	// Check existence first so we can distinguish "not found" from "no change" (RowsAffected=0).
	var exists int64
	if err := s.db.GetContext(ctx, &exists, "SELECT id FROM alerts WHERE id = ?", id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sql.ErrNoRows
		}
		return fmt.Errorf("check alert existence %d: %w", id, err)
	}

	// When userID is zero we preserve the existing updated_by value via IF(?=0, col, ?)
	// so internal backfills don't clobber the last real user. When non-zero we
	// overwrite; the last responder's identity is what forensics cares about.
	var err error
	if status == "resolved" {
		_, err = s.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = ?,
			    resolved_at = IFNULL(resolved_at, NOW(6)),
			    updated_by = IF(? = 0, updated_by, ?)
			WHERE id = ?
		`, status, userID, userID, id)
	} else {
		_, err = s.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = ?,
			    resolved_at = NULL,
			    updated_by = IF(? = 0, updated_by, ?)
			WHERE id = ?
		`, status, userID, userID, id)
	}
	if err != nil {
		return fmt.Errorf("update alert status %d: %w", id, err)
	}
	return nil
}

// GetAlertsByProcessID returns all alerts for a given process ID.
func (s *Store) GetAlertsByProcessID(ctx context.Context, processID int64) ([]Alert, error) {
	var alerts []Alert
	err := s.db.SelectContext(ctx, &alerts,
		`SELECT id, host_id, rule_id, severity, title, description, process_id, status, created_at, updated_at, resolved_at
		 FROM alerts WHERE process_id = ? ORDER BY created_at DESC`, processID)
	if err != nil {
		return nil, fmt.Errorf("get alerts by process id %d: %w", processID, err)
	}
	return alerts, nil
}

// CountAlerts returns the total number of alerts matching the filter (ignoring limit).
func (s *Store) CountAlerts(ctx context.Context, f AlertFilter) (int64, error) {
	query := "SELECT COUNT(*) FROM alerts WHERE 1=1"
	var args []any

	if f.HostID != "" {
		query += " AND host_id = ?"
		args = append(args, f.HostID)
	}
	if f.Status != "" {
		query += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.ProcessID != 0 {
		query += " AND process_id = ?"
		args = append(args, f.ProcessID)
	}

	var count int64
	if err := s.db.GetContext(ctx, &count, query, args...); err != nil {
		return 0, fmt.Errorf("count alerts: %w", err)
	}
	return count, nil
}

func deduplicateStrings(ss []string) []string {
	if len(ss) <= 1 {
		return ss
	}
	seen := make(map[string]struct{}, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		result = append(result, s)
	}
	return result
}

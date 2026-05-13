package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/api"
)

// alertEventsBatchSize caps the number of (alert_id, event_id) rows
// per INSERT. Today's rules cap their output at ~10 events per
// finding, but a future noisy detection could link thousands. Keeping
// the batch bounded stops a single INSERT from breaching MySQL's
// max_allowed_packet on hosts where it's tuned low.
const alertEventsBatchSize = 500

// InsertAlert creates an alert and links it to the given event IDs.
// If a duplicate alert exists (same source, host_id, rule_id,
// process_id), the insert is skipped and the existing alert ID is
// returned. Returns the alert ID and whether it was newly created.
//
// Callers MUST set a.Source. The engine defaults blank to
// AlertSourceDetection before this method sees the alert so existing
// catalog rules keep working unchanged.
func (s *Store) InsertAlert(ctx context.Context, a api.Alert, eventIDs []string) (int64, bool, error) {
	eventIDs = deduplicateStrings(eventIDs)
	// Defense in depth: callers that forget to stamp Source land in
	// the catalog-rule bucket. The ENUM column would otherwise reject
	// an empty string with Error 1265 (Data truncated).
	if a.Source == "" {
		a.Source = api.AlertSourceDetection
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin tx for insert alert: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.ExecContext(ctx, `
		INSERT INTO alerts (host_id, rule_id, source, severity, title, description, process_id, techniques)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.HostID, a.RuleID, a.Source, a.Severity, a.Title, a.Description, a.ProcessID, a.Techniques,
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

	if err := bulkInsertAlertEvents(ctx, tx, alertID, eventIDs, false /* not dedup */); err != nil {
		return 0, false, err
	}

	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit insert alert: %w", err)
	}
	return alertID, true, nil
}

// bulkInsertAlertEvents links eventIDs to alertID with one (chunked)
// multi-row INSERT instead of N round-trips. dedup=true switches to
// INSERT IGNORE so re-linking an existing (alert_id, event_id) PK
// doesn't blow up.
func bulkInsertAlertEvents(ctx context.Context, tx *sqlx.Tx, alertID int64, eventIDs []string, dedup bool) error {
	if len(eventIDs) == 0 {
		return nil
	}
	verb := "INSERT INTO"
	if dedup {
		verb = "INSERT IGNORE INTO"
	}
	for start := 0; start < len(eventIDs); start += alertEventsBatchSize {
		end := min(start+alertEventsBatchSize, len(eventIDs))
		chunk := eventIDs[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)*2)
		for i, eid := range chunk {
			placeholders[i] = "(?, ?)"
			args = append(args, alertID, eid)
		}
		stmt := verb + " alert_events (alert_id, event_id) VALUES " + strings.Join(placeholders, ", ")
		if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
			return fmt.Errorf("link alert_events alert=%d count=%d: %w", alertID, len(chunk), err)
		}
	}
	return nil
}

// mysqlErrDuplicateKey is MySQL error 1062 (duplicate primary/unique key).
const mysqlErrDuplicateKey = 1062

// isDuplicateKeyErr matches MySQL error 1062 (duplicate primary/unique key).
func isDuplicateKeyErr(err error) bool {
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) {
		return false
	}
	return mysqlErr.Number == mysqlErrDuplicateKey
}

// attachEventsToExistingAlert handles the dedup branch when
// (source, host_id, rule_id, process_id) already has an alert row.
// Extracted from InsertAlert to keep the main path under the
// cognitive complexity limit.
func (s *Store) attachEventsToExistingAlert(ctx context.Context, tx *sqlx.Tx, a api.Alert, eventIDs []string) (int64, bool, error) {
	var existingID int64
	if err := tx.GetContext(ctx, &existingID,
		"SELECT id FROM alerts WHERE source = ? AND host_id = ? AND rule_id = ? AND process_id = ?",
		a.Source, a.HostID, a.RuleID, a.ProcessID,
	); err != nil {
		return 0, false, fmt.Errorf("lookup duplicate alert: %w", err)
	}
	if err := bulkInsertAlertEvents(ctx, tx, existingID, eventIDs, true /* dedup */); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit duplicate alert lookup: %w", err)
	}
	return existingID, false, nil
}

// ListAlerts returns alerts matching the given filter, ordered by
// created_at DESC.
func (s *Store) ListAlerts(ctx context.Context, f api.AlertFilter) ([]api.Alert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, host_id, rule_id, source, severity, title, description, process_id,
	          techniques, status, created_at, updated_at, resolved_at, updated_by
	          FROM alerts WHERE 1=1`
	var args []any

	if f.HostID != "" {
		query += " AND host_id = ?"
		args = append(args, f.HostID)
	}
	if f.Status != "" {
		query += " AND status = ?"
		args = append(args, string(f.Status))
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Source != "" {
		query += " AND source = ?"
		args = append(args, f.Source)
	}
	if f.ProcessID != 0 {
		query += " AND process_id = ?"
		args = append(args, f.ProcessID)
	}

	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	var alerts []api.Alert
	if err := s.db.SelectContext(ctx, &alerts, query, args...); err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	return alerts, nil
}

// GetAlert returns a single alert by ID. Returns api.ErrAlertNotFound
// when the row doesn't exist.
func (s *Store) GetAlert(ctx context.Context, id int64) (api.Alert, error) {
	var a api.Alert
	err := s.db.GetContext(ctx, &a,
		`SELECT id, host_id, rule_id, source, severity, title, description, process_id,
		        techniques, status, created_at, updated_at, resolved_at, updated_by
		 FROM alerts WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Alert{}, api.ErrAlertNotFound
	}
	if err != nil {
		return api.Alert{}, fmt.Errorf("get alert %d: %w", id, err)
	}
	return a, nil
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

// UpdateAlertStatus changes the status of an alert. If the new
// status is "resolved", resolved_at is set on first transition only.
// userID is written to alerts.updated_by; pass 0 to leave it
// untouched (e.g. an internal backfill).
//
// Returns api.ErrAlertNotFound when the row doesn't exist.
//
// This persistence-level method does NOT enforce the
// AlertStatusOpen -> AlertStatusAcknowledged -> AlertStatusResolved
// lifecycle: any non-zero status string is written. The operator
// service (commit 10) layers transition validation on top and is
// where api.ErrInvalidAlertTransition is produced. The updated_by
// user is also NOT validated here; the service uses the UserExists
// closure to enforce that before calling.
func (s *Store) UpdateAlertStatus(ctx context.Context, id int64, status api.AlertStatus, userID int64) error {
	var exists int64
	if err := s.db.GetContext(ctx, &exists, "SELECT id FROM alerts WHERE id = ?", id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return api.ErrAlertNotFound
		}
		return fmt.Errorf("check alert existence %d: %w", id, err)
	}

	var err error
	if status == api.AlertStatusResolved {
		_, err = s.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = ?,
			    resolved_at = IFNULL(resolved_at, NOW(6)),
			    updated_by = IF(? = 0, updated_by, ?)
			WHERE id = ?
		`, string(status), userID, userID, id)
	} else {
		_, err = s.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = ?,
			    resolved_at = NULL,
			    updated_by = IF(? = 0, updated_by, ?)
			WHERE id = ?
		`, string(status), userID, userID, id)
	}
	if err != nil {
		return fmt.Errorf("update alert status %d: %w", id, err)
	}
	return nil
}

// CountAlerts returns the total number of alerts matching the
// filter (ignoring limit). Filter set MUST stay in lockstep with
// ListAlerts so pagination metadata describes the same result set.
func (s *Store) CountAlerts(ctx context.Context, f api.AlertFilter) (int64, error) {
	query := "SELECT COUNT(*) FROM alerts WHERE 1=1"
	var args []any

	if f.HostID != "" {
		query += " AND host_id = ?"
		args = append(args, f.HostID)
	}
	if f.Status != "" {
		query += " AND status = ?"
		args = append(args, string(f.Status))
	}
	if f.Severity != "" {
		query += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Source != "" {
		query += " AND source = ?"
		args = append(args, f.Source)
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

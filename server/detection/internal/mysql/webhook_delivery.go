package mysql

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	detapi "github.com/fleetdm/edr/server/detection/api"
)

// maxLastErrorLen bounds the last_error text stored per delivery (the column is VARCHAR(1024)); a longer transport error is truncated.
const maxLastErrorLen = 1024

// ClaimDueWebhookDeliveries leases up to limit pending deliveries whose next_attempt_at has passed, for this worker to send. It runs
// one short transaction: it selects due rows FOR UPDATE OF the delivery table with SKIP LOCKED (so replicas claim disjoint sets and a
// row another replica is sending is skipped, not blocked), then pushes their next_attempt_at out by lease and bumps attempt. The lease
// is the crash-safety window: if this worker dies mid-send the row becomes due again after lease and another replica retries it
// (at-least-once; receivers dedup on the delivery id). The HTTP POST happens OUTSIDE this transaction so a slow receiver never holds
// row locks. The returned Attempt is the post-increment value for this send.
func (s *Store) ClaimDueWebhookDeliveries(ctx context.Context, limit int, lease time.Duration) ([]detapi.WebhookDeliveryClaim, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx for claim webhook deliveries: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var rows []struct {
		ID           int64  `db:"id"`
		PublicID     string `db:"public_id"`
		Attempt      int    `db:"attempt"`
		Payload      []byte `db:"payload"`
		URL          string `db:"url"`
		SecretSealed []byte `db:"secret_sealed"`
	}
	if err := tx.SelectContext(ctx, &rows, `
		SELECT d.id, d.public_id, d.attempt, d.payload, wd.url, wd.secret_sealed
		FROM webhook_delivery d
		JOIN webhook_destination wd ON wd.id = d.destination_id
		WHERE d.status = 'pending' AND d.next_attempt_at <= NOW(6) AND wd.enabled = 1
		ORDER BY d.next_attempt_at
		LIMIT ?
		FOR UPDATE OF d SKIP LOCKED`, limit); err != nil {
		return nil, fmt.Errorf("select due webhook deliveries: %w", err)
	}
	if len(rows) == 0 {
		return nil, tx.Commit()
	}

	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	query, args, err := sqlx.In(
		"UPDATE webhook_delivery SET attempt = attempt + 1, next_attempt_at = DATE_ADD(NOW(6), INTERVAL ? MICROSECOND) WHERE id IN (?)",
		lease.Microseconds(), ids)
	if err != nil {
		return nil, fmt.Errorf("build lease update: %w", err)
	}
	if _, err := tx.ExecContext(ctx, tx.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("lease webhook deliveries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim webhook deliveries: %w", err)
	}

	claims := make([]detapi.WebhookDeliveryClaim, len(rows))
	for i, r := range rows {
		claims[i] = detapi.WebhookDeliveryClaim{
			ID: r.ID, PublicID: r.PublicID, Attempt: r.Attempt + 1, URL: r.URL, Payload: r.Payload, SecretSealed: r.SecretSealed,
		}
	}
	return claims, nil
}

// MarkWebhookDelivered records a successful (2xx) delivery.
func (s *Store) MarkWebhookDelivered(ctx context.Context, id int64, statusCode int) error {
	if _, err := s.db.ExecContext(ctx,
		"UPDATE webhook_delivery SET status = 'delivered', last_status_code = ?, last_error = NULL WHERE id = ?",
		statusCode, id); err != nil {
		return fmt.Errorf("mark webhook delivery %d delivered: %w", id, err)
	}
	return nil
}

// RescheduleWebhookDelivery keeps a delivery pending and sets its next attempt time after a retryable failure. statusCode 0 (a
// transport error with no HTTP response) stores NULL.
func (s *Store) RescheduleWebhookDelivery(ctx context.Context, id int64, nextAttempt time.Time, statusCode int, errMsg string) error {
	if _, err := s.db.ExecContext(ctx,
		"UPDATE webhook_delivery SET next_attempt_at = ?, last_status_code = NULLIF(?, 0), last_error = NULLIF(?, '') WHERE id = ?",
		nextAttempt.UTC(), statusCode, truncate(errMsg, maxLastErrorLen), id); err != nil {
		return fmt.Errorf("reschedule webhook delivery %d: %w", id, err)
	}
	return nil
}

// MarkWebhookFailed records a terminal failure after the retry cap (or an unrecoverable per-row error), surfacing it to operators via
// the delivery-status readout rather than dropping it silently.
func (s *Store) MarkWebhookFailed(ctx context.Context, id int64, statusCode int, errMsg string) error {
	if _, err := s.db.ExecContext(ctx,
		"UPDATE webhook_delivery SET status = 'failed', last_status_code = NULLIF(?, 0), last_error = NULLIF(?, '') WHERE id = ?",
		statusCode, truncate(errMsg, maxLastErrorLen), id); err != nil {
		return fmt.Errorf("mark webhook delivery %d failed: %w", id, err)
	}
	return nil
}

// ListWebhookDeliveries returns the most recent deliveries for a destination (newest first), for the operator delivery-status readout.
// It carries no payload or secret.
func (s *Store) ListWebhookDeliveries(ctx context.Context, destinationID int64, limit int) ([]detapi.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows []struct {
		ID             int64     `db:"id"`
		DestinationID  int64     `db:"destination_id"`
		EventType      string    `db:"event_type"`
		Status         string    `db:"status"`
		Attempt        int       `db:"attempt"`
		LastStatusCode *int      `db:"last_status_code"`
		LastError      *string   `db:"last_error"`
		CreatedAt      time.Time `db:"created_at"`
		UpdatedAt      time.Time `db:"updated_at"`
		NextAttemptAt  time.Time `db:"next_attempt_at"`
	}
	if err := s.db.SelectContext(ctx, &rows, `
		SELECT id, destination_id, event_type, status, attempt, last_status_code, last_error, created_at, updated_at, next_attempt_at
		FROM webhook_delivery WHERE destination_id = ? ORDER BY id DESC LIMIT ?`, destinationID, limit); err != nil {
		return nil, fmt.Errorf("list webhook deliveries for destination %d: %w", destinationID, err)
	}
	out := make([]detapi.WebhookDelivery, 0, len(rows))
	for _, r := range rows {
		lastErr := ""
		if r.LastError != nil {
			lastErr = *r.LastError
		}
		out = append(out, detapi.WebhookDelivery{
			ID: r.ID, DestinationID: r.DestinationID, EventType: r.EventType, Status: detapi.WebhookDeliveryStatus(r.Status),
			Attempt: r.Attempt, LastStatusCode: r.LastStatusCode, LastError: lastErr,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, NextAttemptAt: r.NextAttemptAt,
		})
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

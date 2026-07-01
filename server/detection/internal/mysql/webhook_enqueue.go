package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
)

// alertEnvelopeCols is the alert projection the delivery payload is built from. It mirrors GetAlert's column list (COALESCE keeps a
// process-less alert's NULL process_id scanning into the int64 field as 0).
const alertEnvelopeCols = `id, host_id, rule_id, source, severity, title, description, COALESCE(process_id, 0) AS process_id,
	techniques, status, created_at, updated_at, resolved_at, updated_by`

// loadAlertTx reads the full alert row inside the caller's transaction so the delivery payload reflects the DB-populated fields
// (status, timestamps) rather than the partially-filled struct handed to InsertAlert.
func loadAlertTx(ctx context.Context, tx *sqlx.Tx, id int64) (api.Alert, error) {
	var a api.Alert
	if err := tx.GetContext(ctx, &a, "SELECT "+alertEnvelopeCols+" FROM alerts WHERE id = ?", id); err != nil {
		return api.Alert{}, fmt.Errorf("load alert %d for webhook: %w", id, err)
	}
	return a, nil
}

// matchingWebhookDestinations returns the ids of enabled destinations subscribed to eventType whose minimum severity the alert
// severity meets. Severity is ranked with FIELD so the comparison follows the defined low<medium<high<critical order rather than the
// stored ENUM string.
func matchingWebhookDestinations(ctx context.Context, tx *sqlx.Tx, eventType, severity string) ([]int64, error) {
	var ids []int64
	err := tx.SelectContext(ctx, &ids, `
		SELECT id FROM webhook_destination
		WHERE enabled = 1
		  AND FIND_IN_SET(?, event_types)
		  AND FIELD(?, 'low', 'medium', 'high', 'critical') >= FIELD(min_severity, 'low', 'medium', 'high', 'critical')`,
		eventType, severity)
	if err != nil {
		return nil, fmt.Errorf("select matching webhook destinations: %w", err)
	}
	return ids, nil
}

// webhookEnqueueSpec bundles the per-event inputs for a fan-out so the enqueue helper stays under the parameter-count limit.
type webhookEnqueueSpec struct {
	eventType  string
	alert      api.Alert
	prevStatus string
	dedupKey   string
	occurredAt time.Time
}

// enqueueWebhookDeliveries inserts one pending outbox row per destination, all carrying the same alert snapshot but each with its own
// delivery id (the webhook-id receivers dedup on). The dedup key makes the enqueue idempotent: a re-fired created event or a replayed
// status transition collides on the (alert_id, destination_id, dedup_key) unique key and is a no-op rather than a second delivery.
func (s *Store) enqueueWebhookDeliveries(ctx context.Context, tx *sqlx.Tx, destIDs []int64, spec webhookEnqueueSpec) error {
	for _, destID := range destIDs {
		pubID := uuid.NewString()
		payload, err := json.Marshal(webhook.Build(webhook.BuildParams{
			EventID:        pubID,
			EventType:      webhook.EventType(spec.eventType),
			OccurredAt:     spec.occurredAt,
			Attempt:        1,
			Alert:          spec.alert,
			PreviousStatus: spec.prevStatus,
			ConsoleBaseURL: s.webhookConsoleBaseURL,
		}))
		if err != nil {
			return fmt.Errorf("marshal webhook payload: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO webhook_delivery (public_id, alert_id, destination_id, event_type, dedup_key, payload, next_attempt_at)
			VALUES (?, ?, ?, ?, ?, ?, NOW(6))
			ON DUPLICATE KEY UPDATE public_id = public_id`,
			pubID, spec.alert.ID, destID, spec.eventType, spec.dedupKey, payload); err != nil {
			return fmt.Errorf("insert webhook delivery: %w", err)
		}
	}
	return nil
}

// enqueueNewAlertDeliveries fans a freshly created alert out to matching destinations inside the alert-insert transaction, so a
// queued delivery is durable with the alert. It matches on the caller's severity first and only reloads the full alert when at least
// one destination matches; a no-match is a no-op and never blocks alert persistence.
func (s *Store) enqueueNewAlertDeliveries(ctx context.Context, tx *sqlx.Tx, base api.Alert, alertID int64) error {
	ids, err := matchingWebhookDestinations(ctx, tx, api.WebhookEventAlertCreated, base.Severity)
	if err != nil || len(ids) == 0 {
		return err
	}
	full, err := loadAlertTx(ctx, tx, alertID)
	if err != nil {
		return err
	}
	return s.enqueueWebhookDeliveries(ctx, tx, ids, webhookEnqueueSpec{
		eventType: api.WebhookEventAlertCreated, alert: full, dedupKey: "created", occurredAt: full.CreatedAt,
	})
}

// enqueueStatusChangeDeliveries fans an alert status change out to destinations subscribed to status events, inside the status-update
// transaction. The dedup key is derived from the post-update timestamp so each distinct transition enqueues once while a replayed
// no-op update (which leaves updated_at unchanged) collides and is ignored.
func (s *Store) enqueueStatusChangeDeliveries(ctx context.Context, tx *sqlx.Tx, id int64, prevStatus string) error {
	full, err := loadAlertTx(ctx, tx, id)
	if err != nil {
		return err
	}
	ids, err := matchingWebhookDestinations(ctx, tx, api.WebhookEventAlertStatusChanged, full.Severity)
	if err != nil || len(ids) == 0 {
		return err
	}
	dedupKey := fmt.Sprintf("status:%d", full.UpdatedAt.UnixMicro())
	return s.enqueueWebhookDeliveries(ctx, tx, ids, webhookEnqueueSpec{
		eventType: api.WebhookEventAlertStatusChanged, alert: full, prevStatus: prevStatus, dedupKey: dedupKey, occurredAt: full.UpdatedAt,
	})
}

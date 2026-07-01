//go:build integration

// Integration coverage for the outbound-webhook enqueue hook (issue #496): creating an alert (and changing its status) enqueues one
// durable webhook_delivery row per matching enabled destination, in the same transaction as the alert write, and a re-fired dedup
// does not double-enqueue. Runs against real MySQL via server/testdb/full (migration 00009 applied).

package tests

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/secretseal"
	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

func newEnqueueStore(t *testing.T) (*mysql.Store, *sqlx.DB) {
	t.Helper()
	db := full.Open(t)
	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)
	sealer, err := secretseal.NewSealer(key)
	require.NoError(t, err)
	store.SetWebhookSealer(sealer)
	store.SetWebhookConsoleBaseURL("https://edr.example.com")
	return store, db
}

func makeDest(t *testing.T, store *mysql.Store, name, minSeverity string, enabled bool, eventTypes ...string) int64 {
	t.Helper()
	id, err := store.CreateWebhookDestination(context.Background(), detapi.WebhookDestinationInput{
		Name: name, URL: "https://hooks.example.com/" + name,
		EventTypes: eventTypes, MinSeverity: minSeverity, Enabled: enabled, Secret: "secret-" + name,
	})
	require.NoError(t, err)
	return id
}

type deliveryRow struct {
	DestinationID int64  `db:"destination_id"`
	EventType     string `db:"event_type"`
	Status        string `db:"status"`
	DedupKey      string `db:"dedup_key"`
	Payload       []byte `db:"payload"`
}

func allDeliveries(t *testing.T, db *sqlx.DB) []deliveryRow {
	t.Helper()
	var rows []deliveryRow
	require.NoError(t, db.SelectContext(context.Background(), &rows,
		"SELECT destination_id, event_type, status, dedup_key, payload FROM webhook_delivery ORDER BY id"))
	return rows
}

func highAlert(subject string) detapi.Alert {
	return detapi.Alert{
		HostID: "host-1", RuleID: "cred_access_lsass", Source: detapi.AlertSourceDetection,
		Severity: detapi.SeverityHigh, Title: "LSASS access", Description: "d", ProcessID: 0, Subject: subject,
	}
}

func TestWebhookEnqueue_CreatedFanout(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	ctx := context.Background()

	matched := makeDest(t, store, "matched", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	makeDest(t, store, "too-severe", detapi.SeverityCritical, true, detapi.WebhookEventAlertCreated)   // high < critical: filtered out
	makeDest(t, store, "disabled", detapi.SeverityLow, false, detapi.WebhookEventAlertCreated)         // disabled: filtered out
	makeDest(t, store, "status-only", detapi.SeverityLow, true, detapi.WebhookEventAlertStatusChanged) // wrong event: filtered out

	t.Run("spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/a-new-alert-with-a-matching-destination-queues-one-delivery", func(t *testing.T) {
		alertID, created, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
		require.NoError(t, err)
		require.True(t, created)

		rows := allDeliveries(t, db)
		require.Len(t, rows, 1, "only the enabled, created-subscribed, severity-matching destination is enqueued")
		got := rows[0]
		assert.Equal(t, matched, got.DestinationID)
		assert.Equal(t, detapi.WebhookEventAlertCreated, got.EventType)
		assert.Equal(t, string(detapi.WebhookDeliveryPending), got.Status)
		assert.Equal(t, "created", got.DedupKey)

		var env map[string]any
		require.NoError(t, json.Unmarshal(got.Payload, &env))
		assert.Equal(t, "alert.created", env["event_type"])
		alert, ok := env["alert"].(map[string]any)
		require.True(t, ok)
		assert.EqualValues(t, alertID, alert["id"])
	})

	t.Run("spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/a-deduplicated-alert-does-not-double-queue", func(t *testing.T) {
		_, created, err := store.InsertAlert(ctx, highAlert("test:1"), nil) // same dedup identity
		require.NoError(t, err)
		require.False(t, created, "the re-fired alert deduplicates")
		assert.Len(t, allDeliveries(t, db), 1, "a deduplicated alert must not enqueue a second delivery")
	})
}

func TestWebhookEnqueue_NoDestinations(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	t.Run("spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/alert-creation-is-unaffected-when-no-destination-is-configured", func(t *testing.T) {
		_, created, err := store.InsertAlert(context.Background(), highAlert("test:1"), nil)
		require.NoError(t, err)
		require.True(t, created)
		assert.Empty(t, allDeliveries(t, db))
	})
}

func TestWebhookEnqueue_StatusChange(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	ctx := context.Background()
	makeDest(t, store, "status-sink", detapi.SeverityLow, true, detapi.WebhookEventAlertStatusChanged)

	alertID, created, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)
	require.True(t, created)
	assert.Empty(t, allDeliveries(t, db), "a status-only destination gets no delivery on create")

	t.Run("spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/a-status-change-queues-a-delivery-for-a-subscribed-destination", func(t *testing.T) {
		require.NoError(t, store.UpdateAlertStatus(ctx, alertID, detapi.AlertStatusResolved, "usr_1"))
		rows := allDeliveries(t, db)
		require.Len(t, rows, 1)
		got := rows[0]
		assert.Equal(t, detapi.WebhookEventAlertStatusChanged, got.EventType)

		var env map[string]any
		require.NoError(t, json.Unmarshal(got.Payload, &env))
		alert := env["alert"].(map[string]any)
		assert.Equal(t, "resolved", alert["status"])
		assert.Equal(t, "open", alert["previous_status"], "status-change payload carries the prior status")
	})
}

//go:build integration

// Integration coverage for the outbound alert webhook destination store (issue #496): CRUD against real MySQL through
// server/testdb/full (which applies migration 00009), plus the at-rest sealing invariant (the signing secret is stored encrypted and
// never returned on the read model) and the save-time SSRF/validation rejections.

package tests

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/secretseal"
	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	"github.com/fleetdm/edr/server/testdb/full"
)

func newWebhookStore(t *testing.T) (*mysql.Store, *sqlx.DB, *secretseal.Sealer) {
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
	return store, db, sealer
}

func sealedSecret(t *testing.T, db *sqlx.DB, sealer *secretseal.Sealer, id int64) string {
	t.Helper()
	var sealed []byte
	require.NoError(t, db.GetContext(context.Background(), &sealed, "SELECT secret_sealed FROM webhook_destination WHERE id = ?", id))
	plaintext, err := sealer.Open(sealed)
	require.NoError(t, err)
	return string(plaintext)
}

func TestWebhookDestinationStore_CRUD(t *testing.T) {
	t.Parallel()
	store, db, sealer := newWebhookStore(t)
	ctx := context.Background()

	in := detapi.WebhookDestinationInput{
		Name: "pagerduty", URL: "https://hooks.example.com/edr",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, MinSeverity: detapi.SeverityHigh, Enabled: true,
		Secret: "signing-secret-one",
	}
	id, err := store.CreateWebhookDestination(ctx, in)
	require.NoError(t, err)
	require.Positive(t, id)

	t.Run("spec:alert-webhook-delivery/operators-manage-webhook-destinations-with-a-sealed-write-only-secret/creating-a-destination-does-not-echo-the-secret", func(t *testing.T) {
		list, err := store.ListWebhookDestinations(ctx)
		require.NoError(t, err)
		require.Len(t, list, 1)
		d := list[0]
		assert.Equal(t, "pagerduty", d.Name)
		assert.Equal(t, "https://hooks.example.com/edr", d.URL)
		assert.Equal(t, []string{detapi.WebhookEventAlertCreated}, d.EventTypes)
		assert.Equal(t, detapi.SeverityHigh, d.MinSeverity)
		assert.True(t, d.Enabled)
		assert.True(t, d.SecretSet, "read model reports a secret is set without carrying it")
		// The read model has no secret field at all; the stored form is sealed and decryptable only with the sealer.
		assert.Equal(t, "signing-secret-one", sealedSecret(t, db, sealer, id))
	})

	got, err := store.GetWebhookDestination(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)

	t.Run("spec:alert-webhook-delivery/operators-manage-webhook-destinations-with-a-sealed-write-only-secret/updating-the-secret-changes-the-signing-key-for-later-deliveries", func(t *testing.T) {
		rotate := in
		rotate.Name = "pd-renamed"
		rotate.Secret = "signing-secret-two"
		require.NoError(t, store.UpdateWebhookDestination(ctx, id, rotate))
		assert.Equal(t, "signing-secret-two", sealedSecret(t, db, sealer, id), "a non-empty secret rotates the sealed key")

		keep := in
		keep.Name = "pd-again"
		keep.Enabled = false
		keep.Secret = "" // empty means keep the stored secret
		require.NoError(t, store.UpdateWebhookDestination(ctx, id, keep))
		after, err := store.GetWebhookDestination(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, "pd-again", after.Name)
		assert.False(t, after.Enabled)
		assert.Equal(t, "signing-secret-two", sealedSecret(t, db, sealer, id), "an empty secret keeps the stored key")
	})

	require.NoError(t, store.DeleteWebhookDestination(ctx, id))
	_, err = store.GetWebhookDestination(ctx, id)
	assert.ErrorIs(t, err, mysql.ErrWebhookNotFound)
}

func TestWebhookDestinationStore_Validation(t *testing.T) {
	t.Parallel()
	store, _, _ := newWebhookStore(t)
	ctx := context.Background()
	base := detapi.WebhookDestinationInput{
		Name: "d", URL: "https://ok.example.com/hook",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, MinSeverity: detapi.SeverityLow, Secret: "s",
	}

	cases := []struct {
		name    string
		mutate  func(in *detapi.WebhookDestinationInput)
		wantErr error
	}{
		{"non-https URL rejected", func(in *detapi.WebhookDestinationInput) { in.URL = "http://insecure.example.com" }, webhook.ErrBlockedURL},
		{"private literal URL rejected", func(in *detapi.WebhookDestinationInput) { in.URL = "https://10.0.0.1/hook" }, webhook.ErrBlockedURL},
		{"missing secret rejected", func(in *detapi.WebhookDestinationInput) { in.Secret = "" }, mysql.ErrWebhookSecretMissing},
		{"over-long secret rejected", func(in *detapi.WebhookDestinationInput) { in.Secret = strings.Repeat("x", 300) }, mysql.ErrWebhookSecretTooLong},
		{"empty name rejected", func(in *detapi.WebhookDestinationInput) { in.Name = "" }, mysql.ErrWebhookName},
		{"unknown event type rejected", func(in *detapi.WebhookDestinationInput) { in.EventTypes = []string{"bogus"} }, mysql.ErrWebhookEventTypes},
		{"no event types rejected", func(in *detapi.WebhookDestinationInput) { in.EventTypes = nil }, mysql.ErrWebhookEventTypes},
		{"invalid severity rejected", func(in *detapi.WebhookDestinationInput) { in.MinSeverity = "extreme" }, mysql.ErrWebhookSeverity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			_, err := store.CreateWebhookDestination(ctx, in)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}

	t.Run("update and delete of an unknown id are not found", func(t *testing.T) {
		assert.ErrorIs(t, store.UpdateWebhookDestination(ctx, 987654, base), mysql.ErrWebhookNotFound)
		assert.ErrorIs(t, store.DeleteWebhookDestination(ctx, 987654), mysql.ErrWebhookNotFound)
	})
}

// spec:alert-webhook-delivery/operators-can-test-a-destination-and-see-delivery-health/the-status-readout-reflects-the-latest-outcome
func TestWebhookDestinationStore_DeliveriesReadout(t *testing.T) {
	t.Parallel()
	store, _, _ := newWebhookStore(t)
	ctx := context.Background()
	destID := makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	_, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	pending, err := store.ListWebhookDeliveries(ctx, destID, 50)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, detapi.WebhookDeliveryPending, pending[0].Status)
	assert.Empty(t, pending[0].LastError)

	// Mark it failed so the readout exercises the non-null last_status_code + last_error mapping.
	require.NoError(t, store.MarkWebhookFailed(ctx, pending[0].ID, 503, "receiver unavailable"))
	got, err := store.ListWebhookDeliveries(ctx, destID, 50)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, detapi.WebhookDeliveryFailed, got[0].Status)
	require.NotNil(t, got[0].LastStatusCode)
	assert.Equal(t, 503, *got[0].LastStatusCode)
	assert.Equal(t, "receiver unavailable", got[0].LastError)
}

// TestWebhookDelivery_disabledDestinationNotClaimed pins that disabling a destination stops delivery of its already-queued rows: the
// claim query filters on wd.enabled, so a delivery enqueued while the destination was enabled is no longer claimed once it is disabled.
// spec:alert-webhook-delivery/operators-manage-webhook-destinations-with-a-sealed-write-only-secret/disabling-a-destination-stops-future-deliveries
func TestWebhookDelivery_disabledDestinationNotClaimed(t *testing.T) {
	t.Parallel()
	store, _, _ := newWebhookStore(t)
	ctx := context.Background()
	destID := makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	_, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	require.NoError(t, store.UpdateWebhookDestination(ctx, destID, detapi.WebhookDestinationInput{
		Name: "sink", URL: "https://hooks.example.com/sink",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, MinSeverity: detapi.SeverityLow, Enabled: false,
	}))

	claims, err := store.ClaimDueWebhookDeliveries(ctx, 10, time.Minute)
	require.NoError(t, err)
	assert.Empty(t, claims, "a disabled destination's queued deliveries must not be claimed")
}

func TestWebhookDestinationStore_SealerUnset(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	store, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	// No SetWebhookSealer: a deployment with no root secret cannot seal, so a create that carries a secret is rejected.
	_, err = store.CreateWebhookDestination(context.Background(), detapi.WebhookDestinationInput{
		Name: "d", URL: "https://ok.example.com/hook",
		EventTypes: []string{detapi.WebhookEventAlertCreated}, Secret: "s",
	})
	assert.ErrorIs(t, err, mysql.ErrWebhookSealerUnset)
}

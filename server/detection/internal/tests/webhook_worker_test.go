//go:build integration

// Integration coverage for the webhook delivery worker (issue #496): it claims due outbox rows, unseals the destination secret,
// overlays the attempt number, hands the signed payload to the sender, and records the outcome, retrying with backoff up to the cap
// before marking a delivery failed. A fake sender isolates the claim/backoff/finalize logic from real HTTP (the SSRF-safe client and
// signing are covered by the webhook package's own tests). Runs against real MySQL via server/testdb/full.

package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/pipeline"
)

type fakeResp struct {
	code int
	err  error
}

type fakeSender struct {
	responses  []fakeResp
	calls      int
	lastURL    string
	lastID     string
	lastTS     int64
	lastBody   []byte
	lastSecret []byte
	ids        []string
}

func (f *fakeSender) Deliver(_ context.Context, url, id string, ts int64, body, secret []byte) (int, error) {
	i := f.calls
	f.calls++
	f.lastURL, f.lastID, f.lastTS = url, id, ts
	f.ids = append(f.ids, id)
	f.lastBody = append([]byte(nil), body...)
	f.lastSecret = append([]byte(nil), secret...)
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	return f.responses[i].code, f.responses[i].err
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// pastNow pins the worker clock to a fixed past instant so a rescheduled retry's next_attempt_at is always already due, making the
// retry deterministic without sleeping. The claim lease uses SQL NOW(), so leasing still works.
func pastNow() time.Time { return time.Unix(1000, 0).UTC() }

type deliveryState struct {
	Status         string `db:"status"`
	Attempt        int    `db:"attempt"`
	LastStatusCode *int   `db:"last_status_code"`
}

func onlyDelivery(t *testing.T, db *sqlx.DB) deliveryState {
	t.Helper()
	var s deliveryState
	require.NoError(t, db.GetContext(context.Background(), &s,
		"SELECT status, attempt, last_status_code FROM webhook_delivery LIMIT 1"))
	return s
}

// spec:alert-webhook-delivery/delivery-is-reliable-and-at-least-once/a-transient-failure-is-retried-then-delivered
// spec:alert-webhook-delivery/delivery-is-reliable-and-at-least-once/repeated-attempts-share-a-stable-event-id
func TestWebhookWorker_RetryThenDeliver(t *testing.T) {
	t.Parallel()
	store, db, sealer := newWebhookStore(t)
	ctx := context.Background()
	makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	alertID, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	sender := &fakeSender{responses: []fakeResp{{code: 500}, {code: 200}}}
	worker := pipeline.NewWebhookDelivery(store, sealer, pipeline.WebhookDeliveryOptions{
		Sender: sender, MaxAttempts: 3, BaseBackoff: time.Millisecond, Logger: discardLog(), Now: pastNow,
	})

	n, err := worker.Run(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	// First send got a 500: still pending, retryable, status code recorded, attempt advanced to 1.
	st := onlyDelivery(t, db)
	assert.Equal(t, string(detapi.WebhookDeliveryPending), st.Status)
	assert.Equal(t, 1, st.Attempt)
	require.NotNil(t, st.LastStatusCode)
	assert.Equal(t, 500, *st.LastStatusCode)

	// The worker unsealed the secret and overlaid the attempt number onto the stored payload before sending.
	assert.Equal(t, "secret-sink", string(sender.lastSecret))
	var env map[string]any
	require.NoError(t, json.Unmarshal(sender.lastBody, &env))
	assert.EqualValues(t, 1, env["delivery_attempt"])
	assert.EqualValues(t, alertID, env["alert"].(map[string]any)["id"])

	n, err = worker.Run(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	st = onlyDelivery(t, db)
	assert.Equal(t, string(detapi.WebhookDeliveryDelivered), st.Status)
	require.NotNil(t, st.LastStatusCode)
	assert.Equal(t, 200, *st.LastStatusCode)

	// Both attempts carried the same delivery id, so a receiver dedups repeated attempts of one logical delivery.
	require.Len(t, sender.ids, 2)
	assert.Equal(t, sender.ids[0], sender.ids[1], "the delivery id is stable across retries")
}

// spec:alert-webhook-delivery/delivery-is-reliable-and-at-least-once/a-persistently-failing-delivery-is-marked-failed-after-the-cap
func TestWebhookWorker_FailsAfterCap(t *testing.T) {
	t.Parallel()
	store, db, sealer := newWebhookStore(t)
	ctx := context.Background()
	makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	_, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	sender := &fakeSender{responses: []fakeResp{{code: 503}}} // always fails
	worker := pipeline.NewWebhookDelivery(store, sealer, pipeline.WebhookDeliveryOptions{
		Sender: sender, MaxAttempts: 2, BaseBackoff: time.Millisecond, Logger: discardLog(), Now: pastNow,
	})

	_, err = worker.Run(ctx) // attempt 1: reschedule
	require.NoError(t, err)
	assert.Equal(t, string(detapi.WebhookDeliveryPending), onlyDelivery(t, db).Status)

	_, err = worker.Run(ctx) // attempt 2 == cap: fail
	require.NoError(t, err)
	st := onlyDelivery(t, db)
	assert.Equal(t, string(detapi.WebhookDeliveryFailed), st.Status)
	require.NotNil(t, st.LastStatusCode)
	assert.Equal(t, 503, *st.LastStatusCode)
}

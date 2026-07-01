package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/secretseal"
	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
)

type fakeDeliveryStore struct {
	claims      []detapi.WebhookDeliveryClaim
	delivered   []int64
	rescheduled []int64
	failed      []int64
	failMsg     map[int64]string
}

func (f *fakeDeliveryStore) ClaimDueWebhookDeliveries(context.Context, int, time.Duration) ([]detapi.WebhookDeliveryClaim, error) {
	c := f.claims
	f.claims = nil
	return c, nil
}

func (f *fakeDeliveryStore) MarkWebhookDelivered(_ context.Context, id int64, _ int) error {
	f.delivered = append(f.delivered, id)
	return nil
}

func (f *fakeDeliveryStore) RescheduleWebhookDelivery(_ context.Context, id int64, _ time.Time, _ int, _ string) error {
	f.rescheduled = append(f.rescheduled, id)
	return nil
}

func (f *fakeDeliveryStore) MarkWebhookFailed(_ context.Context, id int64, _ int, msg string) error {
	f.failed = append(f.failed, id)
	if f.failMsg == nil {
		f.failMsg = map[int64]string{}
	}
	f.failMsg[id] = msg
	return nil
}

type fakeDeliverySender struct {
	code int
	err  error
}

func (f fakeDeliverySender) Deliver(context.Context, string, string, int64, []byte, []byte) (int, error) {
	return f.code, f.err
}

func testSealer(t *testing.T) *secretseal.Sealer {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	s, err := secretseal.NewSealer(key)
	require.NoError(t, err)
	return s
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func validClaim(t *testing.T, sealer *secretseal.Sealer, attempt int) detapi.WebhookDeliveryClaim {
	t.Helper()
	payload, err := json.Marshal(webhook.Envelope{SchemaVersion: "1.0", EventID: "e", EventType: webhook.EventAlertCreated, Alert: webhook.AlertBody{ID: 1}})
	require.NoError(t, err)
	sealed, err := sealer.Seal([]byte("the-secret"))
	require.NoError(t, err)
	return detapi.WebhookDeliveryClaim{ID: 7, PublicID: "e", Attempt: attempt, URL: "https://x.example.com", Payload: payload, SecretSealed: sealed}
}

func newTestWorker(store webhookDeliveryStore, sealer *secretseal.Sealer, sender webhookSender, maxAttempts int) *WebhookDeliveryRunner {
	return NewWebhookDelivery(store, sealer, WebhookDeliveryOptions{
		Sender: sender, MaxAttempts: maxAttempts, BaseBackoff: time.Millisecond, Logger: discardLogger(),
		Now: func() time.Time { return time.Unix(1000, 0).UTC() },
	})
}

func TestNewWebhookDelivery_defaultsAndPanics(t *testing.T) {
	t.Parallel()
	sealer := testSealer(t)
	// Zero options exercise every default branch (interval, lease, backoffs, cap, batch, logger, now, sender).
	w := NewWebhookDelivery(&fakeDeliveryStore{}, sealer, WebhookDeliveryOptions{})
	n, err := w.Run(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "no due deliveries")

	assert.Panics(t, func() { NewWebhookDelivery(nil, sealer, WebhookDeliveryOptions{}) })
	assert.Panics(t, func() { NewWebhookDelivery(&fakeDeliveryStore{}, nil, WebhookDeliveryOptions{}) })
}

func TestWebhookDelivery_outcomes(t *testing.T) {
	t.Parallel()
	sealer := testSealer(t)

	t.Run("2xx marks delivered", func(t *testing.T) {
		t.Parallel()
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{validClaim(t, sealer, 1)}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{code: 200}, 3)))
		assert.Equal(t, []int64{7}, store.delivered)
	})

	t.Run("retryable failure reschedules", func(t *testing.T) {
		t.Parallel()
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{validClaim(t, sealer, 1)}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{code: 500}, 3)))
		assert.Equal(t, []int64{7}, store.rescheduled)
		assert.Empty(t, store.failed)
	})

	t.Run("failure at the cap marks failed", func(t *testing.T) {
		t.Parallel()
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{validClaim(t, sealer, 3)}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{code: 503}, 3)))
		assert.Equal(t, []int64{7}, store.failed)
	})

	t.Run("transport error reschedules below cap", func(t *testing.T) {
		t.Parallel()
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{validClaim(t, sealer, 1)}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{err: errors.New("dial timeout")}, 3)))
		assert.Equal(t, []int64{7}, store.rescheduled)
	})

	t.Run("unopenable secret fails terminally", func(t *testing.T) {
		t.Parallel()
		claim := validClaim(t, sealer, 1)
		claim.SecretSealed = []byte("not-a-sealed-blob")
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{claim}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{code: 200}, 3)))
		assert.Equal(t, []int64{7}, store.failed)
		assert.Contains(t, store.failMsg[7], "unseal")
	})

	t.Run("undecodable payload fails terminally", func(t *testing.T) {
		t.Parallel()
		claim := validClaim(t, sealer, 1)
		claim.Payload = []byte("{not json")
		store := &fakeDeliveryStore{claims: []detapi.WebhookDeliveryClaim{claim}}
		require.NoError(t, workerRun(newTestWorker(store, sealer, fakeDeliverySender{code: 200}, 3)))
		assert.Equal(t, []int64{7}, store.failed)
		assert.Contains(t, store.failMsg[7], "decode")
	})
}

// workerRun runs one drain and returns the error (the count is asserted elsewhere).
func workerRun(w *WebhookDeliveryRunner) error {
	_, err := w.Run(context.Background())
	return err
}

func TestWebhookDelivery_backoff(t *testing.T) {
	t.Parallel()
	w := NewWebhookDelivery(&fakeDeliveryStore{}, testSealer(t), WebhookDeliveryOptions{
		BaseBackoff: time.Second, MaxBackoff: 4 * time.Second,
	})
	assert.Equal(t, time.Second, w.backoff(1))
	assert.Equal(t, 2*time.Second, w.backoff(2))
	assert.Equal(t, 4*time.Second, w.backoff(3))
	assert.Equal(t, 4*time.Second, w.backoff(9), "capped at maxBackoff")
}

func TestSendErrString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "boom", sendErrString(errors.New("boom")))
	assert.Equal(t, "non-2xx response", sendErrString(nil))
}

//go:build integration

// Integration coverage for the outbound-webhook durability + multi-replica properties (issue #496), against real MySQL via
// server/testdb/full: enqueue atomicity on rollback, survival of a queued delivery across a restart, and single-claim under
// concurrent replicas.

package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
)

// spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/no-delivery-is-queued-when-the-alert-does-not-persist
func TestWebhookEnqueue_NoDeliveryWhenAlertRollsBack(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	ctx := context.Background()
	makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)

	// A process-backed alert whose process_id has no processes row violates fk_alerts_process, so InsertAlert errors and the whole
	// transaction (including the webhook enqueue) rolls back.
	bad := detapi.Alert{
		HostID: "host-1", RuleID: "r", Source: detapi.AlertSourceDetection, Severity: detapi.SeverityHigh,
		Title: "t", Description: "d", ProcessID: 999999,
	}
	_, _, err := store.InsertAlert(ctx, bad, nil)
	require.Error(t, err)

	var alerts, deliveries int
	require.NoError(t, db.GetContext(ctx, &alerts, "SELECT COUNT(*) FROM alerts"))
	require.NoError(t, db.GetContext(ctx, &deliveries, "SELECT COUNT(*) FROM webhook_delivery"))
	assert.Zero(t, alerts, "the alert did not persist")
	assert.Zero(t, deliveries, "no delivery was queued")
}

// spec:alert-webhook-delivery/alert-lifecycle-events-durably-enqueue-a-delivery-per-matching-destination/a-queued-delivery-survives-a-restart-before-it-is-sent
func TestWebhookDelivery_SurvivesRestart(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	ctx := context.Background()
	makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	_, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	// A brand-new store over the same database stands in for a restarted replica: the committed delivery is durable and claimable.
	fresh, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	claims, err := fresh.ClaimDueWebhookDeliveries(ctx, 10, time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, 1, "the persisted delivery survives and is claimable after a restart")
}

// spec:alert-webhook-delivery/delivery-is-reliable-and-at-least-once/two-replicas-send-a-delivery-once-per-attempt
func TestWebhookDelivery_TwoReplicasClaimOnce(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	ctx := context.Background()
	makeDest(t, store, "sink", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	_, _, err := store.InsertAlert(ctx, highAlert("test:1"), nil)
	require.NoError(t, err)

	// Two replicas over the same database claim concurrently; SELECT ... FOR UPDATE OF ... SKIP LOCKED plus the lease guarantees the
	// single pending delivery goes to exactly one of them.
	repA, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)
	repB, err := mysql.New(db, detectiontestkit.NewMemArchive(), nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for _, rep := range []*mysql.Store{repA, repB} {
		wg.Add(1)
		go func(s *mysql.Store) {
			defer wg.Done()
			claims, claimErr := s.ClaimDueWebhookDeliveries(ctx, 10, time.Minute)
			if claimErr == nil {
				mu.Lock()
				total += len(claims)
				mu.Unlock()
			}
		}(rep)
	}
	wg.Wait()
	assert.Equal(t, 1, total, "the delivery is claimed by exactly one replica per attempt")
}

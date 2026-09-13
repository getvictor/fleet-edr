//go:build integration

// Integration coverage for delivering host health episodes to webhook destinations (issue #778), against real MySQL with migration
// 00015 applied: a delivery row names a health episode instead of an alert, matches destinations by subscription and minimum
// severity, and collapses a repeated enqueue for one episode and destination.

package tests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	"github.com/fleetdm/edr/server/detection/internal/webhook"
)

func criticalEpisode(episodeID int64) mysql.HealthEpisodeDelivery {
	return mysql.HealthEpisodeDelivery{
		EpisodeID: episodeID,
		HostID:    "host-h",
		Episode: webhook.HealthEpisodeBody{
			ID:          episodeID,
			Kind:        "self_heal_failed",
			Component:   "network_extension",
			Subject:     "content_filter",
			Severity:    detapi.SeverityCritical,
			Title:       "EDR sensor could not be restored",
			Description: "automatic recovery gave up on content_filter",
			Detail:      json.RawMessage(`{"provider":"content_filter","outcome":"enable_ineffective","attempts":5}`),
			OpenedAt:    time.Unix(1_767_225_600, 0).UTC(),
		},
	}
}

// spec:alert-webhook-delivery/host-health-episodes-are-delivered/an-episode-opening-reaches-a-subscribed-destination
// spec:alert-webhook-delivery/host-health-episodes-are-delivered/a-destination-not-subscribed-to-health-episodes-receives-nothing
// spec:alert-webhook-delivery/host-health-episodes-are-delivered/the-minimum-severity-filters-health-episodes
//
// TestEnqueueHealthEpisodeOpened_MatchesBySubscriptionAndSeverity: an episode reaches exactly the destinations that asked for it. The
// three rejected destinations each isolate one reason, so a regression that loosened any single filter fails on its own row rather
// than being masked by another.
func TestEnqueueHealthEpisodeOpened_MatchesBySubscriptionAndSeverity(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)

	subscribed := makeDest(t, store, "subscribed", detapi.SeverityHigh, true,
		detapi.WebhookEventAlertCreated, detapi.WebhookEventHealthEpisodeOpened)
	makeDest(t, store, "alerts-only", detapi.SeverityLow, true, detapi.WebhookEventAlertCreated)
	makeDest(t, store, "disabled", detapi.SeverityLow, false, detapi.WebhookEventHealthEpisodeOpened)
	// critical meets critical, so the severity rejection needs a threshold the episode cannot meet. There is none above critical, so
	// the filter is exercised with a lower-severity episode below.
	thresholdDest := makeDest(t, store, "critical-only", detapi.SeverityCritical, true, detapi.WebhookEventHealthEpisodeOpened)

	n, err := store.EnqueueHealthEpisodeOpened(context.Background(), criticalEpisode(900))
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "the subscribed destination and the critical-only one; not the alerts-only or disabled ones")

	rows := allDeliveries(t, db)
	require.Len(t, rows, 2)
	got := map[int64]deliveryRow{}
	for _, r := range rows {
		got[r.DestinationID] = r
	}
	require.Contains(t, got, subscribed)
	require.Contains(t, got, thresholdDest)
	assert.Equal(t, detapi.WebhookEventHealthEpisodeOpened, got[subscribed].EventType)
	assert.Equal(t, "pending", got[subscribed].Status)

	// The envelope carries the episode and the host, and no alert body at all.
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(got[subscribed].Payload, &env))
	assert.NotContains(t, env, "alert", "a health delivery describes no alert and must not carry an empty one a receiver could misread")
	require.Contains(t, env, "health_episode")
	var episode webhook.HealthEpisodeBody
	require.NoError(t, json.Unmarshal(env["health_episode"], &episode))
	assert.Equal(t, int64(900), episode.ID)
	assert.Equal(t, "content_filter", episode.Subject)
	assert.JSONEq(t, `{"provider":"content_filter","outcome":"enable_ineffective","attempts":5}`, string(episode.Detail),
		"the fault's own fields reach the receiver as values")
	assert.JSONEq(t, `{"id":"host-h"}`, string(env["host"]))
	assert.JSONEq(t, `{"console":"https://edr.example.com/ui/hosts/host-h"}`, string(env["links"]),
		"a health event pivots to the host, whose sensor is at fault, not to an alert")

	// The severity filter, isolated: a high episode reaches the high-threshold destination and not the critical-only one.
	high := criticalEpisode(901)
	high.Episode.Severity = detapi.SeverityHigh
	n, err = store.EnqueueHealthEpisodeOpened(context.Background(), high)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "a high episode must not reach a destination whose minimum is critical")
}

// spec:alert-webhook-delivery/host-health-episodes-are-delivered/a-lost-enqueue-is-recovered-on-reprocessing-without-a-duplicate
//
// TestEnqueueHealthEpisodeOpened_IsIdempotentPerEpisodeAndDestination is the store's half of the convergence argument. The engine
// enqueues again on every redelivery because it cannot tell whether the last attempt landed, so repeating the enqueue for one episode
// must collapse onto the delivery already queued rather than notifying a destination twice.
func TestEnqueueHealthEpisodeOpened_IsIdempotentPerEpisodeAndDestination(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	makeDest(t, store, "dest", detapi.SeverityLow, true, detapi.WebhookEventHealthEpisodeOpened)

	first, err := store.EnqueueHealthEpisodeOpened(context.Background(), criticalEpisode(900))
	require.NoError(t, err)
	require.Equal(t, int64(1), first)

	for range 3 {
		again, err := store.EnqueueHealthEpisodeOpened(context.Background(), criticalEpisode(900))
		require.NoError(t, err)
		assert.Zero(t, again, "a repeated enqueue for one episode and destination must not queue a second delivery")
	}
	assert.Len(t, allDeliveries(t, db), 1)

	// A DIFFERENT episode on the same destination is its own delivery: the key is per episode, not per destination.
	other, err := store.EnqueueHealthEpisodeOpened(context.Background(), criticalEpisode(901))
	require.NoError(t, err)
	assert.Equal(t, int64(1), other)
	assert.Len(t, allDeliveries(t, db), 2)
}

// spec:alert-webhook-delivery/host-health-episodes-are-delivered/a-delivery-names-exactly-one-subject
//
// TestWebhookDelivery_NamesExactlyOneSubject pins the check constraint. The store is written to set exactly one subject, but that is
// a property of today's callers; the schema is what keeps a future one from writing a row that names both an alert and an episode, or
// neither, which the delivery worker would send with no way to say what it describes.
func TestWebhookDelivery_NamesExactlyOneSubject(t *testing.T) {
	t.Parallel()
	store, db := newEnqueueStore(t)
	dest := makeDest(t, store, "dest", detapi.SeverityLow, true, detapi.WebhookEventHealthEpisodeOpened)
	alertID, _, err := store.InsertAlert(context.Background(), highAlert("subject-one"), nil)
	require.NoError(t, err)

	cases := []struct {
		name      string
		alertID   any
		episodeID any
	}{
		{"both an alert and an episode", alertID, int64(900)},
		{"neither an alert nor an episode", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.ExecContext(context.Background(), `
				INSERT INTO webhook_delivery (public_id, alert_id, health_episode_id, destination_id, event_type, dedup_key, payload)
				VALUES (UUID(), ?, ?, ?, 'x', ?, '{}')`, tc.alertID, tc.episodeID, dest, tc.name)
			require.Error(t, err, "the schema must refuse a delivery that does not name exactly one subject")
			assert.Contains(t, err.Error(), "chk_webhook_delivery_one_subject")
		})
	}
}

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// healthRule is a stub that declares itself a health signal and returns one finding carrying a health detail, which is the shape
// sensor_recovery_failed produces.
type healthRule struct {
	stubRule
	finding api.Finding
}

func (r *healthRule) NonDetectionKind() rulesapi.NonDetectionKind { return rulesapi.NonDetectionHealth }

func (r *healthRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.calls++
	return []api.Finding{r.finding}, nil
}

// projectionRule declares itself a projection: also a non-detection, but one whose findings still belong in the alert queue. It is
// here so the routing test can show the engine keys on the KIND rather than on "is it a non-detection".
type projectionRule struct {
	stubRule
	finding api.Finding
}

func (r *projectionRule) NonDetectionKind() rulesapi.NonDetectionKind {
	return rulesapi.NonDetectionProjection
}

func (r *projectionRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.calls++
	return []api.Finding{r.finding}, nil
}

// recordingRecorder captures what the engine asked to be recorded, and can fail on demand. It hands back a fixed episode id, the way
// the real store returns the existing row's id on a redelivery.
type recordingRecorder struct {
	episodes []endpointapi.HealthEpisode
	opened   bool
	id       int64
	err      error
}

func (r *recordingRecorder) OpenHealthEpisode(_ context.Context, e endpointapi.HealthEpisode) (int64, bool, error) {
	if r.err != nil {
		return 0, false, r.err
	}
	r.episodes = append(r.episodes, e)
	id := r.id
	if id == 0 {
		id = 77
	}
	return id, r.opened, nil
}

// recordingNotifier captures the deliveries the engine enqueued, and can fail the first N calls to model a failure between the
// episode write and the outbox write.
type recordingNotifier struct {
	deliveries []mysql.HealthEpisodeDelivery
	failFirst  int
	calls      int
}

func (n *recordingNotifier) EnqueueHealthEpisodeOpened(_ context.Context, d mysql.HealthEpisodeDelivery) (int64, error) {
	n.calls++
	if n.calls <= n.failFirst {
		return 0, errors.New("outbox unavailable")
	}
	n.deliveries = append(n.deliveries, d)
	return 1, nil
}

func healthFinding() api.Finding {
	detail, err := json.Marshal(endpointapi.SelfHealFailedDetail{Provider: "content_filter", Outcome: "enable_ineffective", Attempts: 5})
	if err != nil {
		panic(err)
	}
	return api.Finding{
		HostID:      "host-a",
		RuleID:      "sensor_recovery_failed",
		Severity:    api.SeverityCritical,
		Title:       "EDR sensor could not be restored",
		Description: "automatic recovery gave up on content_filter",
		Subject:     "sensor_recovery_failed:content_filter:e1",
		EventIDs:    []string{"e1"},
		Health: &api.HealthDetail{
			Kind:         endpointapi.KindSelfHealFailed,
			Component:    "network_extension",
			Subject:      "content_filter",
			OccurredAtNs: 4_242,
			Detail:       detail,
		},
	}
}

func healthBatch() []api.Event {
	return []api.Event{{EventID: "e1", HostID: "host-a", TimestampNs: 1, EventType: "exec", Platform: "darwin", Payload: []byte("{}")}}
}

// spec:server-detection-rules-engine/registered-rule-catalog/a-health-signal-is-recorded-as-an-episode-rather-than-an-alert
//
// TestEngine_HealthFindingIsRecordedNotAlerted is the routing contract of issue #778.
//
// The engine is built with a NIL store, and that is the load-bearing half of the assertion rather than a convenience. Persisting an
// alert dereferences the store, so a finding that took the alert path here would panic. The test therefore cannot pass while the
// finding still reaches the alerts table, which a test that only checked the recorder received something could.
func TestEngine_HealthFindingIsRecordedNotAlerted(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{opened: true}
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))

	require.Len(t, rec.episodes, 1)
	got := rec.episodes[0]
	assert.Equal(t, "host-a", got.HostID)
	assert.Equal(t, "network_extension", got.Component, "the component is what a later healthy report closes the episode against")
	assert.Equal(t, endpointapi.KindSelfHealFailed, got.Kind)
	assert.Equal(t, api.SeverityCritical, got.Severity, "the move to health must not quietly downgrade how urgent it is")
	assert.Equal(t, "EDR sensor could not be restored", got.Title)
	assert.Equal(t, "content_filter", got.Subject, "two providers under one extension must not collide on one episode")
	assert.Equal(t, "e1", got.SourceEventID,
		"the occurrence is the episode's identity, so a redelivery of this event collapses onto the record it already made")
	assert.Equal(t, int64(4_242), got.OpenedAtNs,
		"the episode opens on the HOST's clock, from the event: server time would measure queue backlog as part of the outage")

	// The fields rather than the prose: the surface that reads an episode filters on them.
	var detail endpointapi.SelfHealFailedDetail
	require.NoError(t, json.Unmarshal(got.Detail, &detail))
	assert.Equal(t, endpointapi.SelfHealFailedDetail{Provider: "content_filter", Outcome: "enable_ineffective", Attempts: 5}, detail)
}

// spec:server-detection-rules-engine/registered-rule-catalog/a-projection-is-still-an-alert
//
// TestEngine_ProjectionFindingStillTakesTheAlertPath shows the engine routes on the declared KIND and not on "is a non-detection".
// application_control_block is a projection and its findings belong in the queue an analyst works, so it must NOT be diverted.
//
// Asserted by the panic the nil store produces on the alert path, which is the same mechanism the test above relies on, read the
// other way: reaching it proves the finding was NOT handed to the recorder.
func TestEngine_ProjectionFindingStillTakesTheAlertPath(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{opened: true}
	finding := healthFinding()
	finding.Health = nil // a projection carries no health detail
	finding.RuleID = "application_control_block"
	rule := &projectionRule{stubRule: stubRule{id: "application_control_block"}, finding: finding}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	assert.Panics(t, func() { _ = evaluateErr(e, context.Background(), healthBatch()) },
		"a projection must still reach alert persistence, which a nil store cannot serve")
	assert.Empty(t, rec.episodes, "a projection is not a health episode")
}

// TestEngine_HealthFindingWithNoRecorderIsDropped pins the deliberate absence of a fallback. An engine wired without a recorder
// must record nothing rather than put the finding back in the alert queue: the reason it left is that it makes no claim about an
// adversary, and an unwired dependency does not make it one.
//
// The nil store again does the work: a fallback to the alert path would panic here.
func TestEngine_HealthFindingWithNoRecorderIsDropped(t *testing.T) {
	t.Parallel()
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	assert.NotPanics(t, func() {
		require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
	}, "an unwired recorder must drop the finding, not fall back to persisting an alert")
}

// TestEngine_HealthRecorderFailureIsReturned: a recorder that fails is a real failure, not a swallowed one. The batch is nacked and
// retried, which is what keeps a transient database error from silently losing the record of a host that is not capturing.
func TestEngine_HealthRecorderFailureIsReturned(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{err: errors.New("boom")}
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	err := evaluateErr(e, context.Background(), healthBatch())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sensor_recovery_failed", "the error must name the rule whose record was lost")
}

// TestEngine_RoutingFollowsTheDeclarationNotThePayload pins that the KIND the rule declares is what decides the destination.
//
// Both halves matter and they fail in opposite directions. A detection that sets the health field by mistake must still alert, or a
// typo would quietly empty an analyst's queue. A health rule that forgets the detail must NOT fall through to an alert, because its
// declaration is what says this makes no claim about an adversary; it is refused instead, since an episode with no kind could
// neither be filed nor ever resolve.
func TestEngine_RoutingFollowsTheDeclarationNotThePayload(t *testing.T) {
	t.Parallel()

	t.Run("a detection that sets the health field still alerts", func(t *testing.T) {
		t.Parallel()
		rec := &recordingRecorder{opened: true}
		// A plain stubRule declares no kind, so it is a detection whatever its finding carries.
		rule := &findingRule{stubRule: stubRule{id: "some_detection"}, finding: healthFinding()}
		e := New(nil, nil)
		e.SetHealthEpisodeRecorder(rec)
		e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

		assert.Panics(t, func() { _ = evaluateErr(e, context.Background(), healthBatch()) },
			"a rule that declares nothing is a detection and must reach alert persistence")
		assert.Empty(t, rec.episodes, "a finding does not become a health episode by carrying a health payload")
	})

	t.Run("a health rule that supplies no detail records nothing and does not alert", func(t *testing.T) {
		t.Parallel()
		rec := &recordingRecorder{opened: true}
		finding := healthFinding()
		finding.Health = nil
		rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: finding}
		e := New(nil, nil)
		e.SetHealthEpisodeRecorder(rec)
		e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

		assert.NotPanics(t, func() {
			require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
		}, "a health rule missing its detail must not fall back to the alert queue")
		assert.Empty(t, rec.episodes, "and must not record an episode that could never be filed or resolved")
	})
}

// findingRule returns one finding and declares no kind, so it is an ordinary detection.
type findingRule struct {
	stubRule
	finding api.Finding
}

func (r *findingRule) Evaluate(_ context.Context, _ []api.Event, _ rulesapi.GraphReader) ([]api.Finding, error) {
	r.calls++
	return []api.Finding{r.finding}, nil
}

// TestEngine_HealthRuleHonoursAnOperatorsMode: a health signal obeys a mode an operator set, like any other rule.
//
// An earlier cut routed on kind BEFORE the mode was acted on, reasoning that no setting could name a rule absent from the tunable
// catalog. UpsertRuleSetting does not validate its rule id against the registered set, so such a setting can exist, and ignoring it
// silently overrode a deliberate choice. Disabled records nothing; the nil store proves it did not become an alert either.
func TestEngine_HealthRuleHonoursAnOperatorsMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []rulesapi.DetectionRuleMode{rulesapi.DetectionRuleModeDisabled, rulesapi.DetectionRuleModeMonitor} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			rec := &recordingRecorder{opened: true}
			rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
			e := New(nil, nil)
			e.SetHealthEpisodeRecorder(rec)
			e.SetModeResolver(overridingResolver{mode: mode})
			e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

			require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
			assert.Empty(t, rec.episodes, "a rule an operator suppressed records nothing")
		})
	}
}

// TestEngine_HealthFindingCitingNoEventIsDropped: the occurrence is the identity, so a finding that cites no event cannot be
// recorded without losing the property that a redelivery collapses onto one record.
func TestEngine_HealthFindingCitingNoEventIsDropped(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{opened: true}
	finding := healthFinding()
	finding.EventIDs = nil
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: finding}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	assert.NotPanics(t, func() {
		require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
	})
	assert.Empty(t, rec.episodes, "an episode with no occurrence could be recorded twice by one redelivery")
}

// spec:alert-webhook-delivery/host-health-episodes-are-delivered/a-lost-enqueue-is-recovered-on-reprocessing-without-a-duplicate
//
// TestEngine_ALostHealthNotificationIsRecoveredOnRedelivery is the property that makes a cross-context dual write safe.
//
// The episode (endpoint) and its delivery (detection's outbox) cannot share a transaction, so the engine writes them in order and a
// failure between the two nacks the batch. The redelivery then finds the episode ALREADY recorded, so the recorder reports
// opened=false. The notification survives only if the engine enqueues on that duplicate too. An engine that enqueued solely on a
// fresh open would drop it here for good, which is the case the retry exists for.
func TestEngine_ALostHealthNotificationIsRecoveredOnRedelivery(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{opened: true, id: 501}
	notifier := &recordingNotifier{failFirst: 1}
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.setHealthNotifier(notifier)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	// First delivery: the episode records, the enqueue fails, and the batch must fail so the event comes back.
	require.Error(t, evaluateErr(e, context.Background(), healthBatch()),
		"a failed enqueue must fail the batch, or nothing redelivers the event and the notification is simply gone")
	require.Empty(t, notifier.deliveries)

	// Redelivery: the episode is now already recorded.
	rec.opened = false
	require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))

	require.Len(t, notifier.deliveries, 1, "the redelivery must enqueue the notification the first attempt lost")
	got := notifier.deliveries[0]
	assert.Equal(t, int64(501), got.EpisodeID, "keyed on the recorded episode, which is what makes the outbox collapse a repeat")
	assert.Equal(t, int64(501), got.Episode.ID)
	assert.Equal(t, "host-a", got.HostID)
	assert.Equal(t, api.SeverityCritical, got.Episode.Severity, "severity is what the destination's minimum filters on")
	assert.Equal(t, "content_filter", got.Episode.Subject)
	assert.Equal(t, int64(4_242), got.Episode.OpenedAt.UnixNano(), "the host's clock, not the enqueue time")
}

// TestEngine_ARedeliveryNotifiesAgainAndLetsTheOutboxCollapseIt: on an ordinary redelivery nothing failed the first time, and the
// engine still enqueues. That is intended, not waste: the engine cannot tell "the enqueue failed last time" from "it succeeded", and
// the outbox's idempotency key is what collapses the repeat. The store test proves the collapse; this proves the engine does not
// short-circuit around it.
func TestEngine_ARedeliveryNotifiesAgainAndLetsTheOutboxCollapseIt(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{opened: false, id: 502}
	notifier := &recordingNotifier{}
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(rec)
	e.setHealthNotifier(notifier)
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
	assert.Len(t, notifier.deliveries, 1, "a duplicate episode is still offered to the outbox, which is what dedups it")
}

// TestEngine_ASuppressedHealthRuleNotifiesNobody: a rule an operator disabled records nothing, so it must not notify either. A delivery
// about an episode that was never written would point a receiver at a record that does not exist.
func TestEngine_ASuppressedHealthRuleNotifiesNobody(t *testing.T) {
	t.Parallel()
	notifier := &recordingNotifier{}
	rule := &healthRule{stubRule: stubRule{id: "sensor_recovery_failed"}, finding: healthFinding()}
	e := New(nil, nil)
	e.SetHealthEpisodeRecorder(&recordingRecorder{opened: true})
	e.setHealthNotifier(notifier)
	e.SetModeResolver(overridingResolver{mode: rulesapi.DetectionRuleModeDisabled})
	e.LoadActive(stubProvider{rules: []rulesapi.Rule{rule}})

	require.NoError(t, evaluateErr(e, context.Background(), healthBatch()))
	assert.Empty(t, notifier.deliveries)
}

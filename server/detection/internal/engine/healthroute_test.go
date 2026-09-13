package engine

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
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

// recordingRecorder captures what the engine asked to be recorded, and can fail on demand.
type recordingRecorder struct {
	episodes []endpointapi.HealthEpisode
	opened   bool
	err      error
}

func (r *recordingRecorder) OpenHealthEpisode(_ context.Context, e endpointapi.HealthEpisode) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	r.episodes = append(r.episodes, e)
	return r.opened, nil
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

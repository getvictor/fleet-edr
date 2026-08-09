package sensorevent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type captured struct {
	eventType string
	payload   map[string]any
}

type recorder struct {
	events []captured
	err    error
}

func (r *recorder) emit(_ context.Context, eventType string, payload map[string]any) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, captured{eventType: eventType, payload: payload})
	return nil
}

func newTransitions(r *recorder) *Transitions {
	return New(r.emit, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func running(p string) map[string]string  { return map[string]string{p: StateRunning} }
func stoppedM(p string) map[string]string { return map[string]string{p: StateStopped} }

// spec:agent-status-reporting/transition-records-distinguish-a-fault-from-a-supported-configuration/reconnecting-does-not-manufacture-transitions
func TestFirstReportEstablishesABaselineWithoutEmitting(t *testing.T) {
	t.Parallel()
	// The extension re-publishes liveness on every handshake, so the first report after an agent restart or an XPC
	// reconnect describes state this process never observed CHANGING. Emitting there would manufacture a transition out of
	// a reconnect, and a tamper signal that fires on restarts is one operators learn to ignore.
	r := &recorder{}
	tr := newTransitions(r)
	assert.Empty(t, tr.Observe(context.Background(), stoppedM("content_filter"), map[string]int{"content_filter": 1}))
	assert.Empty(t, r.events)
}

// spec:agent-status-reporting/capture-provider-transitions-are-recorded-as-durable-events/a-provider-stopping-is-recorded
// spec:agent-status-reporting/transition-records-distinguish-a-fault-from-a-supported-configuration/a-stop-record-carries-the-platform-stop-reason
func TestStoppedTransitionEmitsWithTheRawStopReason(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, running("content_filter"), nil)
	assert.Equal(t, []string{"content_filter"},
		tr.Observe(ctx, stoppedM("content_filter"), map[string]int{"content_filter": 1}))

	require.Len(t, r.events, 1)
	assert.Equal(t, EventType, r.events[0].eventType)
	assert.Equal(t, "content_filter", r.events[0].payload["provider"])
	assert.Equal(t, StateStopped, r.events[0].payload["state"])
	// Carried unreduced so a detection consumer discriminates for itself rather than trusting a collapsed verdict.
	assert.Equal(t, 1, r.events[0].payload["stop_reason"])
}

// spec:agent-status-reporting/capture-provider-transitions-are-recorded-as-durable-events/a-repaired-stop-is-two-records-not-one-annotated-record
func TestRunningTransitionCarriesNoStopReason(t *testing.T) {
	t.Parallel()
	// The recovery half of the pair. A running event carrying the reason it stopped for previously would read as a live
	// fault to anything consuming the payload without cross-checking state.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, stoppedM("content_filter"), map[string]int{"content_filter": 1})
	tr.Observe(ctx, running("content_filter"), nil)

	require.Len(t, r.events, 1)
	assert.Equal(t, StateRunning, r.events[0].payload["state"])
	assert.NotContains(t, r.events[0].payload, "stop_reason")
}

// spec:agent-status-reporting/capture-provider-transitions-are-recorded-as-durable-events/an-unchanged-report-is-recorded-once
func TestRepeatedIdenticalReportsEmitOnce(t *testing.T) {
	t.Parallel()
	// Liveness is level-triggered and re-published on every handshake, so the same stop arrives many times. One stop is one
	// event; re-emitting per report would flood the queue and the alert surface from a single act.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, running("content_filter"), nil)
	for range 5 {
		tr.Observe(ctx, stoppedM("content_filter"), map[string]int{"content_filter": 1})
	}
	assert.Len(t, r.events, 1)
}

// spec:agent-status-reporting/transition-records-distinguish-a-fault-from-a-supported-configuration/a-deliberately-disabled-provider-is-not-recorded-as-a-fault
func TestAProviderGoingAbsentDoesNotEmit(t *testing.T) {
	t.Parallel()
	// #649 reports a deliberately disabled provider as ABSENT rather than stopped. That is a supported configuration, not a
	// fault, so it must never produce tamper evidence.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, map[string]string{"content_filter": StateRunning, "dns_proxy": StateRunning}, nil)
	assert.Empty(t, tr.Observe(ctx, running("content_filter"), nil), "the opt-in DNS proxy was turned off")
	assert.Empty(t, r.events)
}

func TestAProviderReappearingAfterAbsenceEmits(t *testing.T) {
	t.Parallel()
	// The baseline must drop an absent provider, or its later return reads as "no change" and the recovery is never
	// recorded.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, map[string]string{"content_filter": StateRunning, "dns_proxy": StateRunning}, nil)
	tr.Observe(ctx, running("content_filter"), nil) // dns_proxy absent
	assert.Equal(t, []string{"dns_proxy"},
		tr.Observe(ctx, map[string]string{"content_filter": StateRunning, "dns_proxy": StateRunning}, nil))
	require.Len(t, r.events, 1)
	assert.Equal(t, "dns_proxy", r.events[0].payload["provider"])
}

// spec:agent-status-reporting/a-transition-record-is-not-lost-to-a-transient-failure/a-failed-record-is-retried
func TestAFailedEmitIsRetriedOnTheNextReport(t *testing.T) {
	t.Parallel()
	// Losing the event to a transient queue error would lose the only durable record of the tamper, so the transition is
	// not marked observed until it is actually recorded.
	r := &recorder{err: errors.New("queue full")}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, running("content_filter"), nil)
	assert.Empty(t, tr.Observe(ctx, stoppedM("content_filter"), map[string]int{"content_filter": 1}))

	r.err = nil
	assert.Equal(t, []string{"content_filter"},
		tr.Observe(ctx, stoppedM("content_filter"), map[string]int{"content_filter": 1}))
	require.Len(t, r.events, 1)
	assert.Equal(t, StateStopped, r.events[0].payload["state"])
}

func TestMissingStopReasonsStillEmits(t *testing.T) {
	t.Parallel()
	// Version skew: an extension too old to send stop_reasons. The transition is still the evidence, so it must be
	// recorded rather than dropped for want of an optional attribute.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, running("content_filter"), nil)
	assert.Equal(t, []string{"content_filter"}, tr.Observe(ctx, stoppedM("content_filter"), nil))
	require.Len(t, r.events, 1)
	assert.NotContains(t, r.events[0].payload, "stop_reason")
}

func TestUnrecognisedStateIsNotEmitted(t *testing.T) {
	t.Parallel()
	// A state a newer extension introduced. Inventing an event whose meaning this build does not know is worse than
	// staying quiet.
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, running("content_filter"), nil)
	assert.Empty(t, tr.Observe(ctx, map[string]string{"content_filter": "wedged"}, nil))
	assert.Empty(t, r.events)
}

func TestNilEmitterIsInert(t *testing.T) {
	t.Parallel()
	tr := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Empty(t, tr.Observe(context.Background(), stoppedM("content_filter"), nil))
}

func TestBothProvidersTransitioningEmitInDeterministicOrder(t *testing.T) {
	t.Parallel()
	r := &recorder{}
	tr := newTransitions(r)
	ctx := context.Background()

	tr.Observe(ctx, map[string]string{"content_filter": StateRunning, "dns_proxy": StateRunning}, nil)
	got := tr.Observe(ctx,
		map[string]string{"content_filter": StateStopped, "dns_proxy": StateStopped},
		map[string]int{"content_filter": 1, "dns_proxy": 2})
	assert.Equal(t, []string{"content_filter", "dns_proxy"}, got, "map iteration order must not leak into the result")
	assert.Len(t, r.events, 2)
}

package catalog

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// execEventFor builds an exec event a Sigma-backed rule will look at.
func execEventFor(id string, pid int) api.Event {
	return api.Event{
		EventID: id, HostID: "h1", EventType: "exec", TimestampNs: 1,
		Payload: []byte(fmt.Sprintf(`{"pid":%d,"path":"/bin/sh","args":["sh","-c","echo hi"]}`, pid)),
	}
}

// graphCounter counts the reads a rule makes, so a test can assert on lookups rather than on timing.
type graphCounter struct {
	api.GraphReader
	reads int
	proc  *api.Process
}

func (g *graphCounter) GetProcessByPID(_ context.Context, _ string, pid int, _ int64) (*api.Process, error) {
	g.reads++
	if g.proc == nil {
		return nil, nil
	}
	copied := *g.proc
	copied.PID = pid
	return &copied, nil
}

// spec:server-detection-rules-engine/rules-evaluating-one-batch-derive-shared-work-once/one-event-is-decoded-once-however-many-rules-read-it
// TestSigmaEvent_DecodesEachEventOncePerBatch is the property issue #794 exists for.
//
// The engine hands every rule the raw batch, so before this each Sigma-backed rule decoded every event it looked at, and decoded it
// a second time to read the pid back out. Counting decodes rather than measuring time is the point: a benchmark tells you the cost
// moved, and this tells you it moved for the reason claimed and stays moved.
func TestSigmaEvent_DecodesEachEventOncePerBatch(t *testing.T) {
	t.Parallel()

	scope := &api.BatchScope{}
	gr := &graphCounter{}
	evt := execEventFor("e1", 7)

	// Ten rules looking at the same event, which is the shape the imported corpus produces.
	views := make([]*sigmaView, 0, 10)
	for range 10 {
		view, err := sigmaEvent(t.Context(), scope, evt, gr)
		require.NoError(t, err)
		require.NotNil(t, view)
		views = append(views, view)
	}

	shared := sigmaEventsFor(scope)
	assert.Len(t, shared.events, 1, "one event decoded once, however many rules asked for it")

	// Every view sees the same decoded fields and the same pid.
	for i, view := range views {
		values, ok := view.Event.Field("CommandLine")
		require.True(t, ok, "view %d lost the shared decode", i)
		assert.Equal(t, []string{"sh -c echo hi"}, values)
		assert.Equal(t, 7, view.PID, "the pid comes from the shared decode, not a second pass over the payload")
	}
}

// TestSigmaEvent_ReadsTheGraphOncePerEvent pins the half that costs more than the decode.
//
// Eleven rules in the imported corpus read ParentImage. Each resolving its own would issue its own pair of graph reads for the same
// event, which dwarfs the decode they were also each repeating.
func TestSigmaEvent_ReadsTheGraphOncePerEvent(t *testing.T) {
	t.Parallel()

	scope := &api.BatchScope{}
	gr := &graphCounter{proc: &api.Process{ID: 1, PPID: 500, Path: "/usr/bin/parent"}}
	evt := execEventFor("e1", 7)

	for range 5 {
		view, err := sigmaEvent(t.Context(), scope, evt, gr)
		require.NoError(t, err)
		require.NotNil(t, view)
		// Reading the field is what triggers resolution; the detections short-circuit, so a rule that never reads it pays nothing.
		_, _ = view.Event.Field("ParentImage")
	}

	assert.Equal(t, 2, gr.reads, "one child lookup and one parent lookup for the event, not one pair per rule")
}

// spec:server-detection-rules-engine/rules-evaluating-one-batch-derive-shared-work-once/a-failed-lookup-reaches-only-the-rule-that-asked-for-it
// TestSigmaEvent_ResolverErrorsDoNotCrossRules is why the views are copies rather than one shared adapter.
//
// ResolveErr is read per rule and a non-nil one discards that rule's findings for the WHOLE batch. Sharing one adapter would hand
// that loss to rules that never read the field, turning one rule's failed lookup into everyone's lost batch.
func TestSigmaEvent_ResolverErrorsDoNotCrossRules(t *testing.T) {
	t.Parallel()

	scope := &api.BatchScope{}
	gr := &failingGraphReader{}
	evt := execEventFor("e1", 7)

	asked, err := sigmaEvent(t.Context(), scope, evt, gr)
	require.NoError(t, err)
	require.NotNil(t, asked)
	silent, err := sigmaEvent(t.Context(), scope, evt, gr)
	require.NoError(t, err)
	require.NotNil(t, silent)

	_, _ = asked.Event.Field("ParentImage")

	require.Error(t, asked.Event.ResolveErr(), "the rule that read the field sees the failure")
	assert.NoError(t, silent.Event.ResolveErr(), "the rule that never read it keeps its batch")
}

// TestSigmaEvent_DistinctEventsGetDistinctAdaptations pins the memo key.
//
// Keying by event id rather than by index into the batch is required, not incidental: the engine scopes the batch per rule by
// platform, so two rules can be handed slices of different lengths over the same events.
func TestSigmaEvent_DistinctEventsGetDistinctAdaptations(t *testing.T) {
	t.Parallel()

	scope := &api.BatchScope{}
	gr := &graphCounter{}

	first, err := sigmaEvent(t.Context(), scope, execEventFor("e1", 7), gr)
	require.NoError(t, err)
	require.NotNil(t, first)
	second, err := sigmaEvent(t.Context(), scope, execEventFor("e2", 9), gr)
	require.NoError(t, err)
	require.NotNil(t, second)

	assert.Equal(t, 7, first.PID)
	assert.Equal(t, 9, second.PID, "a second event must not be served the first one's adaptation")
	assert.Len(t, sigmaEventsFor(scope).events, 2)
}

// TestSigmaEvent_APayloadWithNoPIDIsSkippedNotRaised pins that a malformed event costs the batch nothing.
func TestSigmaEvent_APayloadWithNoPIDIsSkippedNotRaised(t *testing.T) {
	t.Parallel()

	evt := api.Event{EventID: "e1", HostID: "h1", EventType: "exec", Payload: []byte(`{"path":"/bin/sh","args":["sh"]}`)}
	view, err := sigmaEvent(t.Context(), &api.BatchScope{}, evt, &graphCounter{})

	require.NoError(t, err, "a missing pid is an event to skip, not a reason to fail the rule's batch")
	assert.Nil(t, view)
}

// TestSigmaEvent_WithoutAScopeStillWorks pins that a direct caller does not have to build one.
//
// Evaluate takes this path, and the replay harness and every rule's own tests call Evaluate.
func TestSigmaEvent_WithoutAScopeStillWorks(t *testing.T) {
	t.Parallel()

	view, err := sigmaEvent(t.Context(), nil, execEventFor("e1", 7), &graphCounter{})
	require.NoError(t, err)
	require.NotNil(t, view)
	assert.Equal(t, 7, view.PID)
}

// failingGraphReader fails every lookup, so a test can tell which rules inherit the failure.
type failingGraphReader struct {
	api.GraphReader
}

func (failingGraphReader) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	return nil, assert.AnError
}

// BenchmarkSigmaEventPerRule measures what N Sigma-backed rules pay to look at one exec event, which is the arithmetic issue #794
// is about: the per-rule cost is what multiplies as the catalog fills with imported rules.
//
// The shared case is the whole batch's cost divided by the rules that looked at the event; the unshared case is what each rule paid
// before, and is kept as the comparison so the improvement is measured rather than asserted.
func BenchmarkSigmaEventPerRule(b *testing.B) {
	evt := execEventFor("e1", 7)
	gr := &graphCounter{}

	b.Run("shared across 10 rules", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			scope := &api.BatchScope{}
			for range 10 {
				if _, err := sigmaEvent(b.Context(), scope, evt, gr); err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("unshared, one scope per rule", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			for range 10 {
				if _, err := sigmaEvent(b.Context(), &api.BatchScope{}, evt, gr); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

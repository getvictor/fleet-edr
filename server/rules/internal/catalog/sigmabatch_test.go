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

	// Ten rules looking at the same event, which is the shape the imported corpus produces. After each call, the memo entry the
	// call went through is captured.
	//
	// Comparing the ENTRY POINTER is what actually counts decodes. Asserting the map holds one key does not: a memo that rebuilt
	// and overwrote the same key on every ask would leave exactly one entry while doing all the work this exists to avoid, so the
	// length check would pass the very regression it is named for. A counter installed AFTER these ten calls does not either, since
	// it can only observe the eleventh ask onward. A stable pointer across all ten says each of them was served the first build.
	views := make([]*sigmaView, 0, 10)
	entries := make([]*adaptedEvent, 0, 10)
	for range 10 {
		view := sigmaEvent(t.Context(), scope, evt, gr)
		require.NotNil(t, view)
		views = append(views, view)
		entries = append(entries, sigmaEventsFor(scope).events[evt.EventID])
	}
	for i, entry := range entries {
		assert.Same(t, entries[0], entry, "ask %d was served a rebuilt adaptation rather than the memoized one", i)
	}

	shared := sigmaEventsFor(scope)
	assert.Len(t, shared.events, 1, "and it is held under one key")

	// A DIFFERENT event still builds, exactly once, so the stability above is the memo working rather than nothing happening.
	builds := 0
	other := execEventFor("e-other", 11)
	for range 5 {
		shared.adapt(other, func() *adaptedEvent {
			builds++
			return buildAdapted(other, gr)
		})
	}
	assert.Equal(t, 1, builds, "a new event is built once and then served from the memo")

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
		view := sigmaEvent(t.Context(), scope, evt, gr)
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

	asked := sigmaEvent(t.Context(), scope, evt, gr)
	require.NotNil(t, asked)
	silent := sigmaEvent(t.Context(), scope, evt, gr)
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

	first := sigmaEvent(t.Context(), scope, execEventFor("e1", 7), gr)
	require.NotNil(t, first)
	second := sigmaEvent(t.Context(), scope, execEventFor("e2", 9), gr)
	require.NotNil(t, second)

	assert.Equal(t, 7, first.PID)
	assert.Equal(t, 9, second.PID, "a second event must not be served the first one's adaptation")
	assert.Len(t, sigmaEventsFor(scope).events, 2)
}

// TestSigmaEvent_APayloadWithNoPIDIsSkippedNotRaised pins that a malformed event costs the batch nothing.
func TestSigmaEvent_APayloadWithNoPIDIsSkippedNotRaised(t *testing.T) {
	t.Parallel()

	evt := api.Event{EventID: "e1", HostID: "h1", EventType: "exec", Payload: []byte(`{"path":"/bin/sh","args":["sh"]}`)}
	assert.Nil(t, sigmaEvent(t.Context(), &api.BatchScope{}, evt, &graphCounter{}))
}

// TestSigmaEvent_WithoutAScopeStillWorks pins that a direct caller does not have to build one.
//
// Evaluate takes this path, and the replay harness and every rule's own tests call Evaluate.
func TestSigmaEvent_WithoutAScopeStillWorks(t *testing.T) {
	t.Parallel()

	view := sigmaEvent(t.Context(), nil, execEventFor("e1", 7), &graphCounter{})
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
				if sigmaEvent(b.Context(), scope, evt, gr) == nil {
					b.Fatal("adaptation failed")
				}
			}
		}
	})

	b.Run("unshared, one scope per rule", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			for range 10 {
				if sigmaEvent(b.Context(), &api.BatchScope{}, evt, gr) == nil {
					b.Fatal("adaptation failed")
				}
			}
		}
	})
}

// TestSharedDecode_FindingDescriptionsAreUnchanged pins the operator-facing strings across the move to the shared adapter.
//
// Four rules used to read the path out of a payload struct of their own. Those structs existed only to re-read what the adapter had
// already decoded, so they are gone and the descriptions now read the same value from the shared decode. That is meant to be
// invisible to anyone reading an alert, and two of the four rules had no assertion on their description at all, so "invisible" was
// a claim rather than a fact. It is a fact here.
func TestSharedDecode_FindingDescriptionsAreUnchanged(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		rule  api.Rule
		event api.Event
		// writer is the process row the graph returns, which the description also names in one case.
		writer *api.Process
		// want is the WHOLE description, not a substring. The fixed operator-facing text around the path is part of what a reader
		// sees, so a reworded or reordered description is as much a change as a wrong path.
		want string
	}{
		{
			name:  "sudoers_tamper names the file that was opened",
			rule:  &SudoersTamper{},
			event: openEventFor("/etc/sudoers", 0x601),
			// TargetFilename is supplied only for a write-mode open, and the detection requires it, so it is present whenever
			// this rule fires. That is why reading the path back from the field is equivalent to reading the payload.
			writer: &api.Process{ID: 42, PID: 7, Path: "/usr/bin/vim"},
			want:   "/usr/bin/vim opened /etc/sudoers for writing: sudo escalation surface (MITRE T1548.003)",
		},
		{
			name:   "credential_keychain_dump names the binary that ran",
			rule:   &CredentialKeychainDump{},
			event:  keychainDumpEvent(),
			writer: &api.Process{ID: 43, PID: 7, Path: "/usr/bin/security"},
			want: `/usr/bin/security invoked with "dump-keychain": reads all Keychain entries ` +
				`(Keychain credential access, MITRE T1555.001)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gr := &graphCounter{proc: tc.writer}
			findings, err := tc.rule.Evaluate(t.Context(), []api.Event{tc.event}, gr)
			require.NoError(t, err)
			require.Len(t, findings, 1, "the rule must still fire on its own positive fixture")
			assert.Equal(t, tc.want, findings[0].Description,
				"the description reads the path from the shared decode and must be byte-identical to what it was")
		})
	}
}

// openEventFor builds a write-mode open of path, which is the shape sudoers_tamper acts on.
func openEventFor(path string, flags int) api.Event {
	return api.Event{
		EventID: "e-open", HostID: "h1", EventType: "open", TimestampNs: 1,
		Payload: []byte(fmt.Sprintf(`{"pid":7,"path":%q,"flags":%d}`, path, flags)),
	}
}

// keychainDumpEvent builds the `security dump-keychain` exec credential_keychain_dump fires on.
func keychainDumpEvent() api.Event {
	return api.Event{
		EventID: "e-exec", HostID: "h1", EventType: "exec", TimestampNs: 1,
		Payload: []byte(`{"pid":7,"path":"/usr/bin/security","args":["security","dump-keychain","-d"]}`),
	}
}

// TestSigmaEvent_AMalformedEventDoesNotDiscardTheBatch is a regression test for a behaviour I broke while sharing the adapter.
//
// Before the shared path, every Sigma-backed rule read the pid first and SKIPPED an event whose payload did not decode. Routing the
// decode through sigmaEvent made that failure an error instead, and an error from a rule's per-event evaluator is fatal: it
// discards the findings the rule had already collected from the rest of the batch. One type-invalid payload from one host would
// have silently cost every other alert in that batch, for every imported rule.
//
// The fix is that sigmaEvent reports no error at all. Skipping is what all six rules already did and what their comments already
// promised.
func TestSigmaEvent_AMalformedEventDoesNotDiscardTheBatch(t *testing.T) {
	t.Parallel()

	// A payload whose types are wrong, so json.Unmarshal fails rather than yielding a zero value.
	malformed := api.Event{EventID: "bad", HostID: "h1", EventType: "exec", TimestampNs: 1, Payload: []byte(`{"path":123}`)}
	good := keychainDumpEvent()

	assert.Nil(t, sigmaEvent(t.Context(), &api.BatchScope{}, malformed, &graphCounter{}),
		"an undecodable payload yields no view, and no error for a caller to treat as fatal")

	// End to end: the malformed event sits in front of the one that fires, which is the order that loses findings if it raises.
	gr := &graphCounter{proc: &api.Process{ID: 43, PID: 7, Path: "/usr/bin/security"}}
	findings, err := (&CredentialKeychainDump{}).Evaluate(t.Context(), []api.Event{malformed, good}, gr)

	require.NoError(t, err)
	assert.Len(t, findings, 1, "the malformed event is skipped and the rest of the batch still produces its findings")
}

// TestSigmaEvent_AFailedLookupIsMemoizedToo pins that a failing graph read is not retried by every later rule in the batch.
//
// Three reviewers raised this independently, and the reason it matters is not only load. Retrying means the rules in ONE batch can
// disagree about whether the same process exists: an early rule sees a failure and declines, a later one succeeds and fires. With
// the corpus registered that is 66 retries of a read that just failed, issued exactly when the database is least able to serve
// them. Nothing is cached beyond the batch, because a batch that hits a retryable miss is nacked and re-evaluated with a fresh
// scope.
func TestSigmaEvent_AFailedLookupIsMemoizedToo(t *testing.T) {
	t.Parallel()

	scope := &api.BatchScope{}
	gr := &countingFailure{}
	evt := execEventFor("e1", 7)

	var errs []error
	for range 5 {
		view := sigmaEvent(t.Context(), scope, evt, gr)
		require.NotNil(t, view)
		_, err := view.Subject()
		errs = append(errs, err)
	}

	assert.Equal(t, 1, gr.reads, "the failing read is issued once, not once per rule")
	for i, err := range errs {
		require.Error(t, err, "rule %d must see the failure rather than a silent success", i)
		assert.Equal(t, errs[0].Error(), err.Error(), "every rule in the batch gets the same answer")
	}
}

// countingFailure fails every lookup and counts how many were attempted.
type countingFailure struct {
	api.GraphReader
	reads int
}

func (g *countingFailure) GetProcessByPID(context.Context, string, int, int64) (*api.Process, error) {
	g.reads++
	return nil, assert.AnError
}

// TestSigmaEvent_LazyLookupsRunUnderTheAskingRulesContext pins which rule a deferred graph read is attributed to.
//
// The adaptation is built by whichever rule sees the event first, but the lookups are lazy, so the rule that TRIGGERS one is
// usually a different one. Capturing the builder's context would run the query under a span that has already ended, and MySQL is
// instrumented through otelsql, so the query would be traced against a rule that never asked for it.
func TestSigmaEvent_LazyLookupsRunUnderTheAskingRulesContext(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}
	scope := &api.BatchScope{}
	gr := &ctxRecordingGraph{}
	evt := execEventFor("e1", 7)

	// The first rule builds the adaptation and never reads the graph.
	building := context.WithValue(t.Context(), ctxKey{}, "first-rule")
	require.NotNil(t, sigmaEvent(building, scope, evt, gr))

	// A later rule triggers the lookup. Its context is the live one.
	asking := context.WithValue(t.Context(), ctxKey{}, "asking-rule")
	view := sigmaEvent(asking, scope, evt, gr)
	require.NotNil(t, view)
	_, err := view.Subject()
	require.NoError(t, err)

	require.NotNil(t, gr.seen)
	assert.Equal(t, "asking-rule", gr.seen.Value(ctxKey{}),
		"the query must run under the context of the rule that asked, whose span is live")
}

// ctxRecordingGraph records the context a lookup was performed with.
type ctxRecordingGraph struct {
	api.GraphReader
	seen context.Context //nolint:containedctx // recorded for assertion, never used to carry a deadline
}

func (g *ctxRecordingGraph) GetProcessByPID(ctx context.Context, _ string, pid int, _ int64) (*api.Process, error) {
	g.seen = ctx
	return &api.Process{ID: 1, PID: pid, Path: "/bin/sh"}, nil
}

package catalog

import (
	"maps"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
)

// loadFixtureEvents decodes one replay fixture's event batch.
func loadFixtureEvents(t *testing.T, path string) []detectionapi.Event {
	t.Helper()
	c, err := detectiontestkit.LoadFixture(path)
	require.NoError(t, err)
	require.NotEmpty(t, c.Events, "%s carries no events", path)
	return c.Events
}

// distinctEventTypes returns the event types a batch carries, which is what the engine dispatches on.
func distinctEventTypes(events []detectionapi.Event) []string {
	present := make([]string, 0, 4)
	for _, ev := range events {
		if !slices.Contains(present, ev.EventType) {
			present = append(present, ev.EventType)
		}
	}
	return present
}

// wouldDispatch mirrors the engine's decision: a rule is offered a batch when the batch carries a type it declares.
func wouldDispatch(declared, present []string) bool {
	for _, et := range declared {
		if slices.Contains(present, et) {
			return true
		}
	}
	return false
}

// spec:server-detection-rules-engine/a-rule-declares-the-event-types-it-consumes/a-rule-finds-nothing-in-a-batch-of-types-it-does-not-declare
//
// TestAll_ARuleThatFindsSomethingDeclaredTheBatchesEventType is the corpus equivalence gate for engine dispatch (issue #762).
//
// The engine invokes a rule only when the batch carries an event type it declares. Dispatch is therefore behaviour-preserving
// exactly when no rule can find something in a batch carrying none of its declared types, which is what this asserts over the real
// fixture corpus:
//
//	a rule produced findings from this batch  =>  the batch carried a type that rule declares
//
// Stated that way it needs no second engine run to compare against. Running the corpus twice, once dispatched and once not, would
// answer the same question less directly, since the only thing dispatch can change is whether a rule is invoked at all.
//
// This is the gate the issue asks for, and it is stronger than the synthetic tripwire in registry_test.go because the batches are
// real recorded telemetry with payloads that genuinely fire these rules, rather than payloads assembled to look incriminating.
func TestAll_ARuleThatFindsSomethingDeclaredTheBatchesEventType(t *testing.T) {
	t.Parallel()

	// Recursive, via the replay harness's own discovery: a one-level glob here let a fixture in a subdirectory be replayed and
	// counted as coverage while never reaching this gate.
	fixtures, err := detectiontestkit.FixturePaths("fixtures")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures, "no fixtures found, so this gate would prove nothing")

	rules := New(nil)
	require.NotEmpty(t, rules)

	// DERIVED from the catalog rather than written out, which issue #773 is what made possible: every rule now carries a positive
	// fixture, so the set this corpus exercises is exactly the set of registered rules. Asserting that equality says something
	// much stronger than the old hand-maintained list did, and says it without maintenance: EVERY rule fires somewhere in the
	// corpus, and any rule that stops firing fails here as well as in its own replay.
	//
	// A literal list was right while part of the catalog had no fixtures, because then the fired set was a genuine subset that a
	// reader needed spelling out. It is wrong now: it would be seventy-eight lines restating New(), and every future rule would
	// arrive as a two-place edit where one of the places is easy to forget.
	coveredByCorpus := make([]string, 0, len(rules))
	for _, r := range rules {
		coveredByCorpus = append(coveredByCorpus, r.ID())
	}
	slices.Sort(coveredByCorpus)

	var mu sync.Mutex
	fired := map[string]int{}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		got := slices.Sorted(maps.Keys(fired))
		assert.Equal(t, coveredByCorpus, got,
			"the set of rules this corpus exercises changed; if a fixture corpus was added, extend coveredByCorpus, and if one "+
				"stopped firing that is a regression in the rule, not in this list")
	})

	for _, path := range fixtures {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			t.Parallel()

			events := loadFixtureEvents(t, path)
			present := distinctEventTypes(events)

			ctx := t.Context()
			s := openCatalogStore(t)
			require.NoError(t, s.InsertEvents(ctx, events))
			require.NoError(t, s.ProcessBatch(ctx, events))

			for _, r := range rules {
				// The error is ignored deliberately: the engine already logs and swallows a rule-evaluation error, and a
				// finding is the only thing dispatch could drop.
				findings, _ := r.Evaluate(ctx, events, s.GraphReader())
				if len(findings) == 0 {
					continue
				}
				declared := r.Doc().EventTypes
				mu.Lock()
				fired[r.ID()] += len(findings)
				mu.Unlock()

				assert.True(t, wouldDispatch(declared, present),
					"rule %q produced %d finding(s) from a batch carrying %v, but declares only %v, so dispatch would have "+
						"skipped it and lost those findings", r.ID(), len(findings), present, declared)
			}
		})
	}
}

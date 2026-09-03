package engine

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// recordingRule records that it ran, and optionally blocks so a test can hold an Evaluate open mid-batch.
type recordingRule struct {
	typedRule
	mu      *sync.Mutex
	invoked *[]string
	started chan struct{}
	release chan struct{}
}

func (r *recordingRule) Evaluate(context.Context, []api.Event, rulesapi.GraphReader) ([]api.Finding, error) {
	r.mu.Lock()
	*r.invoked = append(*r.invoked, r.ID())
	r.mu.Unlock()
	if r.started != nil {
		close(r.started)
		<-r.release
	}
	return nil, nil
}

// spec:server-detection-rules-engine/replacing-the-active-rule-set-is-atomic/a-batch-evaluated-during-a-replacement-sees-one-consistent-rule-set
//
// TestEngine_Evaluate_HoldsOneRuleSetAcrossAReplacement drives Evaluate itself, which is the only way to test the property.
//
// The first version of this test loaded the snapshot itself and re-implemented Evaluate's dispatch-then-resolve sequence. It
// therefore proved that ruleSet is internally consistent and proved NOTHING about Evaluate, so it would have passed unchanged if
// Evaluate regressed to loading one set for its indices and another for the rules it invokes. That regression is the entire reason
// the snapshot exists.
//
// So this blocks inside the first rule of set A, swaps the active set to B while that Evaluate is in flight, releases it, and
// asserts the batch was evaluated against A throughout. Both failure modes are covered by asserting the exact invocation list: a
// re-read after the swap would invoke B's rule (wrong rule) or skip A's second rule (missed rule), and either changes the list.
//
// B declares the SAME event type as A on purpose. If it declared a different one, a regression would merely dispatch nothing after
// the swap and the test could pass for the wrong reason on an empty list.
func TestEngine_Evaluate_HoldsOneRuleSetAcrossAReplacement(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var invoked []string
	started := make(chan struct{})
	release := make(chan struct{})

	setA := []rulesapi.Rule{
		&recordingRule{
			typedRule: typedRule{stubRule: stubRule{id: "a1"}, eventTypes: []string{"exec"}},
			mu:        &mu, invoked: &invoked, started: started, release: release,
		},
		&recordingRule{
			typedRule: typedRule{stubRule: stubRule{id: "a2"}, eventTypes: []string{"exec"}},
			mu:        &mu, invoked: &invoked,
		},
	}
	setB := []rulesapi.Rule{
		&recordingRule{
			typedRule: typedRule{stubRule: stubRule{id: "b1"}, eventTypes: []string{"exec"}},
			mu:        &mu, invoked: &invoked,
		},
	}

	e := New(nil, nil)
	e.active.Store(newRuleSet(setA))

	var wg sync.WaitGroup
	wg.Go(func() {
		_, err := e.Evaluate(t.Context(), []api.Event{{EventID: "e1", HostID: "host-a", EventType: "exec"}})
		assert.NoError(t, err)
	})

	<-started                        // a1 is inside Evaluate, holding the batch open
	e.active.Store(newRuleSet(setB)) // the replacement lands mid-batch
	close(release)                   // let a1 finish
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"a1", "a2"}, invoked,
		"the batch must be evaluated against the set it started with: b1 appearing means Evaluate re-read the set, and a2 "+
			"missing means it re-read and then dispatched against B")
}

// TestRuleSet_ConcurrentSwapIsRaceFree is the memory-race half, and only that half.
//
// It does NOT exercise Evaluate (the test above does) and does not prove the single-view property. What it covers is the plain
// data race the old implementation had: `append(e.rules[:0], ...)` wrote into the backing array a concurrent reader was iterating.
// Reinstating that mutation produces data races here under -race; this implementation is clean.
//
// Both sets declare the same event type so the reader always has indices to check. The first version used sets with disjoint
// types, so half its iterations dispatched nothing and asserted nothing.
func TestRuleSet_ConcurrentSwapIsRaceFree(t *testing.T) {
	t.Parallel()

	three := []rulesapi.Rule{
		&typedRule{stubRule: stubRule{id: "exec_a"}, eventTypes: []string{"exec"}},
		&typedRule{stubRule: stubRule{id: "exec_b"}, eventTypes: []string{"exec"}},
		&typedRule{stubRule: stubRule{id: "exec_c"}, eventTypes: []string{"exec"}},
	}
	one := []rulesapi.Rule{
		&typedRule{stubRule: stubRule{id: "exec_only"}, eventTypes: []string{"exec"}},
	}

	e := New(nil, nil)
	e.active.Store(newRuleSet(three))
	batch := []api.Event{eventOfType("exec")}

	var wg sync.WaitGroup
	const rounds = 2000

	wg.Go(func() {
		for i := range rounds {
			if i%2 == 0 {
				e.active.Store(newRuleSet(one))
			} else {
				e.active.Store(newRuleSet(three))
			}
		}
	})

	for range 4 {
		wg.Go(func() {
			for range rounds {
				rs := e.active.Load()
				idx := rs.rulesFor(batch)
				require.NotEmpty(t, idx, "both sets declare exec, so every iteration must actually check something")
				for _, i := range idx {
					require.Less(t, i, len(rs.rules), "a dispatch index must be in range for the set it came from")
					assert.Equal(t, []string{"exec"}, rs.declaredTypes[i], "and must select a rule that set declared for exec")
				}
			}
		})
	}
	wg.Wait()
}

// spec:server-detection-rules-engine/replacing-the-active-rule-set-is-atomic/loading-the-active-set-repeatedly-does-not-duplicate-rules
//
// TestRuleSet_RepeatedLoadDoesNotDuplicate pins replace semantics, which the hot-reload caller in the next change depends on.
//
// LoadActive previously reused the backing array (`append(e.rules[:0], ...)`) partly to get this, so the property has to be
// re-established now that the set is rebuilt each time: a set loaded twice must evaluate each rule once, not twice.
func TestRuleSet_RepeatedLoadDoesNotDuplicate(t *testing.T) {
	t.Parallel()

	provider := staticRules{rules: []rulesapi.Rule{
		&typedRule{stubRule: stubRule{id: "exec_a"}, eventTypes: []string{"exec"}},
	}}
	e := New(nil, nil)

	e.LoadActive(provider)
	e.LoadActive(provider)
	e.LoadActive(provider)

	rs := e.active.Load()
	require.Len(t, rs.rules, 1, "three loads of one rule must leave one rule, not three")
	assert.Len(t, rs.rulesFor([]api.Event{eventOfType("exec")}), 1, "and it must be dispatched once per batch")
}

// TestRuleSet_MutatingTheProvidersSliceCannotReachTheActiveSet covers the copy in LoadActive.
//
// The provider hands over a slice it still owns. Without the copy, a provider that later rewrote its own slice (which the pack
// loader in the next change will do on every reload) would be writing into the set a concurrent Evaluate is holding.
func TestRuleSet_MutatingTheProvidersSliceCannotReachTheActiveSet(t *testing.T) {
	t.Parallel()

	owned := []rulesapi.Rule{&typedRule{stubRule: stubRule{id: "original"}, eventTypes: []string{"exec"}}}
	provider := staticRules{rules: owned}
	e := New(nil, nil)
	e.LoadActive(provider)

	owned[0] = &typedRule{stubRule: stubRule{id: "swapped_underneath"}, eventTypes: []string{"exec"}}

	assert.Equal(t, "original", e.active.Load().rules[0].ID(),
		"the active set must not alias a slice its provider still owns")
}

// staticRules is a minimal ActiveRules provider.
type staticRules struct{ rules []rulesapi.Rule }

func (s staticRules) ActiveRules() []rulesapi.Rule { return s.rules }

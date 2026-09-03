package engine

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// spec:server-detection-rules-engine/replacing-the-active-rule-set-is-atomic/a-batch-evaluated-during-a-replacement-sees-one-consistent-rule-set
//
// TestRuleSet_ReplacedWhileEvaluating is the test this whole change exists for.
//
// Before it, replacing the active set wrote four fields in sequence while Evaluate read them together: it picks indices out of
// dispatch and always, then uses those indices against rules and declaredTypes. A replacement landing between those reads hands
// an evaluation indices built for a set it is no longer holding, and the failure is not a crash. It is a WRONG evaluation: a rule
// invoked for a batch that does not carry its event types, or a rule skipped for one that does. `append(e.rules[:0], ...)` made it
// worse by writing into the very backing array a concurrent Evaluate was iterating.
//
// Two things are asserted, and the second is the one that matters. The race detector catches the memory race. It does NOT catch a
// consistent-but-mismatched view, so every index this returns is checked against the set it came from: a rule selected for a batch
// must actually declare one of that batch's event types, per THAT set.
//
// Run with -race to get both halves.
func TestRuleSet_ReplacedWhileEvaluating(t *testing.T) {
	t.Parallel()

	// Two sets with deliberately different shapes, so a torn or mismatched view is likely to produce an index that is either out
	// of range or selecting a rule which declares the wrong type.
	execOnly := []rulesapi.Rule{
		&typedRule{stubRule: stubRule{id: "exec_a"}, eventTypes: []string{"exec"}},
		&typedRule{stubRule: stubRule{id: "exec_b"}, eventTypes: []string{"exec"}},
		&typedRule{stubRule: stubRule{id: "exec_c"}, eventTypes: []string{"exec"}},
	}
	dnsOnly := []rulesapi.Rule{
		&typedRule{stubRule: stubRule{id: "dns_a"}, eventTypes: []string{"dns_query"}},
	}

	e := New(nil, nil)
	e.active.Store(newRuleSet(execOnly))
	batch := []api.Event{eventOfType("exec")}

	var wg sync.WaitGroup
	const rounds = 2000

	// Writer: swap between two differently shaped sets as fast as it can.
	wg.Go(func() {
		for i := range rounds {
			if i%2 == 0 {
				e.active.Store(newRuleSet(dnsOnly))
			} else {
				e.active.Store(newRuleSet(execOnly))
			}
		}
	})

	// Readers: dispatch and then resolve, exactly as Evaluate does, checking the two agree.
	for range 4 {
		wg.Go(func() {
			for range rounds {
				rs := e.active.Load()
				for _, i := range rs.rulesFor(batch) {
					require.Less(t, i, len(rs.rules), "a dispatch index must be in range for the set it came from")
					declared := rs.declaredTypes[i]
					require.Len(t, declared, 1, "these fixtures declare exactly one type each")
					assert.Equal(t, "exec", declared[0],
						"a rule selected for an exec batch must declare exec IN THE SET IT CAME FROM; anything else is a "+
							"mismatched view, which the race detector cannot see")
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

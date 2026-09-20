//go:build integration

// Concurrent rule changes to one policy must serialize, not deadlock (issue #1057).
//
// The store took row locks in two orders. The single-rule paths wrote or locked the RULE first and then bumped the parent
// policy's version; bulk upsert locked the POLICY first and then touched rules. Two writers in opposite orders each end up
// holding what the other needs, MySQL picks a victim and aborts it with error 1213, and the caller sees a 500.
//
// These tests drive the real store against a real MySQL, because the defect is in lock acquisition order and nothing below the
// database can show it. They are inherently probabilistic: an interleaving has to actually happen. The concurrency and repetition
// here are chosen so the pre-fix code fails reliably, which was checked by running them against it.
package appcontrol_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/sqlhelpers"
)

// deadlockConcurrency and deadlockRounds size the reproduction. Two writers are enough for the shapes below; more of them, over
// several rounds, is what makes the interleaving land often enough for the test to be dependable rather than lucky.
const (
	deadlockConcurrency = 8
	deadlockRounds      = 4
)

// binaryIdentifier is a distinct 64-character binary identifier, so concurrent creates collide on the POLICY rather than on the
// rules' unique key. A duplicate-key error would be a different failure and would mask the one under test.
func binaryIdentifier(n int) string {
	suffix := fmt.Sprintf("%04d", n)
	return strings.Repeat("a", 64-len(suffix)) + suffix
}

// requireNoDeadlock fails with the operation that hit it, since a deadlock reaches the operator as an unexplained 500.
func requireNoDeadlock(t *testing.T, op string, err error) {
	t.Helper()
	if err != nil && sqlhelpers.IsDeadlockErr(err) {
		t.Errorf("%s deadlocked (MySQL 1213), which reaches the caller as a 500: %v", op, err)
	}
}

// Two creates in one policy are the sharpest shape: the INSERT takes a SHARED lock on the parent policy row through the foreign
// key, and the version bump then needs an EXCLUSIVE one. Two of them each hold the shared lock the other must upgrade past.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/concurrent-rule-creates-do-not-deadlock
func TestConcurrentRuleCreatesDoNotDeadlock(t *testing.T) {
	t.Parallel()
	_, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for round := range deadlockRounds {
		for worker := range deadlockConcurrency {
			wg.Add(1)
			go func(round, worker int) {
				defer wg.Done()
				_, err := store.CreateRule(t.Context(), api.CreateRuleRequest{
					PolicyID:    policy.ID,
					RuleType:    api.RuleTypeBinary,
					Enforcement: api.EnforcementProtect,
					Identifier:  binaryIdentifier(round*deadlockConcurrency + worker),
					Severity:    api.SeverityRuleMedium,
					Actor:       "user:7",
					Reason:      "concurrent create",
				})
				requireNoDeadlock(t, "CreateRule", err)
			}(round, worker)
		}
		wg.Wait()
	}
}

// A single-rule update and a bulk upsert touching the same policy approach it from opposite ends: the update locks the rule then
// the policy, the bulk upsert locks the policy then the rules.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-single-rule-change-and-a-bulk-upsert-do-not-deadlock
func TestSingleRuleChangeAndBulkUpsertDoNotDeadlock(t *testing.T) {
	t.Parallel()
	_, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	// Seed the rules both writers contend over, so neither side is creating them during the race.
	ruleIDs := make([]int64, deadlockConcurrency)
	items := make([]api.BulkUpsertRuleItem, deadlockConcurrency)
	for i := range deadlockConcurrency {
		rule, cerr := store.CreateRule(t.Context(), api.CreateRuleRequest{
			PolicyID:    policy.ID,
			RuleType:    api.RuleTypeBinary,
			Enforcement: api.EnforcementProtect,
			Identifier:  binaryIdentifier(i),
			Severity:    api.SeverityRuleMedium,
			Actor:       "user:7",
			Reason:      "seed",
		})
		require.NoError(t, cerr)
		ruleIDs[i] = rule.ID
		items[i] = api.BulkUpsertRuleItem{
			RuleType:    api.RuleTypeBinary,
			Identifier:  binaryIdentifier(i),
			Enforcement: api.EnforcementProtect,
			Severity:    api.SeverityRuleHigh,
		}
	}

	for round := range deadlockRounds {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
				PolicyID: policy.ID,
				Items:    items,
				Actor:    "user:7",
				Reason:   "concurrent bulk upsert",
			})
			requireNoDeadlock(t, "BulkUpsertRules", err)
		}()
		for i := range deadlockConcurrency {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				comment := fmt.Sprintf("round %d", round)
				_, _, err := store.UpdateRule(t.Context(), api.UpdateRuleRequest{
					RuleID:  ruleIDs[i],
					Comment: &comment,
					Actor:   "user:7",
					Reason:  "concurrent update",
				})
				requireNoDeadlock(t, "UpdateRule", err)
			}(i)
		}
		wg.Wait()
	}
}

// Deletes against a bulk upsert, which is the shape that actually contends: two deletes alone take the same locks in the same
// order and merely queue, so racing them against the opposite order is what exercises the ordering.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-single-rule-change-and-a-bulk-upsert-do-not-deadlock
func TestRuleDeletesAgainstABulkUpsertDoNotDeadlock(t *testing.T) {
	t.Parallel()
	_, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	// The bulk upsert keeps re-inserting the keys the deletes remove, so both sides keep finding work across the rounds.
	items := make([]api.BulkUpsertRuleItem, deadlockConcurrency)
	for i := range deadlockConcurrency {
		items[i] = api.BulkUpsertRuleItem{
			RuleType:    api.RuleTypeBinary,
			Identifier:  binaryIdentifier(i),
			Enforcement: api.EnforcementProtect,
			Severity:    api.SeverityRuleMedium,
		}
	}

	for range deadlockRounds {
		// Seed the rules this round's deletes will remove.
		ids := make([]int64, 0, deadlockConcurrency)
		for i := range deadlockConcurrency {
			rule, cerr := store.CreateRule(t.Context(), api.CreateRuleRequest{
				PolicyID:    policy.ID,
				RuleType:    api.RuleTypeBinary,
				Enforcement: api.EnforcementProtect,
				Identifier:  binaryIdentifier(i),
				Severity:    api.SeverityRuleMedium,
				Actor:       "user:7",
				Reason:      "seed",
			})
			if cerr == nil {
				ids = append(ids, rule.ID)
				continue
			}
			// A rule the previous round's bulk upsert re-inserted is already there; delete that one instead.
			require.ErrorIs(t, cerr, api.ErrAppControlDuplicateRule)
			existing, lerr := store.ListRulesByPolicy(t.Context(), policy.ID)
			require.NoError(t, lerr)
			for _, r := range existing {
				if r.Identifier == binaryIdentifier(i) {
					ids = append(ids, r.ID)
					break
				}
			}
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
				PolicyID: policy.ID,
				Items:    items,
				Actor:    "user:7",
				Reason:   "concurrent bulk upsert",
			})
			requireNoDeadlock(t, "BulkUpsertRules", err)
		}()
		for _, id := range ids {
			wg.Add(1)
			go func(id int64) {
				defer wg.Done()
				_, err := store.DeleteRule(t.Context(), api.DeleteRuleRequest{
					RuleID: id,
					Actor:  "user:7",
					Reason: "concurrent delete",
				})
				// A rule the bulk upsert has not re-created may already be gone; that is not what this is watching for.
				requireNoDeadlock(t, "DeleteRule", err)
			}(id)
		}
		wg.Wait()
	}
}

// Deletes on their own, which must still all land.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/concurrent-rule-creates-do-not-deadlock
func TestConcurrentRuleDeletesDoNotDeadlock(t *testing.T) {
	t.Parallel()
	_, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	total := deadlockConcurrency * deadlockRounds
	ruleIDs := make([]int64, total)
	for i := range total {
		rule, cerr := store.CreateRule(t.Context(), api.CreateRuleRequest{
			PolicyID:    policy.ID,
			RuleType:    api.RuleTypeBinary,
			Enforcement: api.EnforcementProtect,
			Identifier:  binaryIdentifier(i),
			Severity:    api.SeverityRuleMedium,
			Actor:       "user:7",
			Reason:      "seed",
		})
		require.NoError(t, cerr)
		ruleIDs[i] = rule.ID
	}

	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.DeleteRule(t.Context(), api.DeleteRuleRequest{
				RuleID: ruleIDs[i],
				Actor:  "user:7",
				Reason: "concurrent delete",
			})
			requireNoDeadlock(t, "DeleteRule", err)
		}(i)
	}
	wg.Wait()

	remaining, err := store.ListRulesByPolicy(t.Context(), policy.ID)
	require.NoError(t, err)
	assert.Empty(t, remaining, "every delete has to have landed, not just avoided deadlocking")
}

// The policy lock predates the deadlock it now also prevents: it was added so two concurrent bulk upserts cannot both classify
// the same key as an insert, between the preflight that reads existing keys and the upsert that writes them. Nothing covered
// that, which a mutation run found while checking this change, so it is covered here rather than left asserted.
//
// Counted rather than timed: whichever upsert goes second must report the keys as updates, so across both runs each key is
// inserted exactly once.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-single-rule-change-and-a-bulk-upsert-do-not-deadlock
func TestConcurrentBulkUpsertsCountEachKeyInsertedOnce(t *testing.T) {
	t.Parallel()
	_, store, _, _ := newService(t)
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	items := make([]api.BulkUpsertRuleItem, deadlockConcurrency)
	for i := range deadlockConcurrency {
		items[i] = api.BulkUpsertRuleItem{
			RuleType:    api.RuleTypeBinary,
			Identifier:  binaryIdentifier(i),
			Enforcement: api.EnforcementProtect,
			Severity:    api.SeverityRuleMedium,
		}
	}

	var mu sync.Mutex
	var inserted, updated int
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
				PolicyID: policy.ID,
				Items:    items,
				Actor:    "user:7",
				Reason:   "concurrent bulk upsert",
			})
			requireNoDeadlock(t, "BulkUpsertRules", err)
			if err != nil {
				return
			}
			mu.Lock()
			inserted += res.Inserted
			updated += res.Updated
			mu.Unlock()
		}()
	}
	wg.Wait()

	assert.Equal(t, deadlockConcurrency, inserted,
		"each key exists once, so it can be reported inserted once: a higher total means both runs called the same key new")
	assert.Equal(t, deadlockConcurrency, updated, "and the run that went second reports them as updates")

	stored, err := store.ListRulesByPolicy(t.Context(), policy.ID)
	require.NoError(t, err)
	assert.Len(t, stored, deadlockConcurrency, "and the counts describe what is actually there")
}

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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

// policyLockWait is how long a rule change is given to acquire a policy another transaction is holding. Long enough that
// opening the transaction and reading the rule cannot themselves consume it on a loaded runner, short enough to pay once.
const policyLockWait = time.Second

// binaryIdentifier is a distinct 64-character binary identifier, so concurrent creates collide on the POLICY rather than on the
// rules' unique key. A duplicate-key error would be a different failure and would mask the one under test.
func binaryIdentifier(n int) string {
	suffix := fmt.Sprintf("%04d", n)
	return strings.Repeat("a", 64-len(suffix)) + suffix
}

// requireSucceeded fails on ANY error, naming a deadlock specially because that is the one under test and reaches the operator
// as an unexplained 500.
//
// Failing on every error is the point, and an earlier version of this that ignored all but 1213 was wrong: the operations here
// could have failed at setup, in the transaction, or on the SQL, and every test would still have passed while serialising
// nothing. A test that only checks the absence of one error cannot tell that from success.
func requireSucceeded(t *testing.T, op string, err error) {
	t.Helper()
	switch {
	case err == nil:
	case sqlhelpers.IsDeadlockErr(err):
		t.Errorf("%s deadlocked (MySQL 1213), which reaches the caller as a 500: %v", op, err)
	default:
		t.Errorf("%s failed: %v", op, err)
	}
}

// requireSucceededOrMissing is requireSucceeded where a concurrent writer may legitimately have removed the row first, which is
// an answer rather than a failure. Everything else, a deadlock included, still fails.
func requireSucceededOrMissing(t *testing.T, op string, err error) {
	t.Helper()
	if errors.Is(err, api.ErrAppControlRuleNotFound) {
		return
	}
	requireSucceeded(t, op, err)
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
				requireSucceeded(t, "CreateRule", err)
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
			requireSucceeded(t, "BulkUpsertRules", err)
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
				requireSucceeded(t, "UpdateRule", err)
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
			requireSucceeded(t, "BulkUpsertRules", err)
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
				// A rule the bulk upsert has not re-created may already be gone, which is an answer, not a failure.
				requireSucceededOrMissing(t, "DeleteRule", err)
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
			requireSucceeded(t, "DeleteRule", err)
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
			requireSucceeded(t, "BulkUpsertRules", err)
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

// A rule whose policy is deleted out from under it is reported MISSING, not as a server error.
//
// Locking the policy first introduced a way to learn about the deletion earlier than before: the rule's policy id is read
// without a lock, and a cascading DeletePolicy between that read and the lock leaves the lock finding no policy. The handler
// turns a missing RULE into a 404 and knows nothing about a missing policy, so reporting the policy there would give the
// operator a 500 for a rule that is, correctly, gone.
//
// The state is produced directly rather than raced for, because the foreign key cascades: at rest a rule cannot outlive its
// policy, and the window only exists inside the transaction. This is that window, held still.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-single-rule-change-and-a-bulk-upsert-do-not-deadlock
func TestARuleWhosePolicyVanishedIsReportedMissing(t *testing.T) {
	t.Parallel()
	_, store, db, _ := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) { return []string{"host-a"}, nil })
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	rule, err := store.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:    policy.ID,
		RuleType:    api.RuleTypeBinary,
		Enforcement: api.EnforcementProtect,
		Identifier:  binaryIdentifier(1),
		Severity:    api.SeverityRuleMedium,
		Actor:       "user:7",
		Reason:      "seed",
	})
	require.NoError(t, err)

	// Drop the policy while leaving its rule behind, which the cascade would otherwise prevent.
	_, err = db.ExecContext(t.Context(), `SET FOREIGN_KEY_CHECKS = 0`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `DELETE FROM app_control_policies WHERE id = ?`, policy.ID)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `SET FOREIGN_KEY_CHECKS = 1`)
	require.NoError(t, err)

	comment := "orphaned"
	_, _, updateErr := store.UpdateRule(t.Context(), api.UpdateRuleRequest{
		RuleID:  rule.ID,
		Comment: &comment,
		Actor:   "user:7",
		Reason:  "update an orphaned rule",
	})
	assert.ErrorIs(t, updateErr, api.ErrAppControlRuleNotFound,
		"the handler turns this into a 404; a policy-shaped error would reach the operator as a 500")

	_, deleteErr := store.DeleteRule(t.Context(), api.DeleteRuleRequest{
		RuleID: rule.ID,
		Actor:  "user:7",
		Reason: "delete an orphaned rule",
	})
	assert.ErrorIs(t, deleteErr, api.ErrAppControlRuleNotFound)
}

// A rule change WAITS for whoever holds the policy, which is what serialising per policy actually means.
//
// The other transaction holds the policy row for the whole test, so the delete cannot get past it and blocks until its context
// runs out. The elapsed time is the assertion that matters: it comes from the clock rather than from anything the store
// computes, so it cannot agree with a mistake in the store the way an error-value check could. Before the fix DeleteRule took no
// policy lock at all and returned promptly.
//
// The wait failing is then reported as the failure it is. A caller whose context expired has not learned that its rule is gone,
// and saying so would turn a busy policy into a phantom deletion in the operator's console.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-rule-change-waits-for-whoever-holds-the-policy
func TestARuleChangeWaitsForWhoeverHoldsThePolicy(t *testing.T) {
	t.Parallel()
	_, store, db, _ := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) { return []string{"host-a"}, nil })
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	rule, err := store.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:    policy.ID,
		RuleType:    api.RuleTypeBinary,
		Enforcement: api.EnforcementProtect,
		Identifier:  binaryIdentifier(1),
		Severity:    api.SeverityRuleMedium,
		Actor:       "user:7",
		Reason:      "seed",
	})
	require.NoError(t, err)

	holder, err := db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	var held int64
	require.NoError(t, holder.QueryRowxContext(t.Context(),
		`SELECT id FROM app_control_policies WHERE id = ? FOR UPDATE`, policy.ID).Scan(&held))

	started := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), policyLockWait)
	defer cancel()
	_, deleteErr := store.DeleteRule(ctx, api.DeleteRuleRequest{
		RuleID: rule.ID,
		Actor:  "user:7",
		Reason: "delete behind a held policy",
	})
	require.Error(t, deleteErr, "the delete cannot proceed while another writer holds the policy")
	assert.GreaterOrEqual(t, time.Since(started), policyLockWait, "and it failed by waiting for the policy, not by skipping it")
	assert.Contains(t, deleteErr.Error(), "lock policy", "the wait is where it failed")
	assert.NotErrorIs(t, deleteErr, api.ErrAppControlRuleNotFound, "the rule is still there; only the wait ran out")
}

// A database that does not answer is reported as a failure, not as a missing rule.
//
// The rule's policy id is read before the lock, and the two outcomes of that read are one `err != nil` apart in the code and a
// whole HTTP status apart for the operator: "no such rule" is an answer, "the database did not answer" is not. Collapsing them
// would tell an operator their rule had been deleted by someone else whenever the database was unwell.
//
// The table is taken away to produce the failure, which is what the seeder's own error-path tests do. The per-test database is
// discarded afterwards, so mutilating its schema costs nothing.
//
// spec:server-application-control/concurrent-rule-changes-to-one-policy-serialize/a-database-that-cannot-answer-is-not-a-missing-rule
func TestADatabaseFailureLookingUpTheRulesPolicyIsNotAMissingRule(t *testing.T) {
	t.Parallel()
	_, store, db, _ := newServiceWithHostsAndAudit(t, func(context.Context) ([]string, error) { return []string{"host-a"}, nil })
	policy, err := store.GetPolicyByName(t.Context(), "Default")
	require.NoError(t, err)

	rule, err := store.CreateRule(t.Context(), api.CreateRuleRequest{
		PolicyID:    policy.ID,
		RuleType:    api.RuleTypeBinary,
		Enforcement: api.EnforcementProtect,
		Identifier:  binaryIdentifier(1),
		Severity:    api.SeverityRuleMedium,
		Actor:       "user:7",
		Reason:      "seed",
	})
	require.NoError(t, err)

	// One pinned connection, because FOREIGN_KEY_CHECKS is a session setting and the pool is free to hand the drop a different
	// session than the one that turned the checks off.
	conn, err := db.Connx(t.Context())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(t.Context(), `SET FOREIGN_KEY_CHECKS = 0`)
	require.NoError(t, err)
	_, err = conn.ExecContext(t.Context(), `DROP TABLE app_control_rules`)
	require.NoError(t, err)

	_, deleteErr := store.DeleteRule(t.Context(), api.DeleteRuleRequest{
		RuleID: rule.ID,
		Actor:  "user:7",
		Reason: "delete against a broken schema",
	})
	require.Error(t, deleteErr)
	assert.NotErrorIs(t, deleteErr, api.ErrAppControlRuleNotFound,
		"a database that cannot answer has not said the rule is gone, and a 404 would claim it had")
	assert.Contains(t, deleteErr.Error(), "lookup rule's policy", "the failure names the read it came from")
}

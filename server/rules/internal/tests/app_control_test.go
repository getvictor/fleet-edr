//go:build integration

// Per-context integration tests for the Application Control subsystem.
// Skipped without EDR_TEST_DSN.

package tests

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// newAppControlStore wires the rules context against a fresh test DB and returns the store handle plus the *Rules so each test can
// re-apply the schema for idempotency checks.
func newAppControlStore(t *testing.T) (api.ApplicationControlStore, *rulesbootstrap.Rules) {
	t.Helper()
	db := full.Open(t)
	deps := rulesbootstrap.Deps{
		DB:     db,
		Logger: slog.Default(),
		AuthZ:  allowAllAuthZ{},
	}
	r, err := rulesbootstrap.New(deps)
	require.NoError(t, err)
	require.NoError(t, r.ApplySchema(t.Context()))
	return r.ApplicationControlStore(), r
}

// TestAppControl_SeedDefaultPolicy locks the bootstrap contract: a fresh deployment boots with one Default policy, version 1, zero
// rules, default_action='NONE'.
func TestAppControl_SeedDefaultPolicy(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	p, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, api.DefaultPolicyName, p.Name)
	assert.Equal(t, int64(1), p.Version)
	assert.Equal(t, api.PolicyDefaultActionNone, p.DefaultAction)
	assert.Equal(t, "system", p.CreatedBy)
	assert.Equal(t, "system", p.UpdatedBy)

	rules, err := store.ListRulesByPolicy(t.Context(), p.ID)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// TestAppControl_BootstrapIdempotent re-applies the schema and seed and confirms the policy count stays at one. Boot loops (e.g.
// cmd/main on restart) must not duplicate the seed row.
func TestAppControl_BootstrapIdempotent(t *testing.T) {
	t.Parallel()
	store, rules := newAppControlStore(t)

	require.NoError(t, rules.ApplySchema(t.Context()))
	require.NoError(t, rules.ApplySchema(t.Context()))

	policies, err := store.ListPolicies(t.Context())
	require.NoError(t, err)
	require.Len(t, policies, 1)
	assert.Equal(t, api.DefaultPolicyName, policies[0].Name)
}

// TestAppControl_GetPolicy_NotFound surfaces the typed sentinel that
// REST handlers map to HTTP 404.
func TestAppControl_GetPolicy_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	_, err := store.GetPolicyByName(t.Context(), "no-such-policy")
	require.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_CreateRule_BinaryHappyPath exercises the demo's critical write: an admin creates a BINARY rule, the row persists,
// the policy version bumps so the next agent poll picks up the change.
func TestAppControl_CreateRule_BinaryHappyPath(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()

	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	preVersion := p.Version

	msg := "Blocked by corporate policy"
	rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("a", 64),
		Severity:   api.SeverityRuleMedium,
		CustomMsg:  &msg,
		Actor:      "demo-admin",
		Reason:     "integration test",
	})
	require.NoError(t, err)
	assert.Equal(t, p.ID, rule.PolicyID)
	assert.Equal(t, api.RuleTypeBinary, rule.RuleType)
	assert.Equal(t, strings.Repeat("a", 64), rule.Identifier)
	assert.Equal(t, api.ActionBlock, rule.Action)
	assert.Equal(t, api.EnforcementProtect, rule.Enforcement)
	assert.True(t, rule.Enabled)
	assert.Equal(t, api.SeverityRuleMedium, rule.Severity)
	assert.Equal(t, api.SourceAdmin, rule.Source)
	if assert.NotNil(t, rule.CustomMsg) {
		assert.Equal(t, msg, *rule.CustomMsg)
	}
	assert.Equal(t, "demo-admin", rule.CreatedBy)

	// Policy version bumps so the next agent fan-out delivers the new
	// snapshot.
	pAfter, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, preVersion+1, pAfter.Version)
	assert.Equal(t, "demo-admin", pAfter.UpdatedBy)

	// The rule appears in the policy's rule list.
	listed, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, rule.ID, listed[0].ID)
}

// TestAppControl_CreateRule_DuplicateRejected confirms the unique key returns the typed sentinel rather than a bare driver error.
// The REST surface maps the sentinel to HTTP 409 so idempotent retries from automation clients are distinguishable from real failures.
func TestAppControl_CreateRule_DuplicateRejected(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	req := api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("b", 64),
		Actor:      "demo-admin",
		Reason:     "first create",
	}
	_, err = store.CreateRule(ctx, req)
	require.NoError(t, err)

	req.Reason = "second create (should collide)"
	_, err = store.CreateRule(ctx, req)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlDuplicateRule)
}

// TestAppControl_CreateRule_RejectsUnsupportedTypes pins the rule_type gate after the Phase A close-out: CDHASH / SIGNINGID / TEAMID
// are accepted (they pass through the validator and the unsupported-sentinel does not fire), while CERTIFICATE + PATH remain
// deferred and continue to surface ErrAppControlUnsupportedRuleType so the REST surface is honest about what's wired today.
// The Identifier per type is shape-valid so the format check passes; the test isolates the rule_type gate from the identifier gate.
func TestAppControl_CreateRule_RejectsUnsupportedTypes(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	for _, tc := range []struct {
		rt         api.RuleType
		identifier string
	}{
		{api.RuleTypeCertificate, strings.Repeat("c", 64)},
		{api.RuleTypePath, "/usr/bin/ls"},
	} {
		t.Run(string(tc.rt), func(t *testing.T) {
			_, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID:   p.ID,
				RuleType:   tc.rt,
				Identifier: tc.identifier,
				Actor:      "demo-admin",
				Reason:     "should be rejected as unsupported",
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrAppControlUnsupportedRuleType)
		})
	}
}

// TestAppControl_CreateRule_AcceptsCDHashSigningIDTeamID is the positive companion to the unsupported-types test. CDHASH /
// SIGNINGID / TEAMID rules MUST round-trip the validator + store + schema after the Phase A close-out — a deferred enum value
// in the schema or a regressed validator would otherwise silently break creating these rule types via the REST handler.
func TestAppControl_CreateRule_AcceptsCDHashSigningIDTeamID(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	cases := []struct {
		rt         api.RuleType
		identifier string
	}{
		{api.RuleTypeCDHash, strings.Repeat("a", 40)},
		{api.RuleTypeSigningID, "EQHXZ8M8AV:com.google.Chrome"},
		{api.RuleTypeSigningID, "platform:com.apple.curl"},
		{api.RuleTypeTeamID, "EQHXZ8M8AV"},
	}
	for _, tc := range cases {
		t.Run(string(tc.rt)+"/"+tc.identifier, func(t *testing.T) {
			rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID:   p.ID,
				RuleType:   tc.rt,
				Identifier: tc.identifier,
				Actor:      "demo-admin",
				Reason:     "phase A acceptance",
			})
			require.NoError(t, err)
			assert.NotZero(t, rule.ID)
			assert.Equal(t, tc.rt, rule.RuleType)
			assert.Equal(t, tc.identifier, rule.Identifier)
			assert.Equal(t, api.ActionBlock, rule.Action)
			assert.True(t, rule.Enabled)
		})
	}
}

// TestAppControl_ListHostGroupsForPolicy_SeededDefault pins the Phase A bootstrap contract: EnsureDefaultPolicy must seed a Default
// policy AND an all-hosts host group AND an assignment between them, and ListHostGroupsForPolicy must return that group. A regression
// in any of those three rows would otherwise silently break the fan-out path (no assignment -> no_assignments skip).
func TestAppControl_ListHostGroupsForPolicy_SeededDefault(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	groups, err := store.ListHostGroupsForPolicy(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, groups, 1, "Default policy must have exactly one seeded host-group assignment")
	assert.Equal(t, api.DefaultHostGroupName, groups[0].Name)
	assert.JSONEq(t, `{"type":"all"}`, string(groups[0].Criteria), "seed criteria must be the all-hosts shape")
}

// TestAppControl_CreateRule_RejectsBadBinaryIdentifier covers the negative half of the BINARY validator at the store level. The store
// path is what the REST handler and any automation client both go through, so this is the gate that protects the database.
func TestAppControl_CreateRule_RejectsBadBinaryIdentifier(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	cases := []struct {
		name string
		id   string
	}{
		{"too short", strings.Repeat("a", 63)},
		{"too long", strings.Repeat("a", 65)},
		{"uppercase", strings.Repeat("A", 64)},
		{"non-hex char", strings.Repeat("g", 64)},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID:   p.ID,
				RuleType:   api.RuleTypeBinary,
				Identifier: tc.id,
				Actor:      "demo-admin",
				Reason:     "should be rejected",
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrAppControlInvalidIdentifier)
		})
	}
}

// TestAppControl_CreateRule_RequiresActorAndReason locks in the auditability contract: a state-changing call without an actor or
// reason is rejected up front, not silently attributed to "system".
func TestAppControl_CreateRule_RequiresActorAndReason(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	base := api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("f", 64),
		Actor:      "demo-admin",
		Reason:     "valid baseline",
	}

	missingActor := base
	missingActor.Actor = "   "
	_, err = store.CreateRule(ctx, missingActor)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)

	missingReason := base
	missingReason.Reason = ""
	_, err = store.CreateRule(ctx, missingReason)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
}

// TestAppControl_CreateRule_UnknownPolicyMapsToNotFound covers the FK-violation path: a CreateRule that names a non-existent policy
// must surface ErrAppControlPolicyNotFound so the REST surface can answer 404, not 500.
func TestAppControl_CreateRule_UnknownPolicyMapsToNotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	_, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   9_999_999,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("e", 64),
		Actor:      "demo-admin",
		Reason:     "should hit FK constraint",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_CreateRule_AtomicityOnVersionBumpFailure covers the transactional contract: if the post-insert version-bump fails,
// the rule MUST NOT remain in the table (we lose the audit trail of "version moved" otherwise, and the agent never sees the new rule).
// Drives the failure by deleting the policy row out from under an in-flight transaction-attempt; this exercises the same atomicity
// guarantee CodeRabbit asked for on the original review.
func TestAppControl_CreateRule_AtomicityOnVersionBumpFailure(t *testing.T) {
	t.Parallel()
	store, rules := newAppControlStore(t)
	ctx := t.Context()
	_ = rules
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	// Happy path first so we know the rule WOULD insert.
	_, err = store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("d", 64),
		Actor:      "demo-admin",
		Reason:     "atomicity baseline",
	})
	require.NoError(t, err)
	// Re-insert the same row with a non-existent policy id; the FK fires before the version bump, so the transaction rolls back cleanly
	// and no orphan row lands.
	_, err = store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID + 1_000_000,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("c", 64),
		Actor:      "demo-admin",
		Reason:     "should rollback cleanly",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
	// The original policy's rules list still has only the baseline rule.
	rulesList, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, rulesList, 1)
}

// TestAppControl_UpdateRule_HappyPath confirms PATCH /rules/{id} applies the partial update and bumps the policy version. We
// flip Enabled, change Severity, set CustomMsg + Comment, and assert the post-update row reflects every field.
func TestAppControl_UpdateRule_HappyPath(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: strings.Repeat("d", 64),
		Severity:   api.SeverityRuleMedium,
		Actor:      "demo-admin",
		Reason:     "fixture for update",
	})
	require.NoError(t, err)
	preVersion := p.Version + 1 // create bumped once

	enabled := false
	sev := api.SeverityRuleHigh
	msg := "Blocked by policy v2"
	comment := "raised severity after incident review"
	updated, err := store.UpdateRule(ctx, api.UpdateRuleRequest{
		RuleID:    rule.ID,
		Enabled:   &enabled,
		Severity:  &sev,
		CustomMsg: &msg,
		Comment:   &comment,
		Actor:     "demo-admin",
		Reason:    "PATCH coverage",
	})
	require.NoError(t, err)
	assert.False(t, updated.Enabled, "enabled flips off")
	assert.Equal(t, api.SeverityRuleHigh, updated.Severity)
	if assert.NotNil(t, updated.CustomMsg) {
		assert.Equal(t, msg, *updated.CustomMsg)
	}
	assert.Equal(t, comment, updated.Comment)

	// Policy version bumped to (preVersion + 1).
	pAfter, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, preVersion+1, pAfter.Version)
}

// TestAppControl_UpdateRule_NotFound pins the typed sentinel for a missing rule id; the REST handler maps it to 404.
func TestAppControl_UpdateRule_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	enabled := false
	_, err := store.UpdateRule(t.Context(), api.UpdateRuleRequest{
		RuleID:  9_999_999,
		Enabled: &enabled,
		Actor:   "demo-admin",
		Reason:  "should be 404",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlRuleNotFound)
}

// TestAppControl_UpdateRule_RequiresAtLeastOneField confirms a body with reason but no mutable field is rejected as
// ErrAppControlInvalidRequest. Without this the handler would happily run an UPDATE that bumps version + updated_by with no
// other side effect, which is a confusing no-op the audit log can't disambiguate.
func TestAppControl_UpdateRule_RequiresAtLeastOneField(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: p.ID, RuleType: api.RuleTypeBinary,
		Identifier: strings.Repeat("e", 64), Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)

	_, err = store.UpdateRule(ctx, api.UpdateRuleRequest{
		RuleID: rule.ID, Actor: "demo-admin", Reason: "no fields",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
}

// TestAppControl_DeleteRule_HappyPath pins the delete + version-bump contract: the rule is gone from ListRulesByPolicy, and
// the returned policy_id matches the rule's parent so the service-layer fan-out targets the right policy.
func TestAppControl_DeleteRule_HappyPath(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: p.ID, RuleType: api.RuleTypeBinary,
		Identifier: strings.Repeat("f", 64), Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)

	policyID, err := store.DeleteRule(ctx, api.DeleteRuleRequest{
		RuleID: rule.ID, Actor: "demo-admin", Reason: "remove after triage",
	})
	require.NoError(t, err)
	assert.Equal(t, p.ID, policyID)

	rules, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, rules, "rule list must be empty after delete")
}

// TestAppControl_DeleteRule_NotFound confirms the typed sentinel for a stale rule id.
func TestAppControl_DeleteRule_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	_, err := store.DeleteRule(t.Context(), api.DeleteRuleRequest{
		RuleID: 9_999_999, Actor: "demo-admin", Reason: "stale id",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlRuleNotFound)
}

// TestAppControl_CreatePolicy_HappyPath confirms POST /policies inserts a new row with version=1, default_action='NONE', and the
// supplied name + description.
func TestAppControl_CreatePolicy_HappyPath(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	policy, err := store.CreatePolicy(t.Context(), api.CreatePolicyRequest{
		Name:        "engineering-laptops",
		Description: "Custom policy for the eng laptop fleet",
		Actor:       "demo-admin",
		Reason:      "second policy",
	})
	require.NoError(t, err)
	assert.NotZero(t, policy.ID)
	assert.Equal(t, "engineering-laptops", policy.Name)
	assert.Equal(t, "Custom policy for the eng laptop fleet", policy.Description)
	assert.Equal(t, int64(1), policy.Version)
	assert.Equal(t, api.PolicyDefaultActionNone, policy.DefaultAction)
	assert.Equal(t, "demo-admin", policy.CreatedBy)
}

// TestAppControl_CreatePolicy_DuplicateName confirms ErrAppControlDuplicatePolicy fires on a name collision. The seed Default
// policy gives us a guaranteed collision target.
func TestAppControl_CreatePolicy_DuplicateName(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	_, err := store.CreatePolicy(t.Context(), api.CreatePolicyRequest{
		Name: api.DefaultPolicyName, Actor: "demo-admin", Reason: "should collide",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlDuplicatePolicy)
}

// TestAppControl_UpdatePolicy_RenameAndBumpVersion confirms PATCH /policies/{id} renames the policy AND bumps the version. The
// version bump matters because Phase B's UI will use it as a "dirty" indicator on the agents tab.
func TestAppControl_UpdatePolicy_RenameAndBumpVersion(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	policy, err := store.CreatePolicy(ctx, api.CreatePolicyRequest{
		Name: "team-alpha", Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)

	newName := "team-alpha-renamed"
	newDescription := "team alpha rebrand"
	updated, err := store.UpdatePolicy(ctx, api.UpdatePolicyRequest{
		PolicyID:    policy.ID,
		Name:        &newName,
		Description: &newDescription,
		Actor:       "demo-admin",
		Reason:      "rename and edit description",
	})
	require.NoError(t, err)
	assert.Equal(t, newName, updated.Name)
	assert.Equal(t, newDescription, updated.Description)
	assert.Equal(t, policy.Version+1, updated.Version)
	assert.Equal(t, "demo-admin", updated.UpdatedBy)
}

// TestAppControl_UpdatePolicy_NotFound + DuplicateName lock the two error sentinels the REST handler maps to 404 and 409.
func TestAppControl_UpdatePolicy_NotFoundAndDuplicate(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	defaultPolicy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	// Not found.
	name := "doesnt-matter"
	_, err = store.UpdatePolicy(ctx, api.UpdatePolicyRequest{
		PolicyID: 9_999_999, Name: &name, Actor: "demo-admin", Reason: "404",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)

	// Duplicate name (rename a fresh policy to the Default policy's name).
	other, err := store.CreatePolicy(ctx, api.CreatePolicyRequest{
		Name: "fresh", Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)
	collidingName := defaultPolicy.Name
	_, err = store.UpdatePolicy(ctx, api.UpdatePolicyRequest{
		PolicyID: other.ID, Name: &collidingName, Actor: "demo-admin", Reason: "should 409",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlDuplicatePolicy)
}

// TestAppControl_DeletePolicy_HappyPath + TestAppControl_DeletePolicy_RefusesDefault enforce the destructive-action contract: a
// custom policy deletes cleanly and cascades its rules; the seed Default policy is rejected with ErrAppControlPolicyImmutable.
func TestAppControl_DeletePolicy_HappyPath(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	policy, err := store.CreatePolicy(ctx, api.CreatePolicyRequest{
		Name: "to-be-deleted", Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)
	// Add a rule so we can confirm the CASCADE.
	_, err = store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: policy.ID, RuleType: api.RuleTypeBinary,
		Identifier: strings.Repeat("9", 64), Actor: "demo-admin", Reason: "fixture",
	})
	require.NoError(t, err)

	require.NoError(t, store.DeletePolicy(ctx, api.DeletePolicyRequest{
		PolicyID: policy.ID, Actor: "demo-admin", Reason: "cleanup",
	}))

	// Policy is gone.
	_, err = store.GetPolicyByName(ctx, "to-be-deleted")
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_DeletePolicy_RefusesDefault locks the failsafe guard: an admin cannot rip the seed policy out from under the
// agents by accident. The handler maps the typed sentinel to HTTP 409.
func TestAppControl_DeletePolicy_RefusesDefault(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	policy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	err = store.DeletePolicy(ctx, api.DeletePolicyRequest{
		PolicyID: policy.ID, Actor: "demo-admin", Reason: "should be blocked",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyImmutable)
}

// TestAppControl_DeletePolicy_NotFound confirms the typed sentinel for an unknown id.
func TestAppControl_DeletePolicy_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	err := store.DeletePolicy(t.Context(), api.DeletePolicyRequest{
		PolicyID: 9_999_999, Actor: "demo-admin", Reason: "stale id",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

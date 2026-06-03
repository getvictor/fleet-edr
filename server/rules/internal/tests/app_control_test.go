//go:build integration

// Per-context integration tests for the Application Control subsystem.
// Skipped without EDR_TEST_DSN.

package tests

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

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

// spec:server-application-control/policy-is-a-named-versioned-ruleset/a-fresh-deployment-boots-and-the-seed-policy-is-present
//
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

// spec:server-application-control/bootstrap-seeds-default-policy-and-all-hosts-group/bootstrap-is-idempotent
//
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

	// The spec scenario "bootstrap is idempotent" requires the host-group, policy, AND assignment counts to all remain at one
	// across repeated ApplySchema calls; assert all three so a regression that re-seeds the all-hosts group or the
	// Default -> all-hosts assignment on every boot is caught here, not just policy duplication.
	groups, err := store.ListHostGroups(t.Context())
	require.NoError(t, err)
	require.Len(t, groups, 1, "all-hosts host group count must stay at one across repeated bootstraps")
	assert.Equal(t, api.DefaultHostGroupName, groups[0].Name)

	assignments, err := store.ListAssignmentsForPolicy(t.Context(), policies[0].ID)
	require.NoError(t, err)
	assert.Len(t, assignments, 1, "Default -> all-hosts assignment count must stay at one across repeated bootstraps")
}

// TestAppControl_GetPolicy_NotFound surfaces the typed sentinel that
// REST handlers map to HTTP 404.
func TestAppControl_GetPolicy_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	_, err := store.GetPolicyByName(t.Context(), "no-such-policy")
	require.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_GetPolicyByID_ReturnsSeededDefault locks the by-id lookup contract: the seeded Default policy is reachable by
// its primary key with the same row shape GetPolicyByName returns. The snapshot composer + DeletePolicy paths both depend on
// this returning the row without a ListPolicies scan.
func TestAppControl_GetPolicyByID_ReturnsSeededDefault(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	byName, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)

	byID, err := store.GetPolicyByID(t.Context(), byName.ID)
	require.NoError(t, err)
	assert.Equal(t, byName.ID, byID.ID)
	assert.Equal(t, byName.Name, byID.Name)
	assert.Equal(t, byName.Version, byID.Version)
	assert.Equal(t, byName.DefaultAction, byID.DefaultAction)
	assert.Equal(t, byName.CreatedBy, byID.CreatedBy)
	assert.Equal(t, byName.UpdatedBy, byID.UpdatedBy)
	assert.Empty(t, byID.Rules, "GetPolicyByID must not populate rules; callers fetch them separately")
}

// TestAppControl_GetPolicyByID_NotFound surfaces the typed sentinel for the snapshot composer + DeletePolicy lookup paths so
// the REST handler maps a missing policy id to HTTP 404 rather than a generic 500.
func TestAppControl_GetPolicyByID_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	_, err := store.GetPolicyByID(t.Context(), 99_999_999)
	require.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_ListRulesAcrossPolicies_FilterDimensions seeds two policies with mixed rules and pins the
// cross-policy GET /rules contract per filter dimension + the intersection + pagination edges. Drives the Store-level method
// directly; the REST handler's query-param parsing is covered separately by appcontrol_rest_test.go.
func TestAppControl_ListRulesAcrossPolicies_FilterDimensions(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()

	defaultPolicy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	// Two extra policies + a mix of rule_types / severities / enabled states across all three so each filter dimension
	// has something to narrow on.
	otherName := fmt.Sprintf("other-policy-%d", time.Now().UnixNano())
	otherPolicy, err := store.CreatePolicy(ctx, api.CreatePolicyRequest{
		Name: otherName, Description: "secondary policy for cross-policy list test",
		Actor: "demo-admin", Reason: "integration test setup",
	})
	require.NoError(t, err)

	// Every seeded rule is enabled=true by CreateRule's default; the enabled tri-state filter is exercised by the sibling
	// TestAppControl_ListRulesAcrossPolicies_EnabledTriState test which calls UpdateRule to flip a row.
	rulesToSeed := []struct {
		policyID   int64
		ruleType   api.RuleType
		identifier string
		severity   api.Severity
	}{
		{defaultPolicy.ID, api.RuleTypeBinary, strings.Repeat("a", 64), api.SeverityRuleHigh},
		{defaultPolicy.ID, api.RuleTypeBinary, strings.Repeat("b", 64), api.SeverityRuleMedium},
		{defaultPolicy.ID, api.RuleTypeCDHash, strings.Repeat("c", 40), api.SeverityRuleHigh},
		{defaultPolicy.ID, api.RuleTypeTeamID, "EQHXZ8M8AV", api.SeverityRuleMedium},
		{otherPolicy.ID, api.RuleTypeBinary, strings.Repeat("d", 64), api.SeverityRuleCritical},
		{otherPolicy.ID, api.RuleTypeCDHash, strings.Repeat("e", 40), api.SeverityRuleLow},
	}
	for _, r := range rulesToSeed {
		_, err := store.CreateRule(ctx, api.CreateRuleRequest{
			PolicyID: r.policyID, RuleType: r.ruleType, Identifier: r.identifier,
			Severity: r.severity, Actor: "demo-admin", Reason: "seed",
		})
		require.NoError(t, err)
	}

	// Empty filter -> every seeded rule (6) plus any rules already on the seed Default. Total is at least 6.
	all, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, all.Total, 6, "empty filter must surface every seeded rule")

	// PolicyID narrows to one policy.
	byPolicy, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{PolicyID: &otherPolicy.ID})
	require.NoError(t, err)
	assert.Equal(t, 2, byPolicy.Total)
	for _, r := range byPolicy.Rules {
		assert.Equal(t, otherPolicy.ID, r.PolicyID)
	}

	// RuleType=BINARY across all policies surfaces 3 rules (2 Default + 1 other).
	byType, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{RuleType: api.RuleTypeBinary})
	require.NoError(t, err)
	assert.Equal(t, 3, byType.Total)
	for _, r := range byType.Rules {
		assert.Equal(t, api.RuleTypeBinary, r.RuleType)
	}

	// Severity=high narrows to 2 rules (Default's BINARY high + Default's CDHASH high).
	bySev, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{Severity: api.SeverityRuleHigh})
	require.NoError(t, err)
	assert.Equal(t, 2, bySev.Total)

	// Intersection: policy + type narrows to exactly 1 (otherPolicy's single BINARY rule).
	both, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{
		PolicyID: &otherPolicy.ID, RuleType: api.RuleTypeBinary,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, both.Total)
	assert.Equal(t, otherPolicy.ID, both.Rules[0].PolicyID)
	assert.Equal(t, api.RuleTypeBinary, both.Rules[0].RuleType)

	// Pagination: Limit=2 returns 2 rows but Total still reflects the unfiltered count.
	page, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, all.Total, page.Total, "Total must ignore Limit/Offset")
	assert.Len(t, page.Rules, 2)

	// Limit auto-clamped to default when 0; auto-clamped to max when oversized.
	defaultLimit, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{Limit: 0})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(defaultLimit.Rules), api.DefaultListRulesAcrossPoliciesLimit)
	overLimit, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{
		Limit: api.MaxListRulesAcrossPoliciesLimit + 1000,
	})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(overLimit.Rules), api.MaxListRulesAcrossPoliciesLimit)
}

// TestAppControl_ListRulesAcrossPolicies_EnabledTriState pins the bool-pointer semantics: nil = both states, &true = only
// enabled, &false = only disabled. A regression that defaults Enabled=true would silently filter out half the result set.
func TestAppControl_ListRulesAcrossPolicies_EnabledTriState(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	defaultPolicy, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	enabledRule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: defaultPolicy.ID, RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("f", 64),
		Severity: api.SeverityRuleHigh, Actor: "demo-admin", Reason: "seed enabled",
	})
	require.NoError(t, err)
	disabledRule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: defaultPolicy.ID, RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("9", 64),
		Severity: api.SeverityRuleHigh, Actor: "demo-admin", Reason: "seed disabled",
	})
	require.NoError(t, err)
	// Flip disabledRule to disabled via UpdateRule (CreateRule always inserts enabled=true).
	disabledFlag := false
	_, err = store.UpdateRule(ctx, api.UpdateRuleRequest{
		RuleID: disabledRule.ID, Enabled: &disabledFlag,
		Actor: "demo-admin", Reason: "disable for filter test",
	})
	require.NoError(t, err)

	enabledOnly, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{
		PolicyID: &defaultPolicy.ID, Enabled: ptrBool(true),
	})
	require.NoError(t, err)
	for _, r := range enabledOnly.Rules {
		assert.True(t, r.Enabled, "Enabled=&true must filter to enabled rules only")
	}
	ids := make([]int64, 0, len(enabledOnly.Rules))
	for _, r := range enabledOnly.Rules {
		ids = append(ids, r.ID)
	}
	assert.Contains(t, ids, enabledRule.ID)
	assert.NotContains(t, ids, disabledRule.ID)

	disabledOnly, err := store.ListRulesAcrossPolicies(ctx, api.ListRulesAcrossPoliciesRequest{
		PolicyID: &defaultPolicy.ID, Enabled: ptrBool(false),
	})
	require.NoError(t, err)
	for _, r := range disabledOnly.Rules {
		assert.False(t, r.Enabled, "Enabled=&false must filter to disabled rules only")
	}
}

func ptrBool(b bool) *bool { return &b }

// spec:server-application-control/policy-is-a-named-versioned-ruleset/creating-a-rule-increments-the-policy-version
//
// TestAppControl_CreateRule_BinaryHappyPath exercises the demo's critical write: an admin creates a BINARY rule, the row persists,
// the policy version bumps so the next agent poll picks up the change. Pins the spec scenario "creating a rule increments the
// policy version": post-create the policy version is preVersion+1 and updated_by reflects the actor.
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

// spec:server-application-control/rule-identifies-one-binary-signing-identity-or-path/duplicating-the-same-rule-type-identifier-is-rejected
//
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

// spec:server-application-control/rule-identifies-one-binary-signing-identity-or-path/two-rules-in-the-same-policy-can-target-the-same-identifier-under-different-types
//
// TestAppControl_CreateRule_SameIdentifierDifferentTypeCoexist pins the spec scenario "two rules in the same policy can target
// the same identifier under different types": the unique key is the triple (policy_id, rule_type, identifier), so the SAME
// identifier string under two distinct rule_types must both persist without tripping ErrAppControlDuplicateRule. BINARY and
// CERTIFICATE share the 64-lowercase-hex identifier format, so a single hex string is valid under both types and is the honest
// way to exercise the "rule_type is part of the key" invariant with two genuinely-accepted identifiers.
func TestAppControl_CreateRule_SameIdentifierDifferentTypeCoexist(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	sharedIdentifier := strings.Repeat("a", 64) // valid for both BINARY and CERTIFICATE

	binaryRule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeBinary,
		Identifier: sharedIdentifier,
		Actor:      "demo-admin",
		Reason:     "binary rule for shared identifier",
	})
	require.NoError(t, err)

	// Same identifier string, different rule_type: must succeed because the unique key includes rule_type.
	certRule, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleTypeCertificate,
		Identifier: sharedIdentifier,
		Actor:      "demo-admin",
		Reason:     "certificate rule for the same identifier",
	})
	require.NoError(t, err, "same identifier under a different rule_type must NOT collide on the unique key")

	assert.NotEqual(t, binaryRule.ID, certRule.ID, "the two rules are distinct rows")
	assert.Equal(t, api.RuleTypeBinary, binaryRule.RuleType)
	assert.Equal(t, api.RuleTypeCertificate, certRule.RuleType)
	assert.Equal(t, sharedIdentifier, binaryRule.Identifier)
	assert.Equal(t, sharedIdentifier, certRule.Identifier)

	listed, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, listed, 2, "both rules coexist on the same policy")
}

// spec:server-admin-surface/persist-and-fan-out-application-control-rules/unsupported-rule-type-is-rejected-without-persisting
//
// TestAppControl_CreateRule_RejectsUnknownRuleType pins the rule_type gate for tokens that are not on the wire enum. After the
// Phase B close-out (PR for #210) every named enum value -- BINARY, CDHASH, SIGNINGID, CERTIFICATE, TEAMID, PATH -- is wired,
// so the only way to fall through to the gate is to submit a token the validator does not recognise. The store must reject
// without persisting and surface ErrAppControlInvalidRuleType (not the retired ErrAppControlUnsupportedRuleType, which is reserved
// for the future case where a value is added to the enum before the extension supports it).
func TestAppControl_CreateRule_RejectsUnknownRuleType(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	// Snapshot the rule count before the rejected create so the assertion below pins the "no persistence on rejected
	// rule_type" contract from openspec/specs/server-admin-surface/spec.md. CodeRabbit minor on PR #290: without this,
	// a regression that ignored the validator's error and persisted the row anyway would still pass the test.
	rulesBefore, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	_, err = store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID:   p.ID,
		RuleType:   api.RuleType("BANANA"),
		Identifier: strings.Repeat("a", 64),
		Actor:      "demo-admin",
		Reason:     "unknown token should be rejected",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRuleType)
	rulesAfter, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Len(t, rulesAfter, len(rulesBefore), "rejected rule_type must not persist a row")
}

// spec:server-application-control/identifier-validation-per-rule-type/a-path-is-canonicalized-before-persistence
//
// TestAppControl_CreateRule_PathPersistsCanonical pins the canonicalization-on-persist contract Gemini surfaced on PR #290.
// An operator who creates a PATH rule for `/tmp/foo` MUST see `/private/tmp/foo` round-trip from the store; the extension's
// AUTH_EXEC walker queries against the canonical form, so persisting the raw `/tmp/foo` would silently make every such rule
// a no-op against the dev VM's actual exec targets.
func TestAppControl_CreateRule_PathPersistsCanonical(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"slash-tmp rewritten to /private/tmp", "/tmp/canonical-tmp-target", "/private/tmp/canonical-tmp-target"},
		{"slash-var rewritten to /private/var", "/var/db/canonical-var-target", "/private/var/db/canonical-var-target"},
		{"already-canonical /private path passes through", "/private/etc/canonical-private-target", "/private/etc/canonical-private-target"},
		{"non-symlink path passes through", "/usr/bin/canonical-usr-target", "/usr/bin/canonical-usr-target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID:   p.ID,
				RuleType:   api.RuleTypePath,
				Identifier: tc.in,
				Actor:      "demo-admin",
				Reason:     "PR #290 path canonical persist",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, rule.Identifier)
		})
	}
}

// TestAppControl_CreateRule_AcceptsAllWiredTypes is the positive companion to the unknown-type test. Every rule type on the
// wire enum MUST round-trip the validator + store + schema. A regression that re-introduced ErrAppControlUnsupportedRuleType
// for CERTIFICATE / PATH (or that broke any other type's validator) would silently break creating these rule types via the
// REST handler.
func TestAppControl_CreateRule_AcceptsAllWiredTypes(t *testing.T) {
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
		{api.RuleTypeCertificate, strings.Repeat("c", 64)},
		{api.RuleTypePath, "/Applications/Foo.app/Contents/MacOS/Foo"},
	}
	for _, tc := range cases {
		t.Run(string(tc.rt)+"/"+tc.identifier, func(t *testing.T) {
			rule, err := store.CreateRule(ctx, api.CreateRuleRequest{
				PolicyID:   p.ID,
				RuleType:   tc.rt,
				Identifier: tc.identifier,
				Actor:      "demo-admin",
				Reason:     "all-wired acceptance",
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

// spec:server-application-control/host-groups-and-policy-assignments/a-fresh-deployment-has-an-all-hosts-group-and-the-default-policy-is-assigned-to-it
//
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

// spec:server-admin-surface/persist-and-fan-out-application-control-rules/missing-actor-or-reason-is-rejected
//
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

// spec:server-application-control/policy-is-a-named-versioned-ruleset/two-policies-cannot-share-a-name
//
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

// TestAppControl_BulkUpsertRules_HappyPath_MixedInsertAndUpdate covers the canonical batch flow: 2 brand-new rules + 1 row that
// already exists on the policy + a different identifier shape per type. The result counts must reflect insert vs update
// correctly; the post-upsert row set must reflect the overwritten severity on the pre-existing row.
func TestAppControl_BulkUpsertRules_HappyPath_MixedInsertAndUpdate(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	// Seed one BINARY rule with severity=medium so we can verify the upsert overwrites to high in the batch below.
	preSeed, err := store.CreateRule(ctx, api.CreateRuleRequest{
		PolicyID: p.ID, RuleType: api.RuleTypeBinary,
		Identifier: strings.Repeat("a", 64), Severity: api.SeverityRuleMedium,
		Actor: "demo-admin", Reason: "pre-seed",
	})
	require.NoError(t, err)
	preVersion, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)

	result, err := store.BulkUpsertRules(ctx, api.BulkUpsertRulesRequest{
		PolicyID: p.ID,
		Items: []api.BulkUpsertRuleItem{
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("a", 64), Severity: api.SeverityRuleHigh},
			{RuleType: api.RuleTypeCDHash, Identifier: strings.Repeat("b", 40), Severity: api.SeverityRuleMedium},
			{RuleType: api.RuleTypeTeamID, Identifier: "EQHXZ8M8AV", Severity: api.SeverityRuleMedium},
		},
		Actor:  "demo-admin",
		Reason: "Q1 intel feed import",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Inserted, "CDHASH + TEAMID are brand-new")
	assert.Equal(t, 1, result.Updated, "BINARY row pre-existed; severity gets overwritten")
	require.Len(t, result.Rules, 3, "result carries the post-upsert row for every requested item")

	// The pre-existing BINARY row keeps its id but the severity is overwritten.
	assert.Equal(t, preSeed.ID, result.Rules[0].ID)
	assert.Equal(t, api.SeverityRuleHigh, result.Rules[0].Severity)

	// Policy version bumps exactly once for the whole batch.
	pAfter, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	assert.Equal(t, preVersion.Version+1, pAfter.Version, "bulk upsert bumps policy version exactly once")
}

// TestAppControl_BulkUpsertRules_Idempotent confirms a re-run with the same payload produces 0 inserts + N updates and the
// same final row set. The audit log would show two separate bulk_upsert rows but each with the same post-upsert state.
// spec:server-application-control/rest-surface-for-policies-rules-groups-and-assignments/a-bulk-upsert-is-idempotent-on-the-unique-key
func TestAppControl_BulkUpsertRules_Idempotent(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	batch := api.BulkUpsertRulesRequest{
		PolicyID: p.ID,
		Items: []api.BulkUpsertRuleItem{
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("c", 64), Severity: api.SeverityRuleMedium},
			{RuleType: api.RuleTypeCDHash, Identifier: strings.Repeat("d", 40), Severity: api.SeverityRuleMedium},
		},
		Actor: "demo-admin", Reason: "first import",
	}

	first, err := store.BulkUpsertRules(ctx, batch)
	require.NoError(t, err)
	assert.Equal(t, 2, first.Inserted)
	assert.Equal(t, 0, first.Updated)

	batch.Reason = "re-running, expect idempotent"
	second, err := store.BulkUpsertRules(ctx, batch)
	require.NoError(t, err)
	assert.Equal(t, 0, second.Inserted)
	assert.Equal(t, 2, second.Updated, "every key already existed; the upsert overwrites without changing fields")
	// Row ids stay the same across the two upserts.
	assert.Equal(t, first.Rules[0].ID, second.Rules[0].ID)
	assert.Equal(t, first.Rules[1].ID, second.Rules[1].ID)
}

// TestAppControl_BulkUpsertRules_BadItemRejectsBatch confirms the all-or-nothing contract: one bad rule rejects the whole
// batch and NO rows are persisted. Without this contract, a paste-many of 100 lines with one typo would leave the operator
// with a half-imported state.
func TestAppControl_BulkUpsertRules_BadItemRejectsBatch(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	ctx := t.Context()
	p, err := store.GetPolicyByName(ctx, api.DefaultPolicyName)
	require.NoError(t, err)
	preRules, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	preCount := len(preRules)

	_, err = store.BulkUpsertRules(ctx, api.BulkUpsertRulesRequest{
		PolicyID: p.ID,
		Items: []api.BulkUpsertRuleItem{
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("e", 64), Severity: api.SeverityRuleMedium},
			{RuleType: api.RuleTypeBinary, Identifier: "TOO-SHORT", Severity: api.SeverityRuleMedium},
			{RuleType: api.RuleTypeTeamID, Identifier: "EQHXZ8M8AV", Severity: api.SeverityRuleMedium},
		},
		Actor: "demo-admin", Reason: "should fail atomically",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidIdentifier)
	assert.True(t, api.IsApplicationControlValidationError(err), "the wrapped error must still match the validation sentinel set")

	// No rows from the batch landed.
	postRules, err := store.ListRulesByPolicy(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, preCount, len(postRules), "all-or-nothing: the valid rules in the batch must NOT have persisted")
}

// TestAppControl_BulkUpsertRules_EmptyBatchRejected covers the empty-input guard. An empty Items slice is operator confusion
// (paste with no content); reject as ErrAppControlInvalidRequest so the REST handler returns 400 instead of silently no-op'ing.
// Both shapes pinned: a nil slice AND an empty non-nil slice (CodeRabbit on PR #190 — Go treats them differently for some
// reflection paths, so locking both keeps the contract honest).
func TestAppControl_BulkUpsertRules_EmptyBatchRejected(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	p, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		items []api.BulkUpsertRuleItem
	}{
		{"nil slice", nil},
		{"empty slice", []api.BulkUpsertRuleItem{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
				PolicyID: p.ID, Items: tc.items, Actor: "demo-admin", Reason: "empty",
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
		})
	}
}

// TestAppControl_BulkUpsertRules_DuplicateKeyInBatch rejects a batch with the same (rule_type, identifier) twice. Without this
// guard, the second occurrence would be classified as Insert (it's not in the pre-batch state) which corrupts the audit row's
// rules_inserted count. CodeRabbit on PR #190 surfaced this as a real correctness bug.
func TestAppControl_BulkUpsertRules_DuplicateKeyInBatch(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	p, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	_, err = store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
		PolicyID: p.ID,
		Items: []api.BulkUpsertRuleItem{
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("7", 64), Severity: api.SeverityRuleMedium},
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("7", 64), Severity: api.SeverityRuleHigh},
		},
		Actor: "demo-admin", Reason: "should reject the duplicate",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
	assert.Contains(t, err.Error(), "duplicates the (rule_type, identifier) of item 0")
}

// TestAppControl_BulkUpsertRules_BatchSizeCap confirms MaxBulkUpsertItems is enforced. 501 items must be rejected before any
// db round-trip so a hostile or buggy client can't tie up the txn for minutes.
func TestAppControl_BulkUpsertRules_BatchSizeCap(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	p, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	items := make([]api.BulkUpsertRuleItem, api.MaxBulkUpsertItems+1)
	for i := range items {
		items[i] = api.BulkUpsertRuleItem{
			RuleType:   api.RuleTypeBinary,
			Identifier: strings.Repeat("0", 60) + fmt.Sprintf("%04d", i),
			Severity:   api.SeverityRuleMedium,
		}
	}
	_, err = store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
		PolicyID: p.ID, Items: items, Actor: "demo-admin", Reason: "oversized",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlInvalidRequest)
}

// TestAppControl_BulkUpsertRules_UnknownPolicyMapsToNotFound exercises the FK violation path: a bulk-upsert against a stale
// policy id must surface ErrAppControlPolicyNotFound so the REST handler maps to 404 instead of leaking a generic 500.
func TestAppControl_BulkUpsertRules_UnknownPolicyMapsToNotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	_, err := store.BulkUpsertRules(t.Context(), api.BulkUpsertRulesRequest{
		PolicyID: 9_999_999,
		Items: []api.BulkUpsertRuleItem{
			{RuleType: api.RuleTypeBinary, Identifier: strings.Repeat("f", 64), Severity: api.SeverityRuleMedium},
		},
		Actor: "demo-admin", Reason: "stale policy id",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrAppControlPolicyNotFound)
}

// TestAppControl_ListHostGroups_SurfacesSeedAllHosts: the bootstrap seeds the `all-hosts` group; the list method must return it.
// Phase A always has exactly one row; this test pins that contract so a regression where the seed got skipped surfaces.
func TestAppControl_ListHostGroups_SurfacesSeedAllHosts(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)

	groups, err := store.ListHostGroups(t.Context())
	require.NoError(t, err)
	require.Len(t, groups, 1, "Phase A bootstrap seeds exactly one host group")
	assert.Equal(t, api.DefaultHostGroupName, groups[0].Name)
	assert.NotZero(t, groups[0].ID)
}

// TestAppControl_GetHostGroupByID_ReturnsSeedRow + NotFound: round-trip the lookup-by-id contract the REST handler depends on.
func TestAppControl_GetHostGroupByID_ReturnsSeedRow(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	groups, err := store.ListHostGroups(t.Context())
	require.NoError(t, err)
	// Pin the Phase A cardinality contract: exactly one seeded host group (all-hosts). A future regression that ships
	// additional seed groups would surface here, not via a brittle groups[0] dereference (CodeRabbit on PR #195).
	require.Len(t, groups, 1)
	assert.Equal(t, api.DefaultHostGroupName, groups[0].Name)

	byID, err := store.GetHostGroupByID(t.Context(), groups[0].ID)
	require.NoError(t, err)
	assert.Equal(t, groups[0].ID, byID.ID)
	assert.Equal(t, api.DefaultHostGroupName, byID.Name)
}

func TestAppControl_GetHostGroupByID_NotFound(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	_, err := store.GetHostGroupByID(t.Context(), 99_999_999)
	require.ErrorIs(t, err, api.ErrAppControlHostGroupNotFound)
}

// spec:server-application-control/bootstrap-seeds-default-policy-and-all-hosts-group/a-fresh-database-boots-into-a-usable-state
//
// TestAppControl_ListAssignmentsForPolicy_SurfacesSeedAssignment: the bootstrap seeds the Default policy + the
// Default -> all-hosts assignment. ListAssignmentsForPolicy on the seed policy returns exactly one row pointing at the seed
// host group with priority 0. Tests the raw-rows shape the REST handler emits (distinct from ListHostGroupsForPolicy which
// returns the joined group metadata). This pins the spec scenario "a fresh database boots into a usable state": exactly one
// host group, exactly one Default policy, and exactly one assignment connecting them.
func TestAppControl_ListAssignmentsForPolicy_SurfacesSeedAssignment(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	defaultPolicy, err := store.GetPolicyByName(t.Context(), api.DefaultPolicyName)
	require.NoError(t, err)
	groups, err := store.ListHostGroups(t.Context())
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, api.DefaultHostGroupName, groups[0].Name)

	assignments, err := store.ListAssignmentsForPolicy(t.Context(), defaultPolicy.ID)
	require.NoError(t, err)
	require.Len(t, assignments, 1, "seed bootstrap creates exactly one assignment row (Default -> all-hosts)")
	assert.Equal(t, defaultPolicy.ID, assignments[0].PolicyID)
	assert.Equal(t, groups[0].ID, assignments[0].HostGroupID)
	assert.Equal(t, 0, assignments[0].Priority)
}

// TestAppControl_ListAssignmentsForPolicy_UnknownPolicyReturnsEmpty: returning [] for a policy that does not exist is the
// correct shape - the handler should not 404 on the assignments collection endpoint. Phase A's seed always has its
// assignment so this dimension only surfaces for synthetic ids; pinning the contract makes Phase B's editable assignments
// land without changing the response shape on an empty result.
func TestAppControl_ListAssignmentsForPolicy_UnknownPolicyReturnsEmpty(t *testing.T) {
	t.Parallel()
	store, _ := newAppControlStore(t)
	assignments, err := store.ListAssignmentsForPolicy(t.Context(), 99_999_999)
	require.NoError(t, err)
	assert.Empty(t, assignments)
}

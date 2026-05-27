package api_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestMarshalSetApplicationControlPayload_RoundTrip pins the wire shape every agent sees. The byte-exact form is the contract the
// extension's Swift decoder parses; field rename / reorder here breaks every deployed agent at the same instant.
func TestMarshalSetApplicationControlPayload_RoundTrip(t *testing.T) {
	msg := "Blocked: corporate policy"
	url := "https://help.example.com/blocked"
	rules := []api.ApplicationControlRule{
		{
			RuleType:    api.RuleTypeBinary,
			Identifier:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Action:      api.ActionBlock,
			Enforcement: api.EnforcementProtect,
			Enabled:     true,
			Severity:    api.SeverityRuleMedium,
			CustomMsg:   &msg,
			CustomURL:   &url,
		},
	}
	policy := api.ApplicationControlPolicy{ID: 7, Version: 42}
	rules[0].ID = 99

	raw, err := api.MarshalSetApplicationControlPayload(policy, rules, time.Time{})
	require.NoError(t, err)

	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.Equal(t, int64(7), decoded.PolicyID)
	assert.Equal(t, int64(42), decoded.PolicyVersion)
	require.Len(t, decoded.Rules, 1)
	got := decoded.Rules[0]
	assert.Equal(t, "app_control:99", got.RuleID)
	assert.Equal(t, api.RuleTypeBinary, got.RuleType)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", got.Identifier)
	assert.Equal(t, api.ActionBlock, got.Action)
	assert.Equal(t, api.EnforcementProtect, got.Enforcement)
	assert.Equal(t, api.SeverityRuleMedium, got.Severity)
	if assert.NotNil(t, got.CustomMsg) {
		assert.Equal(t, msg, *got.CustomMsg)
	}
	if assert.NotNil(t, got.CustomURL) {
		assert.Equal(t, url, *got.CustomURL)
	}
}

// TestMarshalSetApplicationControlPayload_FiltersDisabled covers the payload's filtering contract: disabled rules MUST NOT reach the
// agent. The fan-out path lifts this gate so the extension never allocates snapshot entries for rules an admin has paused.
func TestMarshalSetApplicationControlPayload_FiltersDisabled(t *testing.T) {
	rules := []api.ApplicationControlRule{
		{RuleType: api.RuleTypeBinary, Identifier: "a", Enabled: true},
		{RuleType: api.RuleTypeBinary, Identifier: "b", Enabled: false},
		{RuleType: api.RuleTypeBinary, Identifier: "c", Enabled: true},
	}
	raw, err := api.MarshalSetApplicationControlPayload(api.ApplicationControlPolicy{ID: 1, Version: 1}, rules, time.Time{})
	require.NoError(t, err)
	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded.Rules, 2)
	assert.Equal(t, "a", decoded.Rules[0].Identifier)
	assert.Equal(t, "c", decoded.Rules[1].Identifier)
}

// TestMarshalSetApplicationControlPayload_FiltersExpired covers the expires_at filter when the caller passes a non-zero `now`.
// The agent should never see rules whose TTL has passed.
func TestMarshalSetApplicationControlPayload_FiltersExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	rules := []api.ApplicationControlRule{
		{RuleType: api.RuleTypeBinary, Identifier: "live-no-expiry", Enabled: true},
		{RuleType: api.RuleTypeBinary, Identifier: "expired", Enabled: true, ExpiresAt: &past},
		{RuleType: api.RuleTypeBinary, Identifier: "live-future-expiry", Enabled: true, ExpiresAt: &future},
	}
	raw, err := api.MarshalSetApplicationControlPayload(api.ApplicationControlPolicy{ID: 1, Version: 1}, rules, now)
	require.NoError(t, err)
	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded.Rules, 2)
	assert.Equal(t, "live-no-expiry", decoded.Rules[0].Identifier)
	assert.Equal(t, "live-future-expiry", decoded.Rules[1].Identifier)
}

// TestMarshalSetApplicationControlPayload_EmptyRules confirms the empty-rules case round-trips cleanly. An empty payload is a valid
// state (just-after-policy-creation, or after every rule is deleted) and the agent + extension must handle it without erroring.
func TestMarshalSetApplicationControlPayload_EmptyRules(t *testing.T) {
	raw, err := api.MarshalSetApplicationControlPayload(api.ApplicationControlPolicy{ID: 1, Version: 1}, nil, time.Time{})
	require.NoError(t, err)
	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, int64(1), decoded.PolicyID)
	assert.Equal(t, int64(1), decoded.PolicyVersion)
	assert.Empty(t, decoded.Rules)
}

// TestSetApplicationControlPayload_JSONKeys pins the JSON field names that the extension's Swift Decodable reads. Renames here
// silently break the extension at decode time; this test fails loudly when a rename happens.
func TestSetApplicationControlPayload_JSONKeys(t *testing.T) {
	msg := "blocked"
	raw, err := api.MarshalSetApplicationControlPayload(
		api.ApplicationControlPolicy{ID: 1, Version: 2},
		[]api.ApplicationControlRule{{
			RuleType: api.RuleTypeBinary, Identifier: "x",
			Action: api.ActionBlock, Enforcement: api.EnforcementProtect,
			Enabled: true, Severity: api.SeverityRuleHigh, CustomMsg: &msg,
		}},
		time.Time{},
	)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	for _, key := range []string{"policy_id", "policy_version", "rules"} {
		assert.Contains(t, got, key, "top-level key %q missing", key)
	}
	rulesAny, _ := got["rules"].([]any)
	require.Len(t, rulesAny, 1)
	rule, _ := rulesAny[0].(map[string]any)
	for _, key := range []string{"rule_id", "rule_type", "identifier", "action", "enforcement", "severity", "custom_msg"} {
		assert.Contains(t, rule, key, "rule key %q missing", key)
	}
}

// ruleTypes is the universe of RuleType values the wire payload can carry. The marshal helper does not gate on rule_type (the server's
// validator does, before the rule lands in the database), so for the round-trip property test we sample the full enum and assert each
// value survives Marshal ∘ Unmarshal unchanged.
var ruleTypes = []api.RuleType{
	api.RuleTypeBinary,
	api.RuleTypeCDHash,
	api.RuleTypeSigningID,
	api.RuleTypeCertificate,
	api.RuleTypeTeamID,
	api.RuleTypePath,
}

var severities = []api.Severity{
	api.SeverityRuleLow,
	api.SeverityRuleMedium,
	api.SeverityRuleHigh,
	api.SeverityRuleCritical,
}

// fallbackPostures enumerates the validator-accepted FallbackPosture values plus the empty zero value. The empty case lives
// here so the PBT explicitly covers the "policy struct has no posture set" path that the marshal substitutes with
// DefaultFallbackPosture; the validator-accepted values cover the v0.1.x configurability path that arrives once the REST
// surface lets operators set the posture per policy.
var fallbackPostures = []api.FallbackPosture{
	"",
	api.FallbackPostureFailClosed,
	api.FallbackPostureFailOpen,
	api.FallbackPostureAuditOnly,
}

// genRule produces a random rule shape. Identifier is opaque to the payload codec (the per-rule_type identifier validator runs server-
// side, not in the marshal helper), so we use a printable-ASCII string generator to exercise the JSON encoding path without dragging
// in per-type format gymnastics.
func genRule(t *rapid.T, idx int) api.ApplicationControlRule {
	identifier := rapid.StringMatching(`[a-zA-Z0-9._:-]{1,64}`).Draw(t, "identifier")
	enabled := rapid.Bool().Draw(t, "enabled")
	rt := rapid.SampledFrom(ruleTypes).Draw(t, "rule_type")
	sev := rapid.SampledFrom(severities).Draw(t, "severity")

	var customMsg *string
	if rapid.Bool().Draw(t, "has_custom_msg") {
		s := rapid.StringMatching(`[a-zA-Z0-9 .,:!?-]{0,140}`).Draw(t, "custom_msg")
		customMsg = &s
	}
	var customURL *string
	if rapid.Bool().Draw(t, "has_custom_url") {
		s := "https://example.invalid/" + rapid.StringMatching(`[a-z0-9-]{1,32}`).Draw(t, "url_path")
		customURL = &s
	}

	var expiresAt *time.Time
	if rapid.Bool().Draw(t, "has_expires_at") {
		secs := rapid.Int64Range(-86_400_000, 86_400_000).Draw(t, "expires_at_seconds_from_now")
		exp := time.Unix(secs, 0).UTC()
		expiresAt = &exp
	}

	return api.ApplicationControlRule{
		ID:          int64(idx),
		PolicyID:    1,
		RuleType:    rt,
		Identifier:  identifier,
		Action:      api.ActionBlock,
		Enforcement: api.EnforcementProtect,
		Enabled:     enabled,
		Severity:    sev,
		Source:      api.SourceAdmin,
		CustomMsg:   customMsg,
		CustomURL:   customURL,
		ExpiresAt:   expiresAt,
	}
}

// TestMarshalSetApplicationControlPayload_RapidRoundTrip is the PBT
// counterpart to the example-based round-trip tests above. For any
// random policy + rule list + clock, Marshal then Unmarshal must
// reproduce exactly the policy version, the policy id, and every
// rule that survives the filter (enabled + (no expires_at OR
// expires_at > now OR now is zero)). Catches a regression where a
// future field add forgets a json tag, where the filter loses a rule
// it should keep, or where the JSON shape becomes ambiguous on
// optional fields.
//
// Bounded rule-list size: rapid.SliceOfN caps each generated batch
// so each property iteration stays under a few milliseconds.
func TestMarshalSetApplicationControlPayload_RapidRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		policyID := rapid.Int64Range(1, 1_000_000).Draw(t, "policy_id")
		policyVersion := rapid.Int64Range(1, 1_000_000).Draw(t, "policy_version")
		nRules := rapid.IntRange(0, 20).Draw(t, "n_rules")
		posture := rapid.SampledFrom(fallbackPostures).Draw(t, "deadline_fallback")

		rules := make([]api.ApplicationControlRule, 0, nRules)
		for i := range nRules {
			rules = append(rules, genRule(t, i))
		}

		// "now" is either zero (filter disabled) or a fixed epoch the
		// genRule random expires_at values straddle.
		var now time.Time
		if rapid.Bool().Draw(t, "filter_enabled") {
			now = time.Unix(0, 0).UTC()
		}

		policy := api.ApplicationControlPolicy{ID: policyID, Version: policyVersion, DeadlineFallback: posture}
		raw, err := api.MarshalSetApplicationControlPayload(policy, rules, now)
		require.NoError(t, err)

		var decoded api.SetApplicationControlPayload
		require.NoError(t, json.Unmarshal(raw, &decoded))
		assert.Equal(t, policyID, decoded.PolicyID)
		assert.Equal(t, policyVersion, decoded.PolicyVersion)

		// Posture invariant: the marshal substitutes DefaultFallbackPosture when the upstream policy has no value set
		// (empty string today, or any future value the validator does not recognise). Validator-accepted values flow
		// through verbatim. Either way the decoded wire field must be a validator-accepted posture so the extension
		// snapshot decode cannot fail on an unknown literal.
		expectedPosture := posture
		if !api.IsValidFallbackPosture(expectedPosture) {
			expectedPosture = api.DefaultFallbackPosture
		}
		assert.Equal(t, expectedPosture, decoded.DeadlineFallback)
		assert.True(t, api.IsValidFallbackPosture(decoded.DeadlineFallback),
			"wire posture %q must always pass the validator", decoded.DeadlineFallback)

		// Build the expected post-filter view from the inputs and compare element-wise. The filter contract: drop disabled
		// rules; drop rules whose expires_at is in the past relative to a non-zero `now`.
		expected := make([]api.SetApplicationControlRule, 0, len(rules))
		for _, r := range rules {
			if !r.Enabled {
				continue
			}
			if !now.IsZero() && r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
				continue
			}
			expected = append(expected, api.SetApplicationControlRule{
				RuleID:      api.ApplicationControlRuleID(r.ID),
				RuleType:    r.RuleType,
				Identifier:  r.Identifier,
				Action:      r.Action,
				Enforcement: r.Enforcement,
				Severity:    r.Severity,
				CustomMsg:   r.CustomMsg,
				CustomURL:   r.CustomURL,
			})
		}
		require.Len(t, decoded.Rules, len(expected), "filtered rule count must match")
		for i := range expected {
			got := decoded.Rules[i]
			assert.Equal(t, expected[i].RuleID, got.RuleID)
			assert.Equal(t, expected[i].RuleType, got.RuleType)
			assert.Equal(t, expected[i].Identifier, got.Identifier)
			assert.Equal(t, expected[i].Action, got.Action)
			assert.Equal(t, expected[i].Enforcement, got.Enforcement)
			assert.Equal(t, expected[i].Severity, got.Severity)
			if expected[i].CustomMsg == nil {
				assert.Nil(t, got.CustomMsg)
			} else if assert.NotNil(t, got.CustomMsg) {
				assert.Equal(t, *expected[i].CustomMsg, *got.CustomMsg)
			}
			if expected[i].CustomURL == nil {
				assert.Nil(t, got.CustomURL)
			} else if assert.NotNil(t, got.CustomURL) {
				assert.Equal(t, *expected[i].CustomURL, *got.CustomURL)
			}
		}
	})
}

// TestMarshalSetApplicationControlPayload_DeadlineFallbackDefault pins the v0.1.0 contract: a policy whose DeadlineFallback
// is the zero value (empty string) marshals to "fail-closed" on the wire. Pre-v0.1.0 callers that have not been recompiled
// against the new ApplicationControlPolicy shape will leak that zero value through, and the extension snapshot must still
// receive a safe-by-default posture.
func TestMarshalSetApplicationControlPayload_DeadlineFallbackDefault(t *testing.T) {
	raw, err := api.MarshalSetApplicationControlPayload(
		api.ApplicationControlPolicy{ID: 1, Version: 1},
		nil,
		time.Time{},
	)
	require.NoError(t, err)
	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, api.FallbackPostureFailClosed, decoded.DeadlineFallback)
	assert.Equal(t, api.DefaultFallbackPosture, decoded.DeadlineFallback,
		"DefaultFallbackPosture must be the substituted value")
}

// TestMarshalSetApplicationControlPayload_DeadlineFallbackPassthrough confirms an explicitly-set policy posture survives
// the marshal verbatim. Drives the v0.1.x follow-up that will start carrying real values through ApplicationControlPolicy
// once the DB column lands; the test guarantees the wire path is ready to accept whatever value the REST surface validates.
func TestMarshalSetApplicationControlPayload_DeadlineFallbackPassthrough(t *testing.T) {
	cases := []struct {
		name    string
		posture api.FallbackPosture
	}{
		{"fail-closed", api.FallbackPostureFailClosed},
		{"fail-open", api.FallbackPostureFailOpen},
		{"audit-only", api.FallbackPostureAuditOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := api.MarshalSetApplicationControlPayload(
				api.ApplicationControlPolicy{ID: 1, Version: 1, DeadlineFallback: tc.posture},
				nil,
				time.Time{},
			)
			require.NoError(t, err)
			var decoded api.SetApplicationControlPayload
			require.NoError(t, json.Unmarshal(raw, &decoded))
			assert.Equal(t, tc.posture, decoded.DeadlineFallback)
		})
	}
}

// TestMarshalSetApplicationControlPayload_DeadlineFallbackNormalizesInvalid pins that a non-empty but unrecognised posture is
// substituted with DefaultFallbackPosture before it reaches the wire. The extension's FallbackPosture enum is strict; an
// unknown literal would deactivate Application Control until the next valid push, so the marshal MUST never emit one.
func TestMarshalSetApplicationControlPayload_DeadlineFallbackNormalizesInvalid(t *testing.T) {
	cases := []string{"fail-close", "FAIL-CLOSED", "audit_only", "garbage", "FAIL-OPEN"}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			raw, err := api.MarshalSetApplicationControlPayload(
				api.ApplicationControlPolicy{ID: 1, Version: 1, DeadlineFallback: api.FallbackPosture(bad)},
				nil,
				time.Time{},
			)
			require.NoError(t, err)
			var decoded api.SetApplicationControlPayload
			require.NoError(t, json.Unmarshal(raw, &decoded))
			assert.Equal(t, api.DefaultFallbackPosture, decoded.DeadlineFallback)
			assert.True(t, api.IsValidFallbackPosture(decoded.DeadlineFallback))
		})
	}
}

// TestMarshalSetApplicationControlPayload_DeadlineFallbackWireKey pins the JSON key Swift's Decodable reads. A rename here
// silently breaks the extension's snapshot decode; this test fails loudly when a rename happens.
func TestMarshalSetApplicationControlPayload_DeadlineFallbackWireKey(t *testing.T) {
	raw, err := api.MarshalSetApplicationControlPayload(
		api.ApplicationControlPolicy{ID: 1, Version: 1, DeadlineFallback: api.FallbackPostureAuditOnly},
		nil,
		time.Time{},
	)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Contains(t, got, "deadline_fallback")
	assert.Equal(t, "audit-only", got["deadline_fallback"])
}

// TestIsValidFallbackPosture is the table-driven validator the v0.1.x REST surface will call before persisting an operator-
// supplied posture. Pinning the enum membership here keeps the validator honest if the enum ever picks up a new value (the
// invalid-case lines below must be updated to include the new constant).
func TestIsValidFallbackPosture(t *testing.T) {
	cases := []struct {
		name    string
		posture api.FallbackPosture
		want    bool
	}{
		{"fail-closed", api.FallbackPostureFailClosed, true},
		{"fail-open", api.FallbackPostureFailOpen, true},
		{"audit-only", api.FallbackPostureAuditOnly, true},
		{"empty", "", false},
		{"misspelled fail-close", "fail-close", false},
		{"uppercase", "FAIL-CLOSED", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, api.IsValidFallbackPosture(tc.posture))
		})
	}
}

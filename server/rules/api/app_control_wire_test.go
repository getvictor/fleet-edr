package api_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestMarshalSetApplicationControlPayload_RoundTrip pins the wire
// shape every agent sees. The byte-exact form is the contract the
// extension's Swift decoder parses; field rename / reorder here
// breaks every deployed agent at the same instant.
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

	raw, err := api.MarshalSetApplicationControlPayload(policy, rules, time.Time{})
	require.NoError(t, err)

	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))

	assert.Equal(t, int64(7), decoded.PolicyID)
	assert.Equal(t, int64(42), decoded.PolicyVersion)
	require.Len(t, decoded.Rules, 1)
	got := decoded.Rules[0]
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

// TestMarshalSetApplicationControlPayload_FiltersDisabled covers the
// payload's filtering contract: disabled rules MUST NOT reach the
// agent. The fan-out path lifts this gate so the extension never
// allocates snapshot entries for rules an admin has paused.
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

// TestMarshalSetApplicationControlPayload_FiltersExpired covers the
// expires_at filter when the caller passes a non-zero `now`. The
// agent should never see rules whose TTL has passed.
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

// TestMarshalSetApplicationControlPayload_EmptyRules confirms the
// empty-rules case round-trips cleanly. An empty payload is a valid
// state (just-after-policy-creation, or after every rule is deleted)
// and the agent + extension must handle it without erroring.
func TestMarshalSetApplicationControlPayload_EmptyRules(t *testing.T) {
	raw, err := api.MarshalSetApplicationControlPayload(api.ApplicationControlPolicy{ID: 1, Version: 1}, nil, time.Time{})
	require.NoError(t, err)
	var decoded api.SetApplicationControlPayload
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, int64(1), decoded.PolicyID)
	assert.Equal(t, int64(1), decoded.PolicyVersion)
	assert.Empty(t, decoded.Rules)
}

// TestSetApplicationControlPayload_JSONKeys pins the JSON field
// names that the extension's Swift Decodable reads. Renames here
// silently break the extension at decode time; this test fails
// loudly when a rename happens.
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
	for _, key := range []string{"rule_type", "identifier", "action", "enforcement", "severity", "custom_msg"} {
		assert.Contains(t, rule, key, "rule key %q missing", key)
	}
}

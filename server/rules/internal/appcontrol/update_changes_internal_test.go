package appcontrol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/rules/api"
)

// TestRuleUpdateChanges pins which requests count as a change to a rule. An update that changes nothing is not a mutation, so a
// wrong answer here either bumps the policy version and pushes an identical snapshot to every host, or drops a real change.
func TestRuleUpdateChanges(t *testing.T) {
	t.Parallel()
	msg, url := "Blocked by policy", "https://example.com/why"
	expires := time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)
	current := api.ApplicationControlRule{
		Enabled: true, Severity: api.SeverityRuleMedium, Enforcement: api.EnforcementProtect,
		CustomMsg: &msg, CustomURL: nil, Comment: "seed", ExpiresAt: &expires,
	}
	enabled, disabled := true, false
	medium, high := api.SeverityRuleMedium, api.SeverityRuleHigh
	protect, detect := api.EnforcementProtect, api.EnforcementDetect
	sameMsg, otherMsg, empty := msg, "Different", ""
	sameComment, otherComment := "seed", "changed"
	laterExpiry := expires.Add(time.Hour)
	// The same instant with sub-microsecond digits MySQL would round away, in another zone.
	sameExpiry := expires.Add(400 * time.Nanosecond).In(time.FixedZone("CDT", -5*60*60))

	cases := []struct {
		name string
		req  api.UpdateRuleRequest
		want bool
	}{
		{"every supplied field at its current value", api.UpdateRuleRequest{
			Enabled: &enabled, Severity: &medium, Enforcement: &protect, CustomMsg: &sameMsg, Comment: &sameComment, ExpiresAt: &sameExpiry,
		}, false},
		{"no field supplied", api.UpdateRuleRequest{}, false},
		{"enabled flipped", api.UpdateRuleRequest{Enabled: &disabled}, true},
		{"severity raised", api.UpdateRuleRequest{Severity: &high}, true},
		{"enforcement moved to detect", api.UpdateRuleRequest{Enforcement: &detect}, true},
		{"custom message changed", api.UpdateRuleRequest{CustomMsg: &otherMsg}, true},
		{"custom URL set where there was none", api.UpdateRuleRequest{CustomURL: &url}, true},
		{"empty custom URL where there was none", api.UpdateRuleRequest{CustomURL: &empty}, true},
		{"comment changed", api.UpdateRuleRequest{Comment: &otherComment}, true},
		{"expiry moved", api.UpdateRuleRequest{ExpiresAt: &laterExpiry}, true},
		{"one unchanged field beside a changed one", api.UpdateRuleRequest{Enforcement: &protect, Severity: &high}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ruleUpdateChanges(current, tc.req))
		})
	}

	t.Run("an expiry set on a rule that had none", func(t *testing.T) {
		t.Parallel()
		noExpiry := current
		noExpiry.ExpiresAt = nil
		assert.True(t, ruleUpdateChanges(noExpiry, api.UpdateRuleRequest{ExpiresAt: &expires}))
	})
	t.Run("a custom URL changed from one value to another", func(t *testing.T) {
		t.Parallel()
		withURL := current
		withURL.CustomURL = &url
		other := "https://example.com/other"
		assert.True(t, ruleUpdateChanges(withURL, api.UpdateRuleRequest{CustomURL: &other}))
		assert.False(t, ruleUpdateChanges(withURL, api.UpdateRuleRequest{CustomURL: &url}))
	})
}

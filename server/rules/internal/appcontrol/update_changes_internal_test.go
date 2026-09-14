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

	withoutExpiry := current
	withoutExpiry.ExpiresAt = nil
	withURL := current
	withURL.CustomURL = &url
	otherURL := "https://example.com/other"

	cases := []struct {
		name    string
		current api.ApplicationControlRule
		req     api.UpdateRuleRequest
		want    bool
	}{
		{"every supplied field at its current value", current, api.UpdateRuleRequest{
			Enabled: &enabled, Severity: &medium, Enforcement: &protect, CustomMsg: &sameMsg, Comment: &sameComment, ExpiresAt: &sameExpiry,
		}, false},
		{"no field supplied", current, api.UpdateRuleRequest{}, false},
		{"enabled flipped", current, api.UpdateRuleRequest{Enabled: &disabled}, true},
		{"severity raised", current, api.UpdateRuleRequest{Severity: &high}, true},
		{"enforcement moved to detect", current, api.UpdateRuleRequest{Enforcement: &detect}, true},
		{"custom message changed", current, api.UpdateRuleRequest{CustomMsg: &otherMsg}, true},
		{"custom URL set where there was none", current, api.UpdateRuleRequest{CustomURL: &url}, true},
		{"empty custom URL where there was none", current, api.UpdateRuleRequest{CustomURL: &empty}, true},
		{"custom URL changed from one value to another", withURL, api.UpdateRuleRequest{CustomURL: &otherURL}, true},
		{"custom URL at its current value", withURL, api.UpdateRuleRequest{CustomURL: &url}, false},
		{"comment changed", current, api.UpdateRuleRequest{Comment: &otherComment}, true},
		{"expiry moved", current, api.UpdateRuleRequest{ExpiresAt: &laterExpiry}, true},
		{"expiry set on a rule that had none", withoutExpiry, api.UpdateRuleRequest{ExpiresAt: &expires}, true},
		{"one unchanged field beside a changed one", current, api.UpdateRuleRequest{Enforcement: &protect, Severity: &high}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ruleUpdateChanges(tc.current, tc.req))
		})
	}
}

package catalog

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/fleetdm/edr/server/rules/api"
)

// tccGrant is a tcc_modify event in the shape a grant takes, with the agent's identity signing. Each event its own ID.
func tccGrant(t *testing.T, id string, edit func(p *tccModifyPayload)) api.Event {
	t.Helper()
	p := tccModifyPayload{
		// The shape captured on edr-dev when Firefox was added to Full Disk Access in System Settings: a modify, not a create.
		Service: "SystemPolicyAllFiles", Identity: "org.mozilla.firefox", IdentityType: "bundle_id", UpdateType: "modify",
		Right: "allowed", Reason: "user_set", IdentityPath: "/Applications/Firefox.app",
		IdentityCodeSigning: &codeSigningJSON{TeamID: "43AQ936H96", SigningID: "org.mozilla.firefox"},
	}
	if edit != nil {
		edit(&p)
	}
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	return api.Event{EventID: id, HostID: "fixture-host", TimestampNs: 1, EventType: "tcc_modify", Payload: raw}
}

func evaluateTccGrant(t *testing.T, excl api.ExclusionResolver, events ...api.Event) []api.Finding {
	t.Helper()
	findings, err := (&TccSensitiveGrant{Exclusions: excl}).Evaluate(t.Context(), events, stubGraphReader{})
	require.NoError(t, err)
	return findings
}

// spec:server-detection-rules-engine/a-sensitive-tcc-grant-is-reported/a-sensitive-permission-granted-to-another-vendor-s-app-fires
func TestTccSensitiveGrant_ASensitivePermissionGrantedToAnotherVendorsAppFires(t *testing.T) {
	t.Parallel()
	for service, words := range map[string]string{
		"SystemPolicyAllFiles": "Full Disk Access", "Accessibility": "Accessibility", "ScreenCapture": "Screen Recording",
		"ListenEvent": "Input Monitoring", "PostEvent": "control of input events",
	} {
		t.Run(service, func(t *testing.T) {
			t.Parallel()
			findings := evaluateTccGrant(t, nil, tccGrant(t, service, func(p *tccModifyPayload) { p.Service = service }))
			require.Len(t, findings, 1)
			f := findings[0]
			assert.Equal(t, "tcc_sensitive_grant", f.RuleID)
			assert.Equal(t, api.SeverityMedium, f.Severity)
			assert.Equal(t, "org.mozilla.firefox (/Applications/Firefox.app) was granted "+words+": TCC permission abuse (MITRE T1548.006)",
				f.Description)
			assert.Zero(t, f.ProcessID, "process-less: the recorder is Apple's own and the app need not be running")
			assert.Equal(t, "tccgrant:"+service+":org.mozilla.firefox", f.Subject)
		})
	}
	// A new record, as a prompt answered creates, fires too, and an executable path names itself once.
	created := evaluateTccGrant(t, nil, tccGrant(t, "create", func(p *tccModifyPayload) {
		p.UpdateType, p.Identity, p.IdentityType, p.IdentityPath = "create", "/usr/local/bin/tool", "executable_path", "/usr/local/bin/tool"
	}))
	require.Len(t, created, 1)
	assert.Equal(t, "/usr/local/bin/tool was granted Full Disk Access: TCC permission abuse (MITRE T1548.006)", created[0].Description)
}

// spec:server-detection-rules-engine/a-sensitive-tcc-grant-is-reported/other-changes-do-not-fire
func TestTccSensitiveGrant_OtherChangesDoNotFire(t *testing.T) {
	t.Parallel()
	cases := map[string]func(p *tccModifyPayload){
		"a denial":                        func(p *tccModifyPayload) { p.Right = "denied" },
		"a deletion":                      func(p *tccModifyPayload) { p.UpdateType, p.Right = "delete", "unknown" },
		"a service that is not sensitive": func(p *tccModifyPayload) { p.Service = "Camera" },
		"an MDM profile's grant":          func(p *tccModifyPayload) { p.Reason = "mdm_policy" },
		"an Apple platform binary":        func(p *tccModifyPayload) { p.IdentityCodeSigning = &codeSigningJSON{IsPlatformBinary: true} },
		"an unreadable signature":         func(p *tccModifyPayload) { p.IdentityCodeSigning = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Empty(t, evaluateTccGrant(t, nil, tccGrant(t, name, edit)))
		})
	}
}

// spec:server-detection-rules-engine/a-sensitive-tcc-grant-is-reported/a-granted-app-is-waived-by-its-signer-or-path
func TestTccSensitiveGrant_AGrantedAppIsWaivedBySignerOrPath(t *testing.T) {
	t.Parallel()
	const rule = "tcc_sensitive_grant"
	cases := []struct {
		name  string
		excl  fakeExcl
		fires bool
	}{
		{"by team", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchTeamID, value: "43AQ936H96"}, false},
		{"by qualified signing id", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchSigningID,
			value: "43AQ936H96:org.mozilla.firefox"}, false},
		{"by path", fakeExcl{ruleID: rule, matchType: api.ExclusionMatchPathGlob, value: "/Applications/Firefox.app"}, false},
		{"another rule's exclusion", fakeExcl{ruleID: "suspicious_exec", matchType: api.ExclusionMatchTeamID, value: "43AQ936H96"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := evaluateTccGrant(t, &fakeExclusions{entries: []fakeExcl{tc.excl}}, tccGrant(t, tc.name, nil))
			assert.Equal(t, tc.fires, len(findings) == 1)
		})
	}
}

// TestTccModifyPayload_RoundTrip is the wire round-trip PBT for the tcc_modify payload the rule decodes (CLAUDE.md: new wire struct
// needs Marshal then Unmarshal to be the identity), including the fields the agent adds.
func TestTccModifyPayload_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		in := tccModifyPayload{
			Service:      rapid.String().Draw(rt, "service"),
			Identity:     rapid.String().Draw(rt, "identity"),
			IdentityType: rapid.SampledFrom([]string{"bundle_id", "executable_path", "policy_id", "unknown"}).Draw(rt, "identity_type"),
			UpdateType:   rapid.SampledFrom([]string{"create", "modify", "delete", "unknown"}).Draw(rt, "update_type"),
			Right:        rapid.SampledFrom([]string{"denied", "unknown", "allowed", "limited"}).Draw(rt, "right"),
			Reason:       rapid.String().Draw(rt, "reason"),
			IdentityPath: rapid.String().Draw(rt, "identity_path"),
		}
		if rapid.Bool().Draw(rt, "signed") {
			in.IdentityCodeSigning = &codeSigningJSON{
				TeamID: rapid.String().Draw(rt, "team"), SigningID: rapid.String().Draw(rt, "signing"),
				IsPlatformBinary: rapid.Bool().Draw(rt, "platform"),
			}
		}
		b, err := json.Marshal(in)
		require.NoError(rt, err)
		var out tccModifyPayload
		require.NoError(rt, json.Unmarshal(b, &out))
		assert.Equal(rt, in, out)
	})
}

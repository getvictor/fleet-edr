package appcontrol_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/appcontrol"
)

// TestValidateRuleType_DemoCutAccepts covers the matrix of accepted /
// deferred / invalid rule_type values. The demo cut accepts BINARY
// outright and reports the other five spec'd types as
// ErrAppControlUnsupportedRuleType so REST callers see a precise
// "not yet" instead of a generic "unknown" error.
func TestValidateRuleType_DemoCutAccepts(t *testing.T) {
	cases := []struct {
		name    string
		rt      api.RuleType
		wantErr error
	}{
		{"binary accepted", api.RuleTypeBinary, nil},
		{"cdhash deferred", api.RuleTypeCDHash, api.ErrAppControlUnsupportedRuleType},
		{"signing id deferred", api.RuleTypeSigningID, api.ErrAppControlUnsupportedRuleType},
		{"certificate deferred", api.RuleTypeCertificate, api.ErrAppControlUnsupportedRuleType},
		{"team id deferred", api.RuleTypeTeamID, api.ErrAppControlUnsupportedRuleType},
		{"path deferred", api.RuleTypePath, api.ErrAppControlUnsupportedRuleType},
		{"unknown rejected", api.RuleType("BANANA"), api.ErrAppControlInvalidRuleType},
		{"empty rejected", api.RuleType(""), api.ErrAppControlInvalidRuleType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appcontrol.ValidateRuleType(tc.rt)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestValidateIdentifier_Binary pins the BINARY identifier rule:
// exactly 64 lowercase hex characters. Anything else returns
// ErrAppControlInvalidIdentifier with a message that includes the
// "BINARY rule identifier" hint so audit logs can attribute the
// rejection cleanly.
func TestValidateIdentifier_Binary(t *testing.T) {
	cases := []struct {
		name string
		id   string
		ok   bool
	}{
		{"valid 64 hex", strings.Repeat("a", 64), true},
		{"valid mixed hex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"uppercase rejected", strings.Repeat("A", 64), false},
		{"63 chars rejected", strings.Repeat("a", 63), false},
		{"65 chars rejected", strings.Repeat("a", 65), false},
		{"non-hex char rejected", strings.Repeat("g", 64), false},
		{"empty rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appcontrol.ValidateIdentifier(api.RuleTypeBinary, tc.id)
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrAppControlInvalidIdentifier)
		})
	}
}

// TestValidateIdentifier_DeferredTypes confirms the rest of the
// rule_type enum is wired through the validator. The format check
// for the spec'd identifier fires first; on a well-formed value the
// validator still reports ErrAppControlUnsupportedRuleType so the
// REST handler can return "not yet wired" rather than silently
// accepting the rule.
func TestValidateIdentifier_DeferredTypes(t *testing.T) {
	cases := []struct {
		name        string
		rt          api.RuleType
		id          string
		shapeOK     bool
		wantErrType error
	}{
		{"cdhash 40 hex - unsupported", api.RuleTypeCDHash, strings.Repeat("a", 40), true, api.ErrAppControlUnsupportedRuleType},
		{"cdhash 39 chars - format rejected", api.RuleTypeCDHash, strings.Repeat("a", 39), false, api.ErrAppControlInvalidIdentifier},
		{"team id valid - unsupported", api.RuleTypeTeamID, "EQHXZ8M8AV", true, api.ErrAppControlUnsupportedRuleType},
		{"team id lowercase - format rejected", api.RuleTypeTeamID, "eqhxz8m8av", false, api.ErrAppControlInvalidIdentifier},
		{"signing id valid - unsupported", api.RuleTypeSigningID, "EQHXZ8M8AV:com.google.Chrome", true, api.ErrAppControlUnsupportedRuleType},
		{"signing id platform - unsupported", api.RuleTypeSigningID, "platform:com.apple.curl", true, api.ErrAppControlUnsupportedRuleType},
		{"signing id missing colon - format rejected", api.RuleTypeSigningID, "EQHXZ8M8AVcom.google.Chrome", false, api.ErrAppControlInvalidIdentifier},
		{"certificate 64 hex - unsupported", api.RuleTypeCertificate, strings.Repeat("c", 64), true, api.ErrAppControlUnsupportedRuleType},
		{"certificate 63 chars - format rejected", api.RuleTypeCertificate, strings.Repeat("c", 63), false, api.ErrAppControlInvalidIdentifier},
		{"path absolute - unsupported", api.RuleTypePath, "/usr/bin/ls", true, api.ErrAppControlUnsupportedRuleType},
		{"path relative - format rejected", api.RuleTypePath, "usr/bin/ls", false, api.ErrAppControlInvalidIdentifier},
		{"path empty - format rejected", api.RuleTypePath, "", false, api.ErrAppControlInvalidIdentifier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appcontrol.ValidateIdentifier(tc.rt, tc.id)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErrType)
		})
	}
}

// TestCanonicalizePath covers the macOS-specific /tmp, /var, /etc
// rewrites every PATH rule depends on. The validator path is
// exercised today; the Phase-A PATH-rule decision engine will consume
// the same helper.
func TestCanonicalizePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain path unchanged", "/usr/bin/ls", "/usr/bin/ls", true},
		{"/tmp rewritten", "/tmp/foo", "/private/tmp/foo", true},
		{"/var rewritten", "/var/db/x", "/private/var/db/x", true},
		{"/etc rewritten", "/etc/sudoers", "/private/etc/sudoers", true},
		{"/etc bare rewritten", "/etc", "/private/etc", true},
		{"/tmpfoo NOT rewritten", "/tmpfoo/bar", "/tmpfoo/bar", true},
		{"redundant slashes collapsed", "/usr//bin///ls", "/usr/bin/ls", true},
		{"trailing slash collapsed", "/usr/bin/", "/usr/bin", true},
		{"empty rejected", "", "", false},
		{"relative rejected", "tmp/foo", "", false},
		{".. segment rejected", "/var/foo/../../etc/sudoers", "", false},
		{".. as final segment rejected", "/usr/bin/..", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := appcontrol.CanonicalizePath(tc.in)
			if !tc.ok {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestValidateSeverity covers the empty-is-ok + recognized + rejected
// cases. The REST handler relies on empty → default behavior so the
// admin can omit the field on Add Rule.
func TestValidateSeverity(t *testing.T) {
	cases := []struct {
		name string
		s    api.Severity
		ok   bool
	}{
		{"empty ok (defaults to medium)", "", true},
		{"low ok", api.SeverityRuleLow, true},
		{"medium ok", api.SeverityRuleMedium, true},
		{"high ok", api.SeverityRuleHigh, true},
		{"critical ok", api.SeverityRuleCritical, true},
		{"unknown rejected", api.Severity("emergency"), false},
		{"uppercase rejected", api.Severity("LOW"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := appcontrol.ValidateSeverity(tc.s)
			if tc.ok {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrAppControlInvalidSeverity)
		})
	}
}

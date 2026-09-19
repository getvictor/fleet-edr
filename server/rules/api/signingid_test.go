package api_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// The bypass this closes. `codesign -s - -i com.vendor.tool ./payload` needs no privilege and no Apple account, and under an
// unqualified match that binary inherited every exclusion written for the real vendor's tool (issue #1024).
func TestAnAdHocBinaryClaimingAnIdentifierQualifiesToNothing(t *testing.T) {
	t.Parallel()

	assert.Empty(t, api.QualifiedSigningID("", "com.vendor.tool", false),
		"an identifier nothing vouches for must match no signing_id exclusion at all")
}

func TestQualifiedSigningID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc       string
		teamID     string
		signingID  string
		isPlatform bool
		want       string
	}{
		{
			desc:      "a Developer ID binary is qualified by its team",
			teamID:    "Q6L2SF6YDW",
			signingID: "com.vendor.tool",
			want:      "Q6L2SF6YDW:com.vendor.tool",
		},
		{
			// Apple's binaries carry no team ID, so the platform flag is what vouches for them, and it is the one thing an
			// attacker cannot set on a binary they planted.
			desc:       "an operating-system binary is qualified by platform",
			signingID:  "com.apple.bash",
			isPlatform: true,
			want:       "platform:com.apple.bash",
		},
		{
			desc:       "platform wins over a team, so an Apple binary is never team-qualified",
			teamID:     "APPLE00000",
			signingID:  "com.apple.bash",
			isPlatform: true,
			want:       "platform:com.apple.bash",
		},
		{
			desc:      "an ad-hoc binary qualifies to nothing",
			signingID: "com.vendor.tool",
			want:      "",
		},
		{
			desc:   "an unsigned binary qualifies to nothing",
			teamID: "Q6L2SF6YDW",
			want:   "",
		},
		{
			desc: "nothing at all qualifies to nothing",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, api.QualifiedSigningID(tc.teamID, tc.signingID, tc.isPlatform))
		})
	}
}

// An operator is told at the API, because an exclusion whose value can never match is one they believe is suppressing something.
func TestValidateExclusionValueRefusesABareSigningID(t *testing.T) {
	t.Parallel()

	err := api.ValidateExclusionValue(api.ExclusionMatchSigningID, "com.vendor.tool")

	require.ErrorIs(t, err, api.ErrSigningIDNotQualified)
	require.ErrorContains(t, err, "<TEAMID>:com.vendor.tool", "the message has to show the form, not just name it")
	require.ErrorContains(t, err, "platform:com.vendor.tool")
}

func TestValidateExclusionValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		desc      string
		matchType api.ExclusionMatchType
		value     string
		wantErr   bool
	}{
		{desc: "a team-qualified identifier", matchType: api.ExclusionMatchSigningID, value: "Q6L2SF6YDW:com.vendor.tool"},
		{desc: "a platform-qualified identifier", matchType: api.ExclusionMatchSigningID, value: "platform:com.apple.bash"},
		{
			// An identifier may itself contain a colon, so only the FIRST one divides.
			desc:      "an identifier carrying a colon of its own",
			matchType: api.ExclusionMatchSigningID,
			value:     "Q6L2SF6YDW:com.vendor.tool:helper",
		},
		{desc: "a bare identifier", matchType: api.ExclusionMatchSigningID, value: "com.vendor.tool", wantErr: true},
		{desc: "a qualifier with no identifier", matchType: api.ExclusionMatchSigningID, value: "Q6L2SF6YDW:", wantErr: true},
		{desc: "an identifier with no qualifier", matchType: api.ExclusionMatchSigningID, value: ":com.vendor.tool", wantErr: true},
		{desc: "nothing at all", matchType: api.ExclusionMatchSigningID, value: "", wantErr: true},
		// Every other match type is free text, a glob, or a hash, and has no shape to check.
		{desc: "a team id is unaffected", matchType: api.ExclusionMatchTeamID, value: "Q6L2SF6YDW"},
		{desc: "a path glob is unaffected", matchType: api.ExclusionMatchPathGlob, value: "/opt/*/bin/tool"},
		{desc: "a cdhash is unaffected", matchType: api.ExclusionMatchCDHash, value: "deadbeef"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			err := api.ValidateExclusionValue(tc.matchType, tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// The composer and the validator have to agree, or an operator writes a value the API accepts and nothing ever matches. Checked
// against each other rather than against two hand-written literals.
func TestEveryQualifiedValueTheComposerProducesIsOneTheAPIAccepts(t *testing.T) {
	t.Parallel()
	for _, composed := range []string{
		api.QualifiedSigningID("Q6L2SF6YDW", "com.vendor.tool", false),
		api.QualifiedSigningID("", "com.apple.bash", true),
		api.QualifiedSigningID("Q6L2SF6YDW", "com.vendor.tool:helper", false),
	} {
		require.NotEmpty(t, composed)
		assert.NoError(t, api.ValidateExclusionValue(api.ExclusionMatchSigningID, composed),
			"the API must accept %q, which is what a matching process composes to", composed)
	}
}

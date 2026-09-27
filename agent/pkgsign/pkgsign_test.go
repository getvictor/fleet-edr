package pkgsign

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// The first two are verbatim `pkgutil --check-signature` output captured on edr-dev (macOS 26.3) for issue #1161: our own
// notarized release and an unsigned pkgbuild package.
const (
	notarizedDeveloperID = `Package "fleet-edr-v0.6.0.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2026-09-23 15:45:10 +0000
   Certificate Chain:
    1. Developer ID Installer: VICTOR LYUBOSLAVSKY (FDG8Q7N4CC)
       Expires: 2031-04-22 13:21:07 +0000
       SHA256 Fingerprint:
           00 11
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
       Expires: 2031-09-17 00:00:00 +0000
       ------------------------------------------------------------------------
    3. Apple Root CA
       Expires: 2035-02-09 21:40:36 +0000
`
	unsigned = `Package "edrpkgtest.pkg":
   Status: no signature
`
	untrusted = `Package "selfsigned.pkg":
   Status: signed by untrusted certificate
   Certificate Chain:
    1. Totally Legit Corp (ABCDE12345)
`
	appleSigned = `Package "update.pkg":
   Status: signed Apple Software
   Certificate Chain:
    1. Software Update
       ------------------------------------------------------------------------
    2. Apple Software Update Certification Authority
`
	// The shapes below are not captured output. They pin the parser's refusals: a status it does not know is not trusted, and a
	// team is read only from a Developer ID Installer leaf.
	expired = `Package "old.pkg":
   Status: signed by a certificate that has since expired
   Certificate Chain:
    1. Developer ID Installer: Example Corp (ZYXWV98765)
`
	revoked = `Package "bad.pkg":
   Status: signed by a revoked certificate
   Certificate Chain:
    1. Developer ID Installer: Example Corp (ZYXWV98765)
`
	enterprise = `Package "corp.pkg":
   Status: signed by a certificate trusted by macOS
   Certificate Chain:
    1. Corp Internal Installer Signing (ABCDE12345)
`
	developerIDNotNotarized = `Package "internal.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Certificate Chain:
    1. Developer ID Installer: Example Corp (ZYXWV98765)
`
)

func TestParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		output string
		want   Result
		ok     bool
	}{
		{"notarized developer ID", notarizedDeveloperID, Result{Signed: true, Notarized: true, TeamID: "FDG8Q7N4CC"}, true},
		{"developer ID, not notarized", developerIDNotNotarized, Result{Signed: true, TeamID: "ZYXWV98765"}, true},
		{"unsigned", unsigned, Result{}, true},
		// The team in an untrusted certificate is whatever the signer typed into it, so it must not reach an exclusion.
		{"untrusted certificate names no team", untrusted, Result{}, true},
		{"signed by Apple itself has no Developer ID team", appleSigned, Result{Signed: true}, true},
		// "signed by ..." is also how pkgutil reports certificates macOS refuses, so a prefix match would trust them.
		{"an expired certificate is not trusted", expired, Result{}, true},
		{"a revoked certificate is not trusted", revoked, Result{}, true},
		// Trusted, but its leaf is not a Developer ID: the ten characters in parentheses are whatever the issuer typed.
		{"an enterprise certificate names no team", enterprise, Result{Signed: true}, true},
		// No Status line means pkgutil never read the package, which is "cannot classify" rather than "unsigned".
		{"unreadable", `Error: could not open package`, Result{}, false},
		{"empty", "", Result{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Parse(tc.output)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// package_signing is a new wire field, so it is pinned by a round trip over its whole input space.
func TestResultJSONRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		in := Result{
			Signed:    rapid.Bool().Draw(t, "signed"),
			Notarized: rapid.Bool().Draw(t, "notarized"),
			TeamID:    rapid.StringMatching(`[A-Z0-9]{0,10}`).Draw(t, "team"),
		}
		raw, err := json.Marshal(in)
		require.NoError(t, err)
		var out Result
		require.NoError(t, json.Unmarshal(raw, &out))
		require.Equal(t, in, out)
	})
}

// The field names are the wire contract with the server rule, so they are pinned literally rather than by a round trip, which
// would pass with any names.
func TestResultWireShape(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(Result{Signed: true, Notarized: true, TeamID: "FDG8Q7N4CC"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"signed":true,"notarized":true,"team_id":"FDG8Q7N4CC"}`, string(raw))
}

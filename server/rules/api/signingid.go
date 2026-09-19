package api

import (
	"errors"
	"fmt"
	"strings"
)

// A signing_id exclusion names a code-signing identifier QUALIFIED by who signed it (issue #1024).
//
// The identifier alone is not an identity. It is whatever the signer put in the binary, and an ad-hoc signature can put anything
// there with no privilege and no Apple account:
//
//	codesign -s - -i com.vendor.tool ./payload
//
// That binary has no team, runs on Apple Silicon, and under an unqualified match it inherited every exclusion written for the
// real vendor's tool. So an operator following our own guidance, which until issue #1023 called signing_id "non-spoofable",
// built the bypass themselves.
//
// Binding the identifier to its team is what every vendor that documents this does: Jamf Protect requires a Team ID alongside
// the Signing ID, Santa writes `TEAMID:signing.id` or `platform:com.apple.x`, Elastic pairs the subject name with `trusted`.
// The form here is Santa's, because operators comparing the two products should not have to learn a second spelling.
const (
	// SigningIDQualifierSeparator divides the qualifier from the identifier: `Q6L2SF6YDW:com.vendor.tool`.
	SigningIDQualifierSeparator = ":"
	// SigningIDPlatformQualifier is the qualifier for a binary the operating system vendor ships, which carries no team ID.
	// Apple's own binaries are reported by ESF as platform binaries, and that flag is the only thing an attacker cannot set.
	SigningIDPlatformQualifier = "platform"
)

// ErrSigningIDNotQualified is a signing_id exclusion value written as a bare identifier.
var ErrSigningIDNotQualified = errors.New("a signing_id exclusion must name the team that signed it")

// QualifiedSigningID is the value a process's signature is matched against for a signing_id exclusion, or "" when the process
// cannot be matched by one at all.
//
// The empty return is the security property, not an oversight. A process with an identifier but NO team and NOT platform is
// exactly the ad-hoc case: it has asserted an identifier that nothing vouches for, so there is no qualified value it could
// equal, and every signing_id exclusion misses it. Falling back to the bare identifier there would restore the bypass.
//
// Platform is checked first because Apple's binaries carry no team ID, so the team branch would otherwise discard them.
func QualifiedSigningID(teamID, signingID string, isPlatform bool) string {
	if signingID == "" {
		return ""
	}
	if isPlatform {
		return SigningIDPlatformQualifier + SigningIDQualifierSeparator + signingID
	}
	if teamID == "" {
		return ""
	}
	return teamID + SigningIDQualifierSeparator + signingID
}

// ValidateExclusionValue rejects an exclusion value this build cannot match, so an operator is told at the API rather than
// discovering later that their exclusion never fired.
//
// Only signing_id has a shape today. The other match types are free text, a glob, or a hash whose only invalid forms are
// already caught by never matching anything.
func ValidateExclusionValue(mt ExclusionMatchType, value string) error {
	if mt != ExclusionMatchSigningID {
		return nil
	}
	qualifier, identifier, found := strings.Cut(value, SigningIDQualifierSeparator)
	if !found || qualifier == "" || identifier == "" {
		return fmt.Errorf("%w: write it as <TEAMID>:%s or %s:%s, because a bare identifier is whatever the signer typed and an "+
			"ad-hoc signature can claim any vendor's", ErrSigningIDNotQualified, value, SigningIDPlatformQualifier, value)
	}
	return nil
}

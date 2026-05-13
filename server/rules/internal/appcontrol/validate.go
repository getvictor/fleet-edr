package appcontrol

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
)

// wrapFmt is the standard `error_sentinel: hint` format used by every
// validator below. Extracted to a constant per Sonar go:S1192 so a
// future rename to a structured-error shape is a one-line change.
const wrapFmt = "%w: %s"

// ValidateRuleType reports whether rt is a recognized rule type. The
// demo cut enforces only BINARY; the other five types are recognized
// (so REST callers see the precise "unsupported yet" error rather
// than a generic "unknown" error) but the validator path below
// short-circuits with ErrAppControlUnsupportedRuleType for them.
func ValidateRuleType(rt api.RuleType) error {
	switch rt {
	case api.RuleTypeBinary:
		return nil
	case api.RuleTypeCDHash, api.RuleTypeSigningID, api.RuleTypeCertificate, api.RuleTypeTeamID, api.RuleTypePath:
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	default:
		return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidRuleType, rt)
	}
}

// hex64 matches a 64-character lowercase hex string. Used for BINARY
// (file SHA-256) and CERTIFICATE (leaf cert SHA-256) identifiers.
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hex40 matches a 40-character lowercase hex string. Used for CDHash
// identifiers.
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// teamID matches a 10-character Apple Developer Team ID (uppercase
// alphanumeric).
var teamID = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// signingID matches `<TeamID>:<bundle.id>` or `platform:<bundle.id>`.
// The bundle.id portion is ASCII alphanumeric with `.`, `_`, `-`.
var signingID = regexp.MustCompile(`^(?:[A-Z0-9]{10}|platform):[a-zA-Z0-9._-]+$`)

// ValidateIdentifier checks that the identifier value matches the
// format required by the rule type. Returns
// ErrAppControlInvalidIdentifier with the expected-shape hint string
// (the raw identifier value is NOT included so this validator does
// not turn unbounded admin input into log lines). Returns
// ErrAppControlUnsupportedRuleType if the type is on the enum but
// not yet wired through validation.
func ValidateIdentifier(rt api.RuleType, identifier string) error {
	switch rt {
	case api.RuleTypeBinary:
		if !hex64.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "BINARY rule identifier must be 64 lowercase hex characters")
		}
		return nil
	case api.RuleTypeCDHash:
		if !hex40.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "CDHASH rule identifier must be 40 lowercase hex characters")
		}
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeCertificate:
		if !hex64.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "CERTIFICATE rule identifier must be 64 lowercase hex characters")
		}
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeTeamID:
		if !teamID.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "TEAMID rule identifier must be 10 uppercase alphanumeric characters")
		}
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeSigningID:
		if !signingID.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "SIGNINGID rule identifier must be <TeamID>:<bundle.id> or platform:<bundle.id>")
		}
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypePath:
		if _, err := canonicalizePath(identifier); err != nil {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, err.Error())
		}
		return fmt.Errorf(wrapFmt, api.ErrAppControlUnsupportedRuleType, rt)
	default:
		return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidRuleType, rt)
	}
}

// CanonicalizePath returns the macOS-canonical form of an absolute
// path: rejects relative, empty, or `..`-containing paths, runs the
// input through filepath.Clean to collapse redundant slashes, then
// rewrites the /tmp, /var, /etc symlinks into their /private/...
// forms. Exported for the eventual PATH validator and the
// extension's path-match comparison; the demo cut doesn't call it on
// the hot path.
func CanonicalizePath(p string) (string, error) { return canonicalizePath(p) }

func canonicalizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	// Reject `..` segments before Clean would collapse them. An admin
	// who writes `/var/foo/../../etc/sudoers` is either confused or
	// trying to bypass an audit trail; either way the canonical form
	// should be what they wrote, not what filepath.Clean computed.
	if slices.Contains(strings.Split(p, "/"), "..") {
		return "", errors.New("path must not contain `..` segments")
	}
	cleaned := filepath.Clean(p)
	// macOS canonicalization: /tmp, /var, /etc are symlinks into /private.
	for _, prefix := range []string{"/tmp", "/var", "/etc"} {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return "/private" + cleaned, nil
		}
	}
	return cleaned, nil
}

// ValidateSeverity returns nil for a recognized severity and an
// ErrAppControlInvalidSeverity for anything else. Empty severity is
// allowed and is treated by callers as "use the default" (medium).
func ValidateSeverity(s api.Severity) error {
	if s == "" {
		return nil
	}
	switch s {
	case api.SeverityRuleLow, api.SeverityRuleMedium, api.SeverityRuleHigh, api.SeverityRuleCritical:
		return nil
	default:
		return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidSeverity, s)
	}
}

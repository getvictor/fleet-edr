package appcontrol

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fleetdm/edr/server/rules/api"
)

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
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	default:
		return fmt.Errorf("%w: %s", api.ErrAppControlInvalidRuleType, rt)
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
// format required by the rule type. Returns ErrAppControlInvalidIdentifier
// wrapped with the offending value so audit logs can record what was
// rejected. Returns ErrAppControlUnsupportedRuleType if the type is on
// the enum but not yet wired through validation.
func ValidateIdentifier(rt api.RuleType, identifier string) error {
	switch rt {
	case api.RuleTypeBinary:
		if !hex64.MatchString(identifier) {
			return fmt.Errorf("%w: BINARY rule identifier must be 64 lowercase hex characters", api.ErrAppControlInvalidIdentifier)
		}
		return nil
	case api.RuleTypeCDHash:
		if !hex40.MatchString(identifier) {
			return fmt.Errorf("%w: CDHASH rule identifier must be 40 lowercase hex characters", api.ErrAppControlInvalidIdentifier)
		}
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeCertificate:
		if !hex64.MatchString(identifier) {
			return fmt.Errorf("%w: CERTIFICATE rule identifier must be 64 lowercase hex characters", api.ErrAppControlInvalidIdentifier)
		}
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeTeamID:
		if !teamID.MatchString(identifier) {
			return fmt.Errorf("%w: TEAMID rule identifier must be 10 uppercase alphanumeric characters", api.ErrAppControlInvalidIdentifier)
		}
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypeSigningID:
		if !signingID.MatchString(identifier) {
			return fmt.Errorf("%w: SIGNINGID rule identifier must be <TeamID>:<bundle.id> or platform:<bundle.id>", api.ErrAppControlInvalidIdentifier)
		}
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	case api.RuleTypePath:
		canon, err := canonicalizePath(identifier)
		if err != nil {
			return fmt.Errorf("%w: %s", api.ErrAppControlInvalidIdentifier, err.Error())
		}
		_ = canon
		return fmt.Errorf("%w: %s", api.ErrAppControlUnsupportedRuleType, rt)
	default:
		return fmt.Errorf("%w: %s", api.ErrAppControlInvalidRuleType, rt)
	}
}

// CanonicalizePath returns the macOS-canonical form of an absolute
// path: rejects relative or empty paths, then rewrites /tmp, /var,
// /etc to their /private/... forms. Exported for the eventual PATH
// validator and the extension's path-match comparison; the demo cut
// doesn't call it.
func CanonicalizePath(p string) (string, error) { return canonicalizePath(p) }

func canonicalizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	// macOS canonicalization: /tmp, /var, /etc are symlinks into /private.
	for _, prefix := range []string{"/tmp", "/var", "/etc"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return "/private" + p, nil
		}
	}
	return p, nil
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
		return fmt.Errorf("%w: %s", api.ErrAppControlInvalidSeverity, s)
	}
}

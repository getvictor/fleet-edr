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

// wrapFmt is the standard `error_sentinel: hint` format used by every validator below. Extracted to a constant per Sonar go:S1192 so a
// future rename to a structured-error shape is a one-line change.
const wrapFmt = "%w: %s"

// ValidateRuleType reports whether rt is a recognized rule type. v0.1.0 accepts the full enum: BINARY, CDHASH, SIGNINGID, TEAMID
// (Phase A close-out, PR #289), plus CERTIFICATE and PATH (Phase B close-out, this PR). CERTIFICATE matches against the SHA-256
// of the leaf X.509 signing certificate: the surgical level for compromised-Developer-ID incident response. PATH matches against
// the canonical absolute path of the exec target; the validator's canonicalizePath is the single canonical-form authority and the
// extension applies the same rules on the AUTH callback. ErrAppControlUnsupportedRuleType is retired: every wire-enum value is now
// either accepted or invalid; an unknown token returns ErrAppControlInvalidRuleType.
func ValidateRuleType(rt api.RuleType) error {
	switch rt {
	case api.RuleTypeBinary, api.RuleTypeCDHash, api.RuleTypeSigningID, api.RuleTypeCertificate, api.RuleTypeTeamID, api.RuleTypePath:
		return nil
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

// NormalizeIdentifier returns the canonical persist-ready form of an identifier for the given rule type. For PATH rules this is
// the macOS-canonical form (filepath.Clean + /tmp,/var,/etc → /private rewrite); the extension queries against the canonical form
// at AUTH_EXEC time, so persisting any other shape (e.g. the operator's literal `/tmp/foo`) silently breaks rule match. For every
// other rule type the identifier is returned unchanged. Callers MUST run ValidateIdentifier first so they can return a typed
// validation error; this function assumes the identifier already passed validation and panics through canonicalizePath's error
// only when invoked on invalid input (operationally impossible after ValidateIdentifier succeeds). Gemini flagged the missing
// normalization step on PR #290 (#210).
func NormalizeIdentifier(rt api.RuleType, identifier string) (string, error) {
	if rt != api.RuleTypePath {
		return identifier, nil
	}
	return canonicalizePath(identifier)
}

// ValidateIdentifier checks that the identifier value matches the format required by the rule type. Returns
// ErrAppControlInvalidIdentifier with the expected-shape hint string (the raw identifier value is NOT included so this validator does
// not turn unbounded admin input into log lines). Returns ErrAppControlInvalidRuleType for tokens that aren't on the wire enum at
// all; ErrAppControlUnsupportedRuleType is retired now that every wire enum value is wired through to the extension. For PATH rules
// the format check is the canonicalization-can-succeed check; callers persist the canonical form via NormalizeIdentifier so the
// extension's AUTH_EXEC walker matches against the same string.
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
		return nil
	case api.RuleTypeCertificate:
		if !hex64.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "CERTIFICATE rule identifier must be 64 lowercase hex characters")
		}
		return nil
	case api.RuleTypeTeamID:
		if !teamID.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "TEAMID rule identifier must be 10 uppercase alphanumeric characters")
		}
		return nil
	case api.RuleTypeSigningID:
		if !signingID.MatchString(identifier) {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, "SIGNINGID rule identifier must be <TeamID>:<bundle.id> or platform:<bundle.id>")
		}
		return nil
	case api.RuleTypePath:
		if _, err := canonicalizePath(identifier); err != nil {
			return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidIdentifier, err.Error())
		}
		return nil
	default:
		return fmt.Errorf(wrapFmt, api.ErrAppControlInvalidRuleType, rt)
	}
}

// CanonicalizePath returns the macOS-canonical form of an absolute path: rejects relative, empty, or `..`-containing paths, runs the
// input through filepath.Clean to collapse redundant slashes, then rewrites the /tmp, /var, /etc symlinks into their /private/...
// forms. Exported for the eventual PATH validator and the extension's path-match comparison; the demo cut doesn't call it on the hot
// path.
func CanonicalizePath(p string) (string, error) { return canonicalizePath(p) }

func canonicalizePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	// Reject `..` segments before Clean would collapse them. An admin who writes `/var/foo/../../etc/sudoers` is either confused or trying
	// to bypass an audit trail; either way the canonical form should be what they wrote, not what filepath.Clean computed.
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

// ValidateSeverity returns nil for a recognized severity and an ErrAppControlInvalidSeverity for anything else. Empty severity is
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

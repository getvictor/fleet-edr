// Package detection provides the rule engine for evaluating event
// batches and generating alerts.
//
// Phase 3 of the modular-monolith migration moved the executable rules
// + their metadata + the Rule interface into server/rules. The types
// below survive as type aliases so the existing engine code + the
// rule-call sites (catalog/* via rules.api.Rule, plus tests that
// reference detection.Severity*) keep compiling unchanged. Phase 5
// migrates the engine itself out of this package; at that point this
// file goes away.
package detection

import (
	"github.com/fleetdm/edr/server/rules/api"
)

// Severity levels aligned with industry standards (CrowdStrike, MITRE).
// Re-exported for backward compatibility with existing rule code; new
// rule files should reference api.Severity* directly.
const (
	SeverityLow      = api.SeverityLow
	SeverityMedium   = api.SeverityMedium
	SeverityHigh     = api.SeverityHigh
	SeverityCritical = api.SeverityCritical
)

// Type aliases bridge the old detection.* names to their rules.api
// counterparts. Aliases (= keyword) make these the SAME named type at
// the language level; existing rule files that return
// detection.Documentation transparently satisfy api.Rule's
// Doc() api.Documentation requirement.
type (
	Finding       = api.Finding
	Rule          = api.Rule
	RuleMetadata  = api.RuleMetadata
	Documentation = api.Documentation
	ConfigKnob    = api.ConfigKnob
)

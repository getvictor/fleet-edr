package bootstrap

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// scopeRule is the smallest thing vendoredOrigins reads: an id, and optionally an origin and a non-detection kind.
type scopeRule struct {
	id     string
	origin string
}

func (r scopeRule) ID() string           { return r.id }
func (r scopeRule) DisplayName() string  { return r.id }
func (r scopeRule) Techniques() []string { return nil }
func (r scopeRule) Doc() rulesapi.Documentation {
	return rulesapi.Documentation{Title: r.id, EventTypes: []string{"exec"}}
}
func (r scopeRule) SupportedExclusionMatchTypes() []rulesapi.ExclusionMatchType { return nil }
func (r scopeRule) Platforms() []rulesapi.Platform {
	return []rulesapi.Platform{rulesapi.PlatformDarwin}
}
func (r scopeRule) Evaluate(context.Context, []rulesapi.Event, rulesapi.GraphReader) ([]rulesapi.Finding, error) {
	return nil, nil
}

// originRule declares foreign provenance, which is what makes a rule vendored.
type originRule struct{ scopeRule }

func (r originRule) Origin() string { return r.origin }

// projectionRule is a non-detection projection: its rule id is the operator's own policy entry.
type projectionRule struct{ originRule }

func (r projectionRule) NonDetectionKind() rulesapi.NonDetectionKind {
	return rulesapi.NonDetectionProjection
}

// spec:server-detection-rules-engine/alerts-raised-before-attribution-was-recorded-are-credited/an-alert-from-a-rule-this-project-wrote-is-left-alone
// spec:server-detection-rules-engine/alerts-raised-before-attribution-was-recorded-are-credited/an-alert-from-a-projection-is-left-alone
//
// TestVendoredOrigins covers the two exclusions that make this feature safe, and they are worth a test of their own because
// neither is visible in the SQL the backfill runs: the statement credits whatever it is handed.
//
// Getting either wrong writes something irreversible into an operator's alert history. Crediting our own rules erases the
// distinction migration 00012 preserves between an alert raised before attribution existed and one raised by us. Crediting a
// projection claims this project wrote the operator's blocklist entry, which is the bug review caught in #824.
func TestVendoredOrigins(t *testing.T) {
	t.Parallel()

	rules := []rulesapi.Rule{
		// Ours: implements no OriginNamer, so OriginOf reports the project.
		scopeRule{id: "suspicious_exec"},
		// Vendored: the only shape that may be credited.
		originRule{scopeRule{id: "proc_creation_macos_applescript", origin: "SigmaHQ"}},
		// A projection carrying a foreign origin, which must STILL be skipped: the projection test comes first.
		projectionRule{originRule{scopeRule{id: "application_control_block", origin: "SigmaHQ"}}},
		// Vendored but declaring nothing, which OriginOf reports as unknown rather than as ours. Creditable, because the
		// alternative is crediting this project for a rule that announced foreign provenance.
		originRule{scopeRule{id: "imported_but_unnamed", origin: ""}},
	}

	got := vendoredOrigins(rules)

	assert.Equal(t, map[string]string{
		"proc_creation_macos_applescript": "SigmaHQ",
		"imported_but_unnamed":            rulesapi.UnknownOrigin,
	}, got)

	assert.NotContains(t, got, "suspicious_exec",
		"our own rule must be excluded, or the pre-attribution distinction is destroyed")
	assert.NotContains(t, got, "application_control_block",
		"a projection must be excluded even when it declares an origin, since its rule id is the operator's own policy entry")
}

// TestVendoredOrigins_NoVendoredRules pins the deployment this is a no-op for, so the caller can skip the lock entirely rather
// than taking it to do nothing.
func TestVendoredOrigins_NoVendoredRules(t *testing.T) {
	t.Parallel()
	assert.Empty(t, vendoredOrigins([]rulesapi.Rule{scopeRule{id: "suspicious_exec"}}))
	assert.Empty(t, vendoredOrigins(nil))
}

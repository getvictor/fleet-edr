package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rules/api"
)

// stubRule is a minimal api.Rule. Detections use it directly; non-detections embed it and add NonDetectionKind, which is exactly
// how a real rule opts out.
type stubRule struct{ id string }

func (r stubRule) ID() string                                             { return r.id }
func (r stubRule) DisplayName() string                                    { return r.id }
func (r stubRule) Techniques() []string                                   { return []string{"T1059"} }
func (r stubRule) Doc() api.Documentation                                 { return api.Documentation{Title: r.id} }
func (r stubRule) Platforms() []api.Platform                              { return []api.Platform{api.PlatformDarwin} }
func (r stubRule) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return nil }
func (r stubRule) Evaluate(context.Context, []api.Event, api.GraphReader) ([]api.Finding, error) {
	return nil, nil
}

type stubProjection struct{ stubRule }

func (r stubProjection) NonDetectionKind() api.NonDetectionKind { return api.NonDetectionProjection }

type stubHealth struct{ stubRule }

func (r stubHealth) NonDetectionKind() api.NonDetectionKind { return api.NonDetectionHealth }

func ids(md []api.RuleMetadata) []string {
	out := make([]string, 0, len(md))
	for _, m := range md {
		out = append(out, m.ID)
	}
	return out
}

// spec:server-detection-rules-engine/non-detections-are-excluded-from-the-operator-facing-catalog/the-catalog-omits-a-non-detection
//
// TestList_OmitsNonDetections is the load-bearing assertion of the catalog split: the operator-facing surfaces
// (GET /api/rules, GET /api/attack-coverage, the generated docs) describe detections only, while the engine keeps receiving every
// registered rule. Both halves are asserted together because the value of the split is precisely that they differ; a change that
// filtered ActiveRules too would stop non-detections firing at all, which is a silent loss of alerting rather than a catalog fix.
func TestList_OmitsNonDetections(t *testing.T) {
	t.Parallel()

	rules := []api.Rule{
		stubRule{id: "detection_first"},
		stubProjection{stubRule{id: "a_projection"}},
		stubRule{id: "detection_second"},
		stubHealth{stubRule{id: "a_health_signal"}},
	}
	svc := New(rules, nil, nil)

	assert.Equal(t, []string{"detection_first", "detection_second"}, ids(svc.List()),
		"List must carry detections only, in registration order")

	active := make([]string, 0, len(svc.ActiveRules()))
	for _, r := range svc.ActiveRules() {
		active = append(active, r.ID())
	}
	assert.Equal(t, []string{"detection_first", "a_projection", "detection_second", "a_health_signal"}, active,
		"ActiveRules must still carry every registered rule so evaluation and alert persistence are unchanged")
}

// spec:server-detection-rules-engine/non-detections-are-excluded-from-the-operator-facing-catalog/a-rule-that-declares-nothing-is-a-detection
//
// TestList_AllDetections covers the ordinary case, so the filter cannot regress into dropping rules that never opted out.
func TestList_AllDetections(t *testing.T) {
	t.Parallel()

	svc := New([]api.Rule{stubRule{id: "one"}, stubRule{id: "two"}}, nil, nil)
	assert.Equal(t, []string{"one", "two"}, ids(svc.List()))
}

// TestList_EmptyCatalogs pins the two degenerate inputs the constructor documents as accepted: no rules at all, and a set that is
// entirely non-detections. The second is the one worth having, because an empty List from a non-empty rule set is exactly what a
// misapplied filter produces, and callers render it as "no rules" rather than failing.
func TestList_EmptyCatalogs(t *testing.T) {
	t.Parallel()

	t.Run("no rules", func(t *testing.T) {
		t.Parallel()
		assert.Empty(t, New(nil, nil, nil).List())
	})

	t.Run("only non-detections", func(t *testing.T) {
		t.Parallel()
		svc := New([]api.Rule{stubProjection{stubRule{id: "p"}}, stubHealth{stubRule{id: "h"}}}, nil, nil)
		assert.Empty(t, svc.List(), "a catalog of only non-detections lists nothing")
		require.Len(t, svc.ActiveRules(), 2, "but both still evaluate")
	})
}

// TestList_CarriesFullMetadata guards the fields the filter loop copies. The filter added a continue to this loop, and a copy that
// silently dropped a field would surface as missing documentation in the UI rather than as a test failure anywhere else.
func TestList_CarriesFullMetadata(t *testing.T) {
	t.Parallel()

	got := New([]api.Rule{stubRule{id: "r"}}, nil, nil).List()
	require.Len(t, got, 1)
	assert.Equal(t, "r", got[0].ID)
	assert.Equal(t, []string{"T1059"}, got[0].Techniques)
	assert.Equal(t, "r", got[0].Doc.Title)
	assert.Equal(t, []api.Platform{api.PlatformDarwin}, got[0].Platforms)
	assert.Equal(t, api.DetectionRuleModeAlert, got[0].DefaultMode,
		"a rule declaring no default mirrors alert, never the empty string, so a consumer never has to guess")
}

// spec:server-detection-rules-engine/a-rule-declares-the-mode-it-operates-in-absent-configuration/a-declared-default-is-listed-on-the-rule-catalog
//
// TestList_MirrorsADeclaredDefaultMode pins that a rule's declared default reaches the operator-facing catalog.
//
// Without it the declaration is invisible: the rule-settings surface lists only settings an operator created, so a rule left at its
// own monitor default appears on no surface at all and reads as alerting. That is the difference between a rule an operator has
// chosen to silence and one that was never going to fire, and an operator has to be able to tell them apart.
func TestList_MirrorsADeclaredDefaultMode(t *testing.T) {
	t.Parallel()

	got := New([]api.Rule{monitorStubRule{stubRule{id: "imported"}}}, nil, nil).List()
	require.Len(t, got, 1)
	assert.Equal(t, api.DetectionRuleModeMonitor, got[0].DefaultMode)
}

// monitorStubRule is a stubRule that declares monitor, standing in for an imported rule.
type monitorStubRule struct{ stubRule }

func (monitorStubRule) DefaultMode() api.DetectionRuleMode { return api.DetectionRuleModeMonitor }

// spec:server-detection-rules-engine/operator-toggling-of-individual-rules/the-catalog-reports-the-mode-a-rule-runs-in-not-only-the-one-it-declares
//
// TestList_ReportsTheModeInForceAndItsSource pins that the catalog reports the mode a rule RUNS IN, not only the one it declares.
//
// The spec requires a rule an operator has disabled to stay listed "with its mode indicated", and a declaration is not that: a
// setting overrides it, so a disabled rule was listed looking exactly like one that alerts. Reporting the source alongside is what
// separates a rule sitting in monitor because that is how it shipped from one an operator moved there.
func TestList_ReportsTheModeInForceAndItsSource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		rule         api.Rule
		resolver     api.GlobalRuleModeResolver
		wantMode     api.DetectionRuleMode
		wantSource   api.RuleModeSource
		wantDeclared api.DetectionRuleMode
	}{
		{
			name:         "a setting overrides the rule's declaration",
			rule:         monitorStubRule{stubRule{id: "imported"}},
			resolver:     stubGlobalModes{"imported": {Mode: api.DetectionRuleModeDisabled, Source: api.RuleModeSourceSetting}},
			wantMode:     api.DetectionRuleModeDisabled,
			wantSource:   api.RuleModeSourceSetting,
			wantDeclared: api.DetectionRuleModeMonitor,
		},
		{
			name:         "no setting leaves the rule in its declared mode",
			rule:         monitorStubRule{stubRule{id: "imported"}},
			resolver:     stubGlobalModes{},
			wantMode:     api.DetectionRuleModeMonitor,
			wantSource:   api.RuleModeSourceDefault,
			wantDeclared: api.DetectionRuleModeMonitor,
		},
		{
			name:         "no resolver at all reports the declaration, which is the docs-generator path",
			rule:         monitorStubRule{stubRule{id: "imported"}},
			resolver:     nil,
			wantMode:     api.DetectionRuleModeMonitor,
			wantSource:   api.RuleModeSourceDefault,
			wantDeclared: api.DetectionRuleModeMonitor,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := New([]api.Rule{tc.rule}, tc.resolver, nil).List()
			require.Len(t, got, 1)
			assert.Equal(t, tc.wantMode, got[0].Mode)
			assert.Equal(t, tc.wantSource, got[0].ModeSource)
			assert.Equal(t, tc.wantDeclared, got[0].DefaultMode,
				"the declaration is reported alongside the mode in force, not replaced by it")
		})
	}
}

// stubGlobalModes resolves a canned global mode per rule id, and reports the rule's own default for any id it does not name.
type stubGlobalModes map[string]api.GlobalRuleMode

func (m stubGlobalModes) GlobalRuleMode(ruleID string, ruleDefault api.DetectionRuleMode) api.GlobalRuleMode {
	if got, ok := m[ruleID]; ok {
		return got
	}
	return api.GlobalRuleMode{Mode: ruleDefault, Source: api.RuleModeSourceDefault}
}

// spec:server-detection-rules-engine/the-vendored-upstream-corpus-is-registered-and-does-not-alert-until-promoted/a-vendored-rule-is-attributed-on-the-operator-facing-catalog
//
// TestList_CreditsAVendoredRulesSource pins that a vendored rule's attribution reaches the operator-facing catalog.
//
// The corpus is licensed under DRL 1.1 and its rules are shipped and exported unmodified, so attribution travels with the rule
// itself. This is what carries it onto the surfaces built FROM the rule rather than out of it: the generated reference and the UI
// render a vendored rule exactly like one this project wrote, so without this an operator cannot tell whose rule they are reading.
func TestList_CreditsAVendoredRulesSource(t *testing.T) {
	t.Parallel()

	got := New([]api.Rule{vendoredStubRule{stubRule{id: "vendored"}}, stubRule{id: "ours"}}, nil, nil).List()
	require.Len(t, got, 2)
	assert.Equal(t, "Upstream, by Someone", got[0].Origin)
	assert.Empty(t, got[1].Origin, "a rule this project wrote announces no origin")
}

// vendoredStubRule is a stubRule that names an upstream source, standing in for an imported rule.
type vendoredStubRule struct{ stubRule }

func (vendoredStubRule) Origin() string { return "Upstream, by Someone" }

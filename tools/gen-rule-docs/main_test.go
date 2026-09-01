package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// TestEveryRuleHasDocs is the gate that prevents shipping a new detection rule without operator-facing documentation.
// detection.Rule.Doc() returns a struct, so a rule can technically return the zero value, which this test catches. Severity is also
// gated to one of the documented constants so a typo'd value (e.g. "urgent") fails the test instead of silently producing a broken UI
// severity pill class name and a markdown reference that disagrees with the rest of the codebase.
func TestEveryRuleHasDocs(t *testing.T) {
	t.Parallel()
	allowedSeverities := map[string]struct{}{
		rulesapi.SeverityLow:      {},
		rulesapi.SeverityMedium:   {},
		rulesapi.SeverityHigh:     {},
		rulesapi.SeverityCritical: {},
	}
	for _, r := range allRegisteredRules() {
		t.Run(r.ID, func(t *testing.T) {
			t.Parallel()
			d := r.Doc
			assert.NotEmpty(t, d.Title, "Doc.Title must be set")
			assert.NotEmpty(t, d.Summary, "Doc.Summary must be set (one-line tooltip)")
			assert.NotEmpty(t, d.Description, "Doc.Description must be set (long-form spec)")
			assert.NotEmpty(t, d.Severity, "Doc.Severity must be set")
			assert.Contains(t, allowedSeverities, d.Severity,
				"Doc.Severity must be one of rulesapi.SeverityLow|Medium|High|Critical")
			assert.NotEmpty(t, d.EventTypes, "Doc.EventTypes must list at least one event type")
		})
	}
}

// TestRenderProducesIndexEntryPerRule sanity-checks the markdown structure: the index table at the top of the doc must contain a row
// for every registered rule. Without this, a missing rule could slip through if the generator's loop somehow short-circuited.
func TestRenderProducesIndexEntryPerRule(t *testing.T) {
	t.Parallel()
	rs := allRegisteredRules()
	var buf bytes.Buffer
	require.NoError(t, render(&buf, rs))
	out := buf.String()

	for _, r := range rs {
		// Index entry: the row link uses a backtick-wrapped code span.
		assert.Contains(t, out, "[`"+r.ID+"`]", "rule %q missing from index table", r.ID)
		// Section heading: "## <id>".
		assert.Contains(t, out, "## "+r.ID+"\n", "rule %q missing as a section heading", r.ID)
	}
}

// TestRenderTechniqueLinks checks that every technique in the catalog is rendered as a clickable MITRE link, with sub-technique dots
// translated to slashes (the URL convention attack.mitre.org expects).
func TestRenderTechniqueLinks(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, render(&buf, allRegisteredRules()))
	out := buf.String()

	// Sub-technique: T1574.006 must appear as both the visible label
	// (with the dot) AND inside a URL where the dot is a slash.
	assert.Contains(t, out, "[`T1574.006`]")
	assert.Contains(t, out, "https://attack.mitre.org/techniques/T1574/006/")
	// Top-level technique: no slash translation needed.
	assert.Contains(t, out, "https://attack.mitre.org/techniques/T1059/")
}

// TestRenderCarriesAttributionAndReferences pins that the generated reference credits every rule and cites the vendored ones
// (issue #765).
//
// RuleDetail's doc promises this markdown is generated from the same Doc() definitions and therefore stays aligned with the rule
// page. Adding references to the page and not here broke that promise silently, since nothing compared the two surfaces. Copilot
// caught it on #824; this is what would have.
func TestRenderCarriesAttributionAndReferences(t *testing.T) {
	t.Parallel()
	rs := allRegisteredRules()
	var buf bytes.Buffer
	require.NoError(t, render(&buf, rs))
	out := buf.String()

	var cited int
	for _, r := range rs {
		// Attribution is total, so every rule in the catalog names a source. An empty one would render a blank table cell.
		assert.NotEmptyf(t, r.Origin, "rule %q reports no origin, so the generated reference credits nobody for it", r.ID)
		assert.Containsf(t, out, "| Source | "+r.Origin+" |", "rule %q missing its Source row", r.ID)

		if len(r.Doc.References) == 0 {
			continue
		}
		cited++
		for _, ref := range r.Doc.References {
			assert.Containsf(t, out, "- "+ref, "rule %q missing citation %q", r.ID, ref)
		}
	}
	// The vendored corpus is the reason references exist, so a run where nothing is cited means the parse path broke upstream of
	// this renderer rather than that the catalog happens to cite nothing.
	assert.Positive(t, cited, "no rule in the catalog carries a citation")
}

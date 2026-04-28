package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection"
)

// TestEveryRuleHasDocs is the gate that prevents shipping a new detection
// rule without operator-facing documentation. detection.Rule.Doc() returns
// a struct, so a rule can technically return the zero value — this test
// catches that. Severity is also gated to one of the documented constants
// so a typo'd value (e.g. "urgent") fails the test instead of silently
// producing a broken UI severity pill class name and a markdown reference
// that disagrees with the rest of the codebase.
func TestEveryRuleHasDocs(t *testing.T) {
	allowedSeverities := map[string]struct{}{
		detection.SeverityLow:      {},
		detection.SeverityMedium:   {},
		detection.SeverityHigh:     {},
		detection.SeverityCritical: {},
	}
	for _, r := range allRegisteredRules() {
		t.Run(r.ID(), func(t *testing.T) {
			d := r.Doc()
			assert.NotEmpty(t, d.Title, "Doc().Title must be set")
			assert.NotEmpty(t, d.Summary, "Doc().Summary must be set (one-line tooltip)")
			assert.NotEmpty(t, d.Description, "Doc().Description must be set (long-form spec)")
			assert.NotEmpty(t, d.Severity, "Doc().Severity must be set")
			assert.Contains(t, allowedSeverities, d.Severity,
				"Doc().Severity must be one of detection.SeverityLow|Medium|High|Critical")
			assert.NotEmpty(t, d.EventTypes, "Doc().EventTypes must list at least one event type")
		})
	}
}

// TestRenderProducesIndexEntryPerRule sanity-checks the markdown structure:
// the index table at the top of the doc must contain a row for every
// registered rule. Without this, a missing rule could slip through if the
// generator's loop somehow short-circuited.
func TestRenderProducesIndexEntryPerRule(t *testing.T) {
	rs := allRegisteredRules()
	var buf bytes.Buffer
	require.NoError(t, render(&buf, rs))
	out := buf.String()

	for _, r := range rs {
		// Index entry: the row link uses a backtick-wrapped code span.
		assert.Contains(t, out, "[`"+r.ID()+"`]", "rule %q missing from index table", r.ID())
		// Section heading: "## <id>".
		assert.Contains(t, out, "## "+r.ID()+"\n", "rule %q missing as a section heading", r.ID())
	}
}

// TestRenderTechniqueLinks checks that every technique in the catalog is
// rendered as a clickable MITRE link, with sub-technique dots translated to
// slashes (the URL convention attack.mitre.org expects).
func TestRenderTechniqueLinks(t *testing.T) {
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

// TestRenderConfigKnobsListed confirms that rules with config knobs surface
// their env var, type, and description in the per-rule Configuration table.
func TestRenderConfigKnobsListed(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, render(&buf, allRegisteredRules()))
	out := buf.String()

	for _, env := range []string{
		"EDR_LAUNCHAGENT_ALLOWLIST",
		"EDR_LAUNCHDAEMON_TEAMID_ALLOWLIST",
		"EDR_SUDOERS_WRITER_ALLOWLIST",
		"EDR_SUSPICIOUS_EXEC_PARENT_ALLOWLIST",
	} {
		assert.Contains(t, out, "`"+env+"`",
			"expected config env var %q to appear in generated docs", env)
	}
}

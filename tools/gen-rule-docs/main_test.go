package main

import (
	"bytes"
	"net/url"
	"strings"
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
			// The RENDERED form, not the raw string: a citation that is not an http(s) URL is deliberately emitted as an inert
			// code span, so asserting the raw value here would forbid the safety this document depends on.
			assert.Containsf(t, out, "- "+mdReference(ref), "rule %q missing citation %q", r.ID, ref)
		}
	}
	// The vendored corpus is the reason references exist, so a run where nothing is cited means the parse path broke upstream of
	// this renderer rather than that the catalog happens to cite nothing.
	assert.Positive(t, cited, "no rule in the catalog carries a citation")
}

// TestMDReference pins that a citation this project did not write cannot become markdown (issue #765, found by Qodo).
//
// The upstream corpus is vendored verbatim, so a reference is attacker-influenceable in the same sense the UI already treats it:
// a markdown link in a raw bullet renders as a working link inside our own operator documentation, which is a more trustworthy
// frame than a web page. Only a complete http(s) URL is allowed to stay followable.
func TestMDReference(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"an https URL becomes an explicit autolink", "https://redcanary.com/blog/x", "<https://redcanary.com/blog/x>"},
		{"an http URL becomes an explicit autolink", "http://example.com/a", "<http://example.com/a>"},
		{"a markdown link is neutralised", "[citation](//attacker.example)", "`[citation](//attacker.example)`"},
		{"a javascript URL is not followable", "javascript:alert(1)", "`javascript:alert(1)`"},
		{"free text is inert", "Internal research note, 2026", "`Internal research note, 2026`"},
		{"a scheme-relative URL is not an absolute http URL", "//attacker.example", "`//attacker.example`"},
		{"an embedded newline cannot restructure the document", "a\nb", "`a b`"},
		{"a CRLF collapses too", "a\r\nb", "`a b`"},
		// The fence has to outgrow the value or the span ends early and the tail escapes as live markdown.
		{"a backtick in the value grows the fence", "a`b", "``a`b``"},
		{"a double backtick grows it further", "a``b", "```a``b```"},
		{"an empty reference renders as an empty span", "   ", "``"},
		// Padding is required here and only here: without the spaces the content's own backtick merges with the fence.
		{"a value ending in a backtick keeps its padding", "ab`", "`` ab` ``"},
		// The reason the URL branch re-serialises instead of echoing: url.Parse accepts a valid prefix followed by anything, so
		// this reports scheme https and host safe.example. Emitting the input back would render the attacker's image inside our
		// own operator documentation. Percent-encoding is what makes it inert.
		{"markdown trailing a valid URL prefix is encoded, not echoed",
			"https://safe.example/a ![pixel](https://attacker.example/p)",
			"<https://safe.example/a%20%21%5Bpixel%5D%28https://attacker.example/p%29>"},
		{"angle brackets in a URL cannot break the autolink", "https://safe.example/a<b>c", "<https://safe.example/a%3Cb%3Ec>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, mdReference(tc.ref))
		})
	}
}

// TestRenderNeverEmitsAnUnvettedLink is the whole-document check behind the unit test above: no citation in the real generated
// reference is followable unless it is an http(s) URL.
func TestRenderNeverEmitsAnUnvettedLink(t *testing.T) {
	t.Parallel()
	rs := allRegisteredRules()
	var buf bytes.Buffer
	require.NoError(t, render(&buf, rs))

	for _, r := range rs {
		for _, ref := range r.Doc.References {
			rendered := mdReference(ref)
			if strings.HasPrefix(rendered, "<") {
				u, err := url.Parse(strings.Trim(rendered, "<>"))
				require.NoErrorf(t, err, "rule %q citation %q renders as a link but does not parse", r.ID, ref)
				assert.Containsf(t, []string{"http", "https"}, u.Scheme,
					"rule %q citation %q renders as a link with scheme %q", r.ID, ref, u.Scheme)
				continue
			}
			assert.Containsf(t, rendered, "`", "rule %q citation %q is neither a vetted URL nor an inert span", r.ID, ref)
		}
	}
}

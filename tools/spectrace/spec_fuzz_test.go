package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzSplitRequirementText exercises the normaliser both archive-verify sides go through, on input the operator points at with
// `--specs-dir` and on the archived deltas under `--changes-dir`. Neither is untrusted in the security sense, but both are
// hand-written Markdown, and a parser that panics on a malformed heading takes the release step down at the worst moment.
//
// Three invariants, all of them things the comparison relies on rather than restatements of the code:
//
//   - No output line is empty or carries leading or trailing whitespace. A blank line would compare equal across every span and
//     make one requirement's text look present in another's.
//   - Every scenario key is slug-stable. The delta side and the canonical side derive the key independently, so a key that
//     changes under a second slugify would put the same scenario under two names.
//   - No span holds more logical lines than the input held physical ones. Each output line is a join of one or more input lines,
//     so anything else means text was invented.
func FuzzSplitRequirementText(f *testing.F) {
	f.Add("### Requirement: The thing\nBody.\n\n#### Scenario: One\n- **THEN** it does\n")
	f.Add("#### Scenario: \n\n#### Scenario: One\n#### Scenario: One\n")
	f.Add("### Requirement:\n\t \n#### Notes\n- a\n\n\n- b\n")
	f.Add("#### Scenario: Ünïcode ✓\n  spaced  out  \n")

	f.Fuzz(func(t *testing.T, doc string) {
		lines := strings.Split(doc, "\n")
		got := splitRequirementText(lines)

		total := len(got.body)
		for scenario, spanLines := range got.scenarios {
			require.Equal(t, scenario, slugify(scenario), "scenario keys must be slug-stable")
			total += len(spanLines)
		}
		require.LessOrEqual(t, total, len(lines), "every output line joins at least one input line")

		spans := [][]string{got.body}
		for _, spanLines := range got.scenarios {
			spans = append(spans, spanLines)
		}
		for _, span := range spans {
			for _, line := range span {
				require.NotEmpty(t, line, "a blank line would compare equal across every span")
				require.Equal(t, strings.TrimSpace(line), line, "leading or trailing whitespace defeats the comparison")
			}
		}
	})
}

// FuzzParseSpec covers the walk that feeds the fuzzed normaliser, since it decides which lines belong to which requirement.
//
// The invariant is the one the two sides of archive-verify agree on: a scenario's canonical ID is its spec directory, its
// requirement's slug and its own slug, joined. Anything else and a marker resolves to a scenario the report cannot name.
func FuzzParseSpec(f *testing.F) {
	f.Add("### Requirement: The thing\nIt SHALL do it.\n\n#### Scenario: One\n- **THEN** it does\n")
	f.Add("## Requirements\n### Requirement: A\n#### Scenario: B\n### Requirement: A\n#### Scenario: B\n")
	f.Add("#### Scenario: orphan with no requirement\n")

	f.Fuzz(func(t *testing.T, doc string) {
		scenarios, bodies, err := parseSpec(strings.NewReader(doc), "cap", "cap/spec.md")
		require.NoError(t, err, "a string reader cannot fail, so an error here is a parser fault")
		for _, s := range scenarios {
			require.Equal(t, "cap/"+slugify(s.Requirement)+"/"+slugify(s.Title), s.ID)
			require.Contains(t, bodies, slugify(s.Requirement), "a scenario's requirement must have collected its own lines")
		}
	})
}

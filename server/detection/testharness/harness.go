// Package testharness runs detection rules against JSON fixtures so new
// rule PRs can be reviewed as "here are the events, here are the expected
// findings" — no boilerplate per test. Existing rules keep their bespoke
// tests (see server/detection/rules/*_test.go); new rules should prefer
// this harness.
//
// Fixture layout:
//
//	server/detection/rules/fixtures/<rule_id>/<case>.json
//
// Each JSON file is one Go sub-test. Its name (minus .json) becomes the
// sub-test name, so `positive_dump_keychain.json` prints as
// `positive_dump_keychain` in test output. Expected-no-findings cases
// just set "expected_findings": [] (or omit the key).
//
// What the harness does per case:
//  1. Spin up an isolated MySQL test store.
//  2. s.InsertEvents(events) — server stamps ingested_at_ns here.
//  3. graph.Builder.ProcessBatch(events) — materialises the process
//     rows the rule depends on (fork/exec/exit).
//  4. rule.Evaluate(events, store) and check the findings shape against
//     the fixture's expected_findings.
//
// What the harness does NOT do:
//   - Persist findings as alerts (the engine does that in production).
//     Rules are tested in isolation; Engine.Evaluate behaviour is
//     covered separately by engine_test.go.
package testharness

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/graph"
	"github.com/fleetdm/edr/server/store"
)

// FixtureCase is one named scenario loaded from a fixture JSON file.
type FixtureCase struct {
	// Events are the event envelopes the rule will see. Fork + exec
	// pairs are expected for any process the rule's Evaluate dereferences
	// via GetProcessByPID; the harness calls ProcessBatch to materialise
	// them before Evaluate.
	Events []store.Event `json:"events"`
	// ExpectedFindings is the assertion target. An empty slice (or
	// omitted key) means "rule must not fire for these events" — a
	// negative test.
	ExpectedFindings []ExpectedFinding `json:"expected_findings,omitempty"`
}

// ExpectedFinding describes a finding the rule is expected to produce.
// Strict fields (RuleID + Severity) are equality-matched; soft fields
// (DescriptionContains, EventIDs) are optional substring / set
// assertions so fixtures don't break when descriptions are reworded.
type ExpectedFinding struct {
	RuleID              string   `json:"rule_id"`
	Severity            string   `json:"severity"`
	DescriptionContains string   `json:"description_contains,omitempty"`
	EventIDs            []string `json:"event_ids,omitempty"`
}

// Replay discovers every *.json file under fixtureDir, runs each as a
// sub-test, and asserts the findings match. Fails t if fixtureDir is
// missing or has no cases — a silent pass when all cases accidentally
// get moved is worse than a loud fail.
func Replay(t *testing.T, rule detection.Rule, fixtureDir string) {
	t.Helper()
	entries, err := os.ReadDir(fixtureDir)
	require.NoError(t, err, "fixture dir not found: %s", fixtureDir)

	var cases []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		cases = append(cases, e.Name())
	}
	require.NotEmpty(t, cases, "no *.json fixtures in %s", fixtureDir)

	for _, name := range cases {
		caseName := strings.TrimSuffix(name, ".json")
		path := filepath.Join(fixtureDir, name)
		t.Run(caseName, func(t *testing.T) {
			runCase(t, rule, path)
		})
	}
}

func runCase(t *testing.T, rule detection.Rule, path string) {
	t.Helper()
	// Path is constructed from a fixed fixtureDir + a filename we
	// already discovered via os.ReadDir on that same directory, so
	// there's no user-input taint. gosec's G304 is a false positive
	// in the test-harness context.
	raw, err := os.ReadFile(path) //nolint:gosec // fixture path, not user input
	require.NoError(t, err)

	var c FixtureCase
	require.NoError(t, json.Unmarshal(raw, &c), "decode %s", path)

	s := store.OpenTestStore(t)
	ctx := t.Context()
	require.NoError(t, s.InsertEvents(ctx, c.Events), "insert events")

	builder := graph.NewBuilder(s, slog.Default())
	require.NoError(t, builder.ProcessBatch(ctx, c.Events), "materialize")

	findings, err := rule.Evaluate(ctx, c.Events, s)
	require.NoError(t, err, "rule.Evaluate")

	require.Len(t, findings, len(c.ExpectedFindings),
		"finding count mismatch — expected %d, got %d",
		len(c.ExpectedFindings), len(findings))

	// Positional match. Rules in this codebase emit findings in
	// deterministic order (iteration over sorted event batches); if a
	// rule ever goes non-deterministic we should address it in the rule
	// itself, not here.
	for i, want := range c.ExpectedFindings {
		got := findings[i]
		assert.Equal(t, want.RuleID, got.RuleID, "finding[%d].rule_id", i)
		assert.Equal(t, want.Severity, got.Severity, "finding[%d].severity", i)
		if want.DescriptionContains != "" {
			assert.Contains(t, got.Description, want.DescriptionContains,
				"finding[%d].description must contain %q", i, want.DescriptionContains)
		}
		if len(want.EventIDs) > 0 {
			assert.ElementsMatch(t, want.EventIDs, got.EventIDs,
				"finding[%d].event_ids", i)
		}
	}
}

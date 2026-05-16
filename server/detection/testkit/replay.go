package testkit

// Replay runs detection rules against JSON fixtures so new rule PRs
// can be reviewed as "here are the events, here are the expected
// findings" — no per-rule boilerplate.
//
// Fixture layout:
//
//	<fixtureDir>/<case>.json
//
// Each JSON file is one Go sub-test. Its name (minus .json) becomes
// the sub-test name, so `positive_dump_keychain.json` prints as
// `positive_dump_keychain` in test output. Expected-no-findings cases
// just set "expected_findings": [] (or omit the key).
//
// What Replay does per case:
//
//  1. Spin up an isolated MySQL test DB via testdb.Open.
//  2. Apply detection's schema + migrations via testkit's own helpers
//     (no bootstrap import needed at the call site).
//  3. s.InsertEvents(events) — server stamps ingested_at_ns here.
//  4. graph.Builder.ProcessBatch(events) — materialises the process
//     rows the rule depends on (fork/exec/exit).
//  5. rule.Evaluate(events, store) and check the findings shape against
//     the fixture's expected_findings.
//
// What Replay does NOT do: persist findings as alerts (the engine
// does that in production). Rules are tested in isolation;
// Engine.Evaluate behaviour is covered by engine_test.go.

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/testdb"
)

// FixtureCase is one named scenario loaded from a fixture JSON file.
type FixtureCase struct {
	// Events are the event envelopes the rule will see. Fork + exec pairs are expected for any process the rule's Evaluate dereferences
	// via GetProcessByPID; Replay calls ProcessBatch to materialise them before Evaluate.
	Events []detectionapi.Event `json:"events"`
	// ExpectedFindings is the assertion target. An empty slice (or omitted key) means "rule must not fire for these events" — a negative
	// test.
	ExpectedFindings []ExpectedFinding `json:"expected_findings,omitempty"`
}

// ExpectedFinding describes a finding the rule is expected to produce. Strict fields (RuleID + Severity) are equality-matched;
// soft fields (DescriptionContains, EventIDs) are optional substring / set assertions so fixtures don't break when descriptions are
// reworded.
type ExpectedFinding struct {
	RuleID              string   `json:"rule_id"`
	Severity            string   `json:"severity"`
	DescriptionContains string   `json:"description_contains,omitempty"`
	EventIDs            []string `json:"event_ids,omitempty"`
}

// Replay discovers every *.json file at or below fixtureDir
// (recursively), runs each as a sub-test, and asserts the findings
// match. Fails t if fixtureDir is missing or has no cases — a silent
// pass when all cases accidentally get moved is worse than a loud fail.
//
// Sub-tests are named by the fixture's path relative to fixtureDir
// with the `.json` suffix stripped, so a file at
// `<dir>/sudoers/positive_overwrite.json` renders as sub-test name
// `sudoers/positive_overwrite` and scoping via `-run` works naturally.
func Replay(t *testing.T, rule rulesapi.Rule, fixtureDir string) {
	t.Helper()

	var cases []string
	err := filepath.WalkDir(fixtureDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		cases = append(cases, path)
		return nil
	})
	require.NoError(t, err, "walk fixture dir: %s", fixtureDir)
	require.NotEmpty(t, cases, "no *.json fixtures under %s", fixtureDir)

	for _, path := range cases {
		rel, err := filepath.Rel(fixtureDir, path)
		require.NoError(t, err)
		caseName := strings.TrimSuffix(rel, ".json")
		t.Run(caseName, func(t *testing.T) {
			runCase(t, rule, path)
		})
	}
}

func runCase(t *testing.T, rule rulesapi.Rule, path string) {
	t.Helper()
	// Path is constructed from a fixed fixtureDir + a filename we already discovered via filepath.WalkDir on that same directory,
	// so there's no user-input taint. gosec's G304 is a false positive in the test-harness context.
	raw, err := os.ReadFile(path) //nolint:gosec // fixture path, not user input
	require.NoError(t, err)

	var c FixtureCase
	require.NoError(t, json.Unmarshal(raw, &c), "decode %s", path)

	db := testdb.Open(t)
	ctx := t.Context()
	require.NoError(t, ApplySchema(ctx, db), "apply detection schema")
	mysqlStore, err := mysql.New(db)
	require.NoError(t, err, "wrap test store")
	require.NoError(t, mysqlStore.InsertEvents(ctx, c.Events), "insert events")

	builder := graph.NewBuilder(mysqlStore, slog.Default())
	require.NoError(t, builder.ProcessBatch(ctx, c.Events), "materialize")

	findings, err := rule.Evaluate(ctx, c.Events, mysqlStore)
	require.NoError(t, err, "rule.Evaluate")

	require.Len(t, findings, len(c.ExpectedFindings),
		"finding count mismatch — expected %d, got %d",
		len(c.ExpectedFindings), len(findings))

	// Positional match. Rules in this codebase emit findings in
	// deterministic order (iteration over sorted event batches); if
	// a rule ever goes non-deterministic we should address it in the
	// rule itself, not here.
	//
	// Range over findings rather than ExpectedFindings so nilaway can
	// see that we never index a nil slice — rule.Evaluate returns a
	// nil []Finding for no-match cases, which is Go-idiomatic but
	// trips nilaway's can-be-nil flow without this rewrite. The
	// require.Len above guarantees ExpectedFindings[i] is in range.
	for i, got := range findings {
		want := c.ExpectedFindings[i]
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

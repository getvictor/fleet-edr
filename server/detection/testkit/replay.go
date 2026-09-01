package testkit

// Replay runs detection rules against JSON fixtures so new rule PRs
// can be reviewed as "here are the events, here are the expected
// findings" with no per-rule boilerplate.
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
//  3. archive.Insert(events): seeds the in-memory event archive the
//     rule's correlation + evidence reads delegate to (ADR-0015).
//  4. graph.Builder.ProcessBatch(events): materialises the process
//     rows the rule depends on (fork/exec/exit).
//  5. rule.Evaluate(events, store) and check the findings shape against
//     the fixture's expected_findings.
//
// What Replay does NOT do: persist findings as alerts (the engine
// does that in production). Rules are tested in isolation;
// Engine.Evaluate behaviour is covered by engine_test.go.

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionapi "github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/graph"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/testdb"
	visibilitytestkit "github.com/fleetdm/edr/server/visibility/testkit"
)

// FixtureCase is one named scenario loaded from a fixture JSON file.
type FixtureCase struct {
	// Events are the event envelopes the rule will see. Fork + exec pairs are expected for any process the rule's Evaluate dereferences
	// via GetProcessByPID; Replay calls ProcessBatch to materialise them before Evaluate.
	Events []detectionapi.Event `json:"events"`
	// ExpectedFindings is the assertion target. An empty slice (or omitted key) means "rule must not fire for these events": a negative
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

// FixturePaths returns every fixture file at or below dir, sorted, so that DISCOVERY is defined once.
//
// Three places ask "what are this rule's fixtures": Replay, the catalog's coverage gate, and its dispatch-equivalence gate. When
// two of them walked recursively and the third globbed one level, a fixture in a subdirectory was replayed and counted as
// coverage while silently bypassing dispatch equivalence. A shared answer is the only way those three cannot drift again.
//
// A missing directory is reported as fs.ErrNotExist rather than as an empty list, because "this rule has no fixtures" and "this
// rule's fixtures moved" are different problems and only the caller knows which one it is gating on.
func FixturePaths(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	return paths, nil
}

// LoadFixture decodes one fixture file. Paired with FixturePaths so the shape a caller gets is defined once too.
func LoadFixture(path string) (FixtureCase, error) {
	// The path comes from FixturePaths walking a directory the caller named, so there is no user-input taint.
	raw, err := os.ReadFile(path) //nolint:gosec // fixture path, not user input
	if err != nil {
		return FixtureCase{}, fmt.Errorf("read %s: %w", path, err)
	}
	var c FixtureCase
	if err := json.Unmarshal(raw, &c); err != nil {
		return FixtureCase{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return c, nil
}

// Replay discovers every *.json file at or below fixtureDir
// (recursively), runs each as a sub-test, and asserts the findings
// match. Fails t if fixtureDir is missing or has no cases: a silent
// pass when all cases accidentally get moved is worse than a loud fail.
//
// Sub-tests are named by the fixture's path relative to fixtureDir
// with the `.json` suffix stripped, so a file at
// `<dir>/sudoers/positive_overwrite.json` renders as sub-test name
// `sudoers/positive_overwrite` and scoping via `-run` works naturally.
func Replay(t *testing.T, rule rulesapi.Rule, fixtureDir string) {
	t.Helper()

	cases, err := FixturePaths(fixtureDir)
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
	c, err := LoadFixture(path)
	require.NoError(t, err)

	db := testdb.Open(t)
	ctx := t.Context()
	require.NoError(t, ApplySchema(ctx, db), "apply detection schema")
	archive := visibilitytestkit.NewMemArchive()
	mysqlStore, err := mysql.New(db, archive, nil)
	require.NoError(t, err, "wrap test store")
	require.NoError(t, archive.Insert(ctx, c.Events), "seed archive")

	builder := graph.NewBuilder(mysqlStore, slog.Default())
	require.NoError(t, builder.ProcessBatch(ctx, c.Events), "materialize")

	findings, err := rule.Evaluate(ctx, c.Events, mysqlStore)
	require.NoError(t, err, "rule.Evaluate")

	// Computed once per case rather than per finding: it is a property of the RULE, not of anything it produced.
	nd, isNonDetection := rule.(rulesapi.NonDetection)
	isProjection := isNonDetection && nd.NonDetectionKind() == rulesapi.NonDetectionProjection

	require.Len(t, findings, len(c.ExpectedFindings),
		"finding count mismatch: expected %d, got %d",
		len(c.ExpectedFindings), len(findings))

	// Positional match. Rules in this codebase emit findings in
	// deterministic order (iteration over sorted event batches); if
	// a rule ever goes non-deterministic we should address it in the
	// rule itself, not here.
	//
	// Range over findings rather than ExpectedFindings so nilaway can
	// see that we never index a nil slice: rule.Evaluate returns a
	// nil []Finding for no-match cases, which is Go-idiomatic but
	// trips nilaway's can-be-nil flow without this rewrite. The
	// require.Len above guarantees ExpectedFindings[i] is in range.
	for i, got := range findings {
		want := c.ExpectedFindings[i]
		assert.Equal(t, want.RuleID, got.RuleID, "finding[%d].rule_id", i)
		assert.Equal(t, want.Severity, got.Severity, "finding[%d].severity", i)
		// Issue #519: a DETECTION rule's alert title MUST be its one canonical DisplayName so the alert an operator triages names
		// the rule they can look up in the docs and exclusions. Asserted here for every fixture-replayed rule with no per-fixture
		// boilerplate.
		//
		// A projection is exempt: it renders a decision the agent already made, so its findings carry the matched app-control
		// rule's id and a title computed from the application, and there is no rule-level title for them to equal. Keyed off the
		// rule's STRUCTURAL classification, matching how registry_test.go states the same exemption, and deliberately not off
		// Finding.Source: the source is output under test, so a detection rule that stamped the app-control source would exempt
		// itself from the very guard this line is. TestAll_NonDetectionClassification pins which rules are projections, so the
		// exemption cannot be widened here either.
		//
		// (This previously held by accident: the rule was table-driven only, so replay never reached it. Issue #773 gave it a
		// fixture, which turned that accident into a failure.)
		if !isProjection {
			assert.Equal(t, rule.DisplayName(), got.Title,
				"finding[%d].title must equal the rule's canonical DisplayName (issue #519)", i)
		}
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

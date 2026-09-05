package bootstrap

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// stubCorpus serves a fixed document set as the stored corpus.
type stubCorpus struct{ docs []rulecontentapi.Document }

func (c stubCorpus) Documents(context.Context) ([]rulecontentapi.Document, error) { return c.docs, nil }
func (c stubCorpus) Version(context.Context) (int64, error)                       { return 1, nil }

// TestLoadCorpus_ReadsDocumentsOutsideTheImportedPrefix pins the stored-corpus root on the PRODUCTION load path, which review
// pointed out nothing did.
//
// The validator was tested directly and the existing startup tests only ever supply the embedded `imported/` corpus, so either
// production call could have reverted to catalog.CorpusRoot and every test would still have passed: validation would accept an
// authored rule that the runtime then silently never loads. That divergence is the single worst outcome this seam can produce,
// because the operator is told their rule was stored and nothing anywhere says it is not running.
//
// The assertion is presence rather than absence of an error, and that matters: loadCorpus falls back to the corpus embedded in the
// binary when nothing loads, so a wrong root returns a perfectly healthy rule set that simply lacks the authored rule.
func TestLoadCorpus_ReadsDocumentsOutsideTheImportedPrefix(t *testing.T) {
	t.Parallel()
	authored := ruleDoc("authored/operator_written_rule.yml", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"Operator Written Rule", simpleDetection)

	rules := loadCorpus(t.Context(), stubCorpus{docs: []rulecontentapi.Document{authored}},
		slog.New(slog.DiscardHandler))

	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID())
	}
	require.NotEmpty(t, ids)
	assert.Contains(t, ids, "operator_written_rule",
		"a document stored outside imported/ must reach the running rule set, not be silently skipped")
}

// TestLoadCorpus_StillReadsTheImportedPrefix keeps the change above from being a swap rather than a widening: content stored under
// the prefix the seed writes must keep loading exactly as before.
func TestLoadCorpus_StillReadsTheImportedPrefix(t *testing.T) {
	t.Parallel()
	vendored := ruleDoc("imported/process_creation/vendored_shaped_rule.yml", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"Vendored Shaped Rule", simpleDetection)

	rules := loadCorpus(t.Context(), stubCorpus{docs: []rulecontentapi.Document{vendored}},
		slog.New(slog.DiscardHandler))

	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID())
	}
	assert.Contains(t, ids, "vendored_shaped_rule")
}

// TestReload_ReadsDocumentsOutsideTheImportedPrefix is the same property on the RELOAD path, which the boot-path test above does
// not reach.
//
// The two call sites share one constant today, so a single edit moves both, but they are separate calls and mutation showed the
// reload one alone is otherwise unpinned: reverting it while leaving the boot path intact passed every test in this package. A
// deployment in that state would load an authored rule at startup and quietly drop it at the next publish, which is worse than
// never loading it at all, because it works until it does not.
func TestReload_ReadsDocumentsOutsideTheImportedPrefix(t *testing.T) {
	t.Parallel()
	authored := ruleDoc("authored/reloaded_operator_rule.yml", "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"Reloaded Operator Rule", simpleDetection)

	r, _ := testRules(t, fakeCorpus{docs: []rulecontentapi.Document{authored}, version: 7})

	n, err := r.Reload(t.Context())
	require.NoError(t, err)
	require.Positive(t, n)

	ids := make([]string, 0, n)
	for _, rule := range r.svc.ActiveRules() {
		ids = append(ids, rule.ID())
	}
	assert.Contains(t, ids, "reloaded_operator_rule",
		"a published document outside imported/ must reach the rule set, not be dropped at the next reload")
}

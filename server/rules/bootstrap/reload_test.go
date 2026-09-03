package bootstrap

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	"github.com/fleetdm/edr/server/rules/api"
	"github.com/fleetdm/edr/server/rules/internal/catalog"
	"github.com/fleetdm/edr/server/rules/internal/detectionconfig"
	"github.com/fleetdm/edr/server/rules/internal/service"
	"github.com/fleetdm/edr/server/testdb"
)

// stubRule is a minimal api.Rule for the fan-out tests, which care only about a rule's id and the exclusion match types it
// declares. Nothing here is evaluated.
type stubRule struct {
	id    string
	match []api.ExclusionMatchType
}

func (r stubRule) ID() string                                             { return r.id }
func (r stubRule) DisplayName() string                                    { return r.id }
func (r stubRule) Techniques() []string                                   { return nil }
func (r stubRule) Doc() api.Documentation                                 { return api.Documentation{Title: r.id} }
func (r stubRule) Platforms() []api.Platform                              { return []api.Platform{api.PlatformDarwin} }
func (r stubRule) SupportedExclusionMatchTypes() []api.ExclusionMatchType { return r.match }
func (r stubRule) Evaluate(context.Context, []api.Event, api.GraphReader) ([]api.Finding, error) {
	return nil, nil
}

// testRules builds a Rules with only the collaborators the reload path touches.
//
// The database is real because detectionconfig requires one to construct, following the convention its own tests use, but nothing
// here reads or writes it: every assertion below resolves in memory, and the exclusion checks reject before any statement runs.
func testRules(t *testing.T, corpus rulecontentapi.Corpus) (*Rules, *capturingHandler) {
	t.Helper()
	var logged capturingHandler
	logger := slog.New(&logged)
	cfg := detectionconfig.NewService(detectionconfig.NewStore(testdb.Open(t)), nil, nil, logger)
	return &Rules{
		svc:                service.New(nil, cfg, logger),
		detectionConfigSvc: cfg,
		corpus:             corpus,
		logger:             logger,
	}, &logged
}

// spec:rule-content/a-running-server-picks-up-changed-content/content-published-elsewhere-is-picked-up-without-a-restart
//
// TestReload_InstallsStoredContentAndStampsItsVersion is the happy path: the stored corpus becomes the rule set in force, stamped
// with the version it was built from so a later poll can tell whether it is still current.
func TestReload_InstallsStoredContentAndStampsItsVersion(t *testing.T) {
	t.Parallel()

	r, logged := testRules(t, fakeCorpus{docs: embeddedCorpus(t), version: 42})

	n, err := r.Reload(t.Context())
	require.NoError(t, err)

	assert.Positive(t, n, "the vendored corpus loads rules, so a zero here means nothing was installed")
	assert.Len(t, r.svc.ActiveRules(), n, "and the reported count is the set actually in force")
	assert.Equal(t, int64(42), r.svc.ActiveVersion(), "stamped with the version read from the store, not a guess")
	assert.False(t, logged.warned, "a successful reload is not a fallback and must not read as one")
}

// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/a-store-that-cannot-be-read-keeps-the-set-in-force
//
// TestReload_KeepsTheSetInForceWhenTheStoreCannotBeRead covers the only failures that keep history.
//
// A read that fails leaves the stored state UNKNOWN, so the set already in force is the best available answer and the next tick
// retries. The version is deliberately not advanced, so the poll still sees a difference and tries again.
func TestReload_KeepsTheSetInForceWhenTheStoreCannotBeRead(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		corpus rulecontentapi.Corpus
	}{
		{name: "the version counter is unreadable", corpus: fakeCorpus{versionErr: errors.New("dial tcp: connection refused")}},
		{name: "the documents are unreadable", corpus: fakeCorpus{version: 9, err: errors.New("dial tcp: connection refused")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, _ := testRules(t, tc.corpus)
			r.installRuleSet([]api.Rule{stubRule{id: "already-running"}}, 3)

			_, err := r.Reload(t.Context())
			require.Error(t, err, "the caller has to be told, or the refresh loop cannot report it")

			require.Len(t, r.svc.ActiveRules(), 1, "the set already in force must survive a store that cannot be read")
			assert.Equal(t, "already-running", r.svc.ActiveRules()[0].ID())
			assert.Equal(t, int64(3), r.svc.ActiveVersion(),
				"and its version, so the next poll still sees a difference and retries")
		})
	}
}

// spec:rule-content/an-unavailable-or-unusable-store-leaves-detections-running/unusable-stored-content-converges-on-the-build-s-corpus
//
// TestReload_ConvergesOnTheBuildsCorpusWhenContentIsUnusable is the anti-divergence property, and it replaced the behaviour I
// shipped first.
//
// Keeping the set already in force for these cases seemed obviously right and cannot work. All three are DETERMINATE: the store
// was read, and what it holds yields no runnable rules. Keeping the running set makes the rule set a function of a replica's
// history rather than of stored content, so a replica that restarts against the same store lands somewhere else, and because
// neither records the version nothing ever reconciles them. One bad publish would split the fleet permanently.
//
// So each of these installs the corpus built into the binary and RECORDS the version, which is what a replica starting from
// scratch does with the same store. The recorded version is the assertion that matters: without it the poll re-reads forever and
// the divergence is merely slower.
func TestReload_ConvergesOnTheBuildsCorpusWhenContentIsUnusable(t *testing.T) {
	t.Parallel()

	fromBuild := len(catalog.NewWithCorpus(nil, catalog.MustLoadImported()))
	require.Greater(t, fromBuild, 10, "the build's corpus must be substantial, or these assertions say little")

	cases := []struct {
		name   string
		corpus rulecontentapi.Corpus
	}{
		{
			name:   "the corpus was emptied",
			corpus: fakeCorpus{version: 9, docs: nil},
		},
		{
			name: "the content does not parse",
			corpus: fakeCorpus{version: 9, docs: []rulecontentapi.Document{
				{Path: "imported/broken.yml", Content: []byte("{{ not sigma")},
			}},
		},
		{
			// The loader refuses a rule it cannot run individually and reports that as success with nothing loaded, NOT as an
			// error, so this arrives on the happy path. A file_event rule is the real refusal this sensor produces, since it reads
			// telemetry the agent does not collect.
			name: "every document is refused individually",
			corpus: fakeCorpus{version: 9, docs: []rulecontentapi.Document{{
				Path:    "imported/file_event/file_event_macos_emond_launch_daemon.yml",
				Content: mustReadEmbedded(t, "imported/file_event/file_event_macos_emond_launch_daemon.yml"),
			}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, logged := testRules(t, tc.corpus)
			r.installRuleSet([]api.Rule{stubRule{id: "already-running"}}, 3)

			_, err := r.Reload(t.Context())
			require.NoError(t, err, "a determinate state is not a failure to report; it is a state to converge on")

			assert.Len(t, r.svc.ActiveRules(), fromBuild,
				"every replica reading this store must reach the same set, which is the one built into the binary")
			assert.Equal(t, int64(9), r.svc.ActiveVersion(),
				"and the version must be RECORDED, or the poll re-reads forever and replicas never agree they are done")
			assert.True(t, logged.warned, "silently replacing an operator's content with the build's is not acceptable")
		})
	}
}

// spec:rule-content/a-running-server-picks-up-changed-content/the-version-is-read-before-the-content
//
// TestReload_ReadsTheVersionBeforeTheDocuments pins an ordering that looks arbitrary and is not.
//
// The two reads cannot be atomic across this interface, so a publish landing between them produces a mismatched pair either way.
// Reading the version FIRST pairs newer documents with an older version, so the next poll still sees a difference and converges.
// The reverse pairs older documents with the newer version, which matches on the next poll and leaves stale content in force with
// nothing to correct it. Reversing the two statements is a silent, permanent staleness bug, so the order is asserted directly.
func TestReload_ReadsTheVersionBeforeTheDocuments(t *testing.T) {
	t.Parallel()

	var calls []string
	r, _ := testRules(t, fakeCorpus{docs: embeddedCorpus(t), version: 1, calls: &calls})

	_, err := r.Reload(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"version", "documents"}, calls,
		"version first: the reverse order can pin stale content under a version that says it is current")
}

// spec:rule-content/a-running-server-picks-up-changed-content/the-rule-set-in-force-is-replaced-wholesale
//
// TestInstallRuleSet_BringsTheExclusionSupportMapAlong covers the second of the three consumers, and the one with no symptom of
// its own: the map the create-exclusion API validates against is built from the rule set, so a reload that updated only the
// service would leave it answering for the previous set.
//
// Both directions are asserted through the two DIFFERENT rejections, which is what distinguishes presence from absence: a rule
// missing from the map is "not a registered rule", while a rule present but declaring no match types is "does not accept
// exclusions". A stale map would call the newly added rule unregistered.
func TestInstallRuleSet_BringsTheExclusionSupportMapAlong(t *testing.T) {
	t.Parallel()

	r, _ := testRules(t, nil)
	create := func(ruleID string) error {
		_, err := r.detectionConfigSvc.CreateExclusion(t.Context(), nil, "",
			detectionconfig.CreateExclusionInput{RuleID: ruleID, MatchType: api.ExclusionMatchPathGlob, Value: "/tmp/*"})
		return err
	}

	r.installRuleSet([]api.Rule{stubRule{id: "before", match: []api.ExclusionMatchType{api.ExclusionMatchPathGlob}}}, 1)
	require.ErrorContains(t, create("after"), "does not name a registered rule",
		"a rule that is not in the set yet must be rejected, or the assertion below proves nothing")

	r.installRuleSet([]api.Rule{stubRule{id: "after"}}, 2)

	require.ErrorContains(t, create("before"), "does not name a registered rule",
		"the rule the reload removed must be gone from the map")
	require.ErrorContains(t, create("after"), "does not accept exclusions",
		"and the rule it added must be IN the map: a stale map would call this one unregistered")
}

// spec:rule-content/a-running-server-picks-up-changed-content/the-rule-set-in-force-is-replaced-wholesale
//
// TestInstallRuleSet_NotifiesTheObserver covers the third consumer. The detection engine compiles its own dispatch indices from
// the rule set and rebuilds them only when told, so without this notification a published rule is listed by the API and never
// evaluated, which is the failure mode with the least visible symptom of the three.
func TestInstallRuleSet_NotifiesTheObserver(t *testing.T) {
	t.Parallel()

	r, _ := testRules(t, fakeCorpus{docs: embeddedCorpus(t), version: 5})
	var notified atomic.Int64
	r.SetRuleSetObserver(func() { notified.Add(1) })

	_, err := r.Reload(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int64(1), notified.Load(), "a successful install must tell the engine to rebuild")

	r.corpus = fakeCorpus{versionErr: errors.New("dial tcp: connection refused")}
	_, err = r.Reload(t.Context())
	require.Error(t, err)
	assert.Equal(t, int64(1), notified.Load(),
		"and a failed reload must not, since nothing changed and a rebuild would only cost work")
}

// spec:rule-content/a-running-server-picks-up-changed-content/an-unchanged-version-does-not-re-read-the-content
// spec:rule-content/a-running-server-picks-up-changed-content/a-replica-adopts-stored-content-on-its-first-poll
//
// TestCorpusRefreshTick_ReloadsOnlyWhenTheVersionChanged is what makes the poll affordable. Without the gate every tick would
// read, parse and compile the whole corpus on every replica forever; with it, a steady state is one indexed single-row read per
// interval. The gate is asserted by call count rather than by timing, so it cannot pass by being slow.
func TestCorpusRefreshTick_ReloadsOnlyWhenTheVersionChanged(t *testing.T) {
	t.Parallel()

	var calls []string
	r, _ := testRules(t, fakeCorpus{docs: embeddedCorpus(t), version: 7, calls: &calls})

	require.False(t, r.corpusRefreshTick(t.Context()), "a version that differs from the loaded one reloads")
	require.Equal(t, int64(7), r.svc.ActiveVersion())
	loaded := len(r.svc.ActiveRules())

	calls = nil
	require.False(t, r.corpusRefreshTick(t.Context()), "and a version that matches does not")

	assert.Equal(t, []string{"version"}, calls, "the content must not be re-read when the version has not moved")
	assert.Len(t, r.svc.ActiveRules(), loaded)
}

// TestCorpusRefreshLoop_StopsWithoutWorkToDo covers the two ways the loop ends: a deployment with no stored content has nothing to
// poll and must not spin, and a cancelled context stops it without logging, because shutdown racing a poll is expected.
func TestCorpusRefreshLoop_StopsWithoutWorkToDo(t *testing.T) {
	t.Parallel()

	t.Run("no store configured", func(t *testing.T) {
		t.Parallel()
		r, _ := testRules(t, nil)
		done := make(chan struct{})
		go func() { defer close(done); r.CorpusRefreshLoop(t.Context(), time.Millisecond) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("the loop must return immediately when there is no stored content to poll")
		}
	})

	t.Run("context cancelled mid-poll", func(t *testing.T) {
		t.Parallel()
		r, logged := testRules(t, fakeCorpus{versionErr: errors.New("dial tcp: connection refused")})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		assert.True(t, r.corpusRefreshTick(ctx), "a cancelled context stops the loop")
		assert.False(t, logged.warned, "and does so silently, because shutdown racing a poll is not a fault")
	})
}

// TestInstallRuleSet_IsSafeUnderConcurrentReads is the -race half of the fan-out.
//
// Reloading used to be impossible, so every consumer of the rule set was written on the assumption that it is filled once during
// wiring and read-only thereafter, and the exclusion-support map said so in a comment. Making content reloadable turns that
// assumption false: the map is now rewritten on a background loop while request handlers are reading it. Reinstating a plain map
// field there reports a data race here.
func TestInstallRuleSet_IsSafeUnderConcurrentReads(t *testing.T) {
	t.Parallel()

	r, _ := testRules(t, nil)
	sets := [][]api.Rule{
		{stubRule{id: "generation-a", match: []api.ExclusionMatchType{api.ExclusionMatchPathGlob}}},
		{stubRule{id: "generation-b"}},
	}
	r.installRuleSet(sets[0], 1)

	const rounds = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range rounds {
			r.installRuleSet(sets[i%len(sets)], int64(i))
		}
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			// The error is not the point: whichever generation is in force, this reads the map the installer is replacing.
			_, _ = r.detectionConfigSvc.CreateExclusion(t.Context(), nil, "",
				detectionconfig.CreateExclusionInput{RuleID: "generation-a", MatchType: api.ExclusionMatchPathGlob, Value: "/tmp/*"})
			_ = r.svc.ActiveRules()
			_ = r.svc.List()
		}
	}()
	wg.Wait()

	assert.Len(t, r.svc.ActiveRules(), 1, "and the set in force after the churn is one whole generation, not a mixture")
}

// mustReadEmbedded reads one document out of the corpus built into this binary, so a fixture is real content the loader treats the
// way it treats production content rather than a string that merely resembles a rule.
func mustReadEmbedded(t *testing.T, docPath string) []byte {
	t.Helper()
	body, err := fs.ReadFile(EmbeddedCorpusFS(), docPath)
	require.NoErrorf(t, err, "the embedded corpus must still hold %s", docPath)
	return body
}

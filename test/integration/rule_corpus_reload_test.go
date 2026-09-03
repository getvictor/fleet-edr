//go:build integration

package integration

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	detectionbootstrap "github.com/fleetdm/edr/server/detection/bootstrap"
	detectiontestkit "github.com/fleetdm/edr/server/detection/testkit"
	identitytestkit "github.com/fleetdm/edr/server/identity/testkit"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
	visibilitybootstrap "github.com/fleetdm/edr/server/visibility/bootstrap"
)

// spec:rule-content/a-running-server-picks-up-changed-content/content-published-elsewhere-is-picked-up-without-a-restart
//
// TestRuleCorpusReload_TwoReplicasConverge is the multi-replica claim, tested the only way it can be: two independently
// constructed rules contexts sharing one database, one of them publishing.
//
// The compiled rule set is a per-replica cache (ADR-0010), so a publish is invisible to a peer until that peer re-reads. Both
// halves matter and both are asserted. A replica that never converged would keep detecting on withdrawn content indefinitely; a
// rule set that were somehow shared would make the version counter and the refresh loop pointless machinery.
func TestRuleCorpusReload_TwoReplicasConverge(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	logger := slog.New(slog.DiscardHandler)

	ruleContentCtx, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)

	// Publisher and subscriber: separate contexts over one store, which is what two replicas are.
	newReplica := func() *rulesbootstrap.Rules {
		r, newErr := rulesbootstrap.New(ctx, rulesbootstrap.Deps{
			DB: db, Logger: logger, AuthZ: identitytestkit.AllowAllAuthZ{},
			Corpus: ruleContentCtx.Corpus(),
		})
		require.NoError(t, newErr)
		return r
	}

	seeded, err := ruleContentCtx.SeedFrom(ctx, rulesbootstrap.EmbeddedCorpusFS(),
		rulesbootstrap.EmbeddedCorpusRoot, rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err)
	require.True(t, seeded, "the fixture database starts empty, so this is the write that fills it")

	publisher, subscriber := newReplica(), newReplica()
	fromCorpus := corpusRuleIDs(t)
	full := len(filterCorpusIDs(fromCorpus, publisher.ContentService().ActiveRules()))
	require.Greater(t, full, 10, "the seeded corpus is substantial, which is what makes the contrast below meaningful")

	// The subscriber's engine-side consumer, so the test proves the notification a real deployment depends on and not just the
	// service's own swap.
	var notified atomic.Int64
	subscriber.SetRuleSetObserver(func() { notified.Add(1) })

	// Publish a corpus of one document, the way an operator replacing a rule pack would.
	published, err := ruleContentCtx.Replace(ctx, oneStoredDocument(t))
	require.NoError(t, err)
	require.Positive(t, published, "a replacement bumps the version, which is what a peer polls")

	// The subscriber has not re-read yet, so it must still be running what it loaded. This is the per-replica half: if this
	// assertion fails, the two contexts are sharing a rule set and the refresh machinery below proves nothing.
	require.Len(t, filterCorpusIDs(fromCorpus, subscriber.ContentService().ActiveRules()), full,
		"a publish on another replica must not reach into this one's compiled set")

	go subscriber.CorpusRefreshLoop(ctx, 10*time.Millisecond)

	// Converged on the EXACT published rule, not merely on a smaller set. A reload that produced nothing would also be smaller,
	// and that is what an unrunnable document yields, so a count comparison could not tell the two apart.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{storedRuleID}, filterCorpusIDs(fromCorpus, subscriber.ContentService().ActiveRules()))
	}, 10*time.Second, 20*time.Millisecond, "the subscriber must converge on the published corpus without a restart")

	assert.Positive(t, notified.Load(), "and must tell its engine to rebuild, or the API lists rules that never run")
	assert.Len(t, filterCorpusIDs(fromCorpus, publisher.ContentService().ActiveRules()), full,
		"the publisher's own set is untouched until its own loop runs, which is the same per-replica property")

	// A SECOND publish, which is the one that actually exercises the version gate. The first reload happens no matter what the
	// counter says, because a freshly built replica stamps its set as not-from-storage, so a replacement that failed to bump the
	// version would still be picked up once and look correct. Only a subsequent publish can tell the two apart.
	republished, err := ruleContentCtx.Replace(ctx, []rulecontentapi.Document{
		{Path: secondStoredRuleDoc, Content: mustReadVendored(t, secondStoredRuleDoc)},
	})
	require.NoError(t, err)
	require.Greater(t, republished, published, "each replacement must advance the counter, or a peer cannot tell content changed")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []string{secondStoredRuleID}, filterCorpusIDs(fromCorpus, subscriber.ContentService().ActiveRules()))
	}, 10*time.Second, 20*time.Millisecond, "and the replica keeps converging on later publishes, not just the first")
}

// The document a second publish installs, so the test can prove the version gate across successive publishes rather than only on
// a replica's first load. A different rule from storedRuleDoc, and in the same accepted category.
const (
	secondStoredRuleDoc = "imported/process_creation/proc_creation_macos_base64_decode.yml"
	secondStoredRuleID  = "proc_creation_macos_base64_decode"
)

// oneStoredDocument returns a single real document from the corpus embedded in this build, as storage-shaped content.
//
// Real content, and named rather than picked by a walk: the vendored tree's first two documents are rules this sensor refuses, so
// taking whichever sorts first yields an empty rule set that is indistinguishable from a corpus that never loaded. That mistake
// made the first version of the sibling test vacuous.
func oneStoredDocument(t *testing.T) []rulecontentapi.Document {
	t.Helper()
	return []rulecontentapi.Document{{Path: storedRuleDoc, Content: mustReadVendored(t, storedRuleDoc)}}
}

// countingProvider hands the engine the same rule set the rules context holds, and records the size of what it handed over.
type countingProvider struct {
	inner     interface{ ActiveRules() []rulesapi.Rule }
	delivered *atomic.Int64
}

func (c countingProvider) ActiveRules() []rulesapi.Rule {
	rules := c.inner.ActiveRules()
	c.delivered.Store(int64(len(rules)))
	return rules
}

// spec:rule-content/a-running-server-picks-up-changed-content/the-rule-set-in-force-is-replaced-wholesale
//
// TestRuleCorpusReload_ThePublishReachesTheDetectionEngine closes a gap review found: every other test here installs a counter as
// the observer, so nothing checked that a publish actually reaches the thing that evaluates rules. The engine compiles its own
// dispatch indices and rebuilds them only when told, so a miswired observer leaves the API listing a rule the engine never runs,
// which is the failure with the least visible symptom in this change.
//
// What this pins is the cross-context contract: a publish causes detection's LoadActive to be invoked, with the post-publish rule
// set. What it does not pin is cmd/main's own closure, which nothing short of running main can; the integration stack now carries
// the same wiring so the two cannot drift silently.
func TestRuleCorpusReload_ThePublishReachesTheDetectionEngine(t *testing.T) {
	t.Parallel()
	db := full.Open(t)
	ctx := t.Context()
	logger := slog.New(slog.DiscardHandler)

	ruleContentCtx, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)
	seeded, err := ruleContentCtx.SeedFrom(ctx, rulesbootstrap.EmbeddedCorpusFS(),
		rulesbootstrap.EmbeddedCorpusRoot, rulesbootstrap.EmbeddedCorpusIncludes)
	require.NoError(t, err)
	require.True(t, seeded)

	rulesCtx, err := rulesbootstrap.New(ctx, rulesbootstrap.Deps{
		DB: db, Logger: logger, AuthZ: identitytestkit.AllowAllAuthZ{},
		Corpus: ruleContentCtx.Corpus(),
	})
	require.NoError(t, err)

	// Detection needs a real event log to construct. Nothing here feeds it events: the assertion is about what the engine is
	// HANDED on a publish, not about what it does with a batch afterwards.
	visibilityCtx, err := visibilitybootstrap.New(visibilitybootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)
	detectionCtx, err := detectionbootstrap.New(detectionbootstrap.Deps{
		DB:           db,
		Logger:       logger,
		Mode:         detectionbootstrap.ModeFull,
		AuthZ:        identitytestkit.AllowAllAuthZ{},
		EventLog:     visibilityCtx.EventLog(),
		EventArchive: detectiontestkit.NewMemArchive(),
	})
	require.NoError(t, err)

	// Wired the way cmd/main wires it, with a counter in the middle recording what the engine was actually handed.
	var delivered atomic.Int64
	rulesCtx.SetRuleSetObserver(func() {
		detectionCtx.LoadActive(countingProvider{inner: rulesCtx.ContentService(), delivered: &delivered})
	})

	fromCorpus := corpusRuleIDs(t)
	full := len(filterCorpusIDs(fromCorpus, rulesCtx.ContentService().ActiveRules()))
	require.Greater(t, full, 10)
	require.Zero(t, delivered.Load(), "nothing has been published yet, so the engine has not been told anything")

	_, err = ruleContentCtx.Replace(ctx, oneStoredDocument(t))
	require.NoError(t, err)

	go rulesCtx.CorpusRefreshLoop(ctx, 10*time.Millisecond)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Positive(c, delivered.Load(), "the engine must be handed a rule set after a publish")
		assert.Equal(c, int64(len(rulesCtx.ContentService().ActiveRules())), delivered.Load(),
			"and it must be the set in force after the publish, not the one from before")
	}, 10*time.Second, 20*time.Millisecond)

	assert.Less(t, delivered.Load(), int64(full),
		"the published corpus is smaller than the seeded one, so a delivery of the old size means the engine kept the old set")
}

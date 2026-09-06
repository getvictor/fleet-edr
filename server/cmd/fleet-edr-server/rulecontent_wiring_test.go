//go:build integration

package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
	rulecontentbootstrap "github.com/fleetdm/edr/server/rulecontent/bootstrap"
	"github.com/fleetdm/edr/server/testdb/full"
)

// TestOpenRuleContent_InstallsThisBuildsPack pins the startup WIRING rather than the upgrade itself, which is tested where it
// lives. Review of the previous change in this area found exactly this shape of seam unguarded: the call was covered by nothing,
// so deleting it left every test green while the product silently stopped doing the thing the change existed to do.
//
// The fixture is what makes it able to fail. The corpus is pre-loaded with a pack that is NOT this build's, so the seed declines
// (it acts only on an empty corpus) and only the upgrade can reconcile it. Starting from an empty database instead would install
// this build's pack through the seed, and the assertion would hold whether or not the upgrade were wired at all.
func TestOpenRuleContent_InstallsThisBuildsPack(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := full.Open(t)
	logger := slog.New(slog.DiscardHandler)

	rc, err := rulecontentbootstrap.New(rulecontentbootstrap.Deps{DB: db, Logger: logger})
	require.NoError(t, err)

	// A deployment already carrying some older generation of shipped content.
	_, err = rc.Replace(ctx, []rulecontentapi.Document{{
		Path:    "imported/stale.yml",
		Content: []byte("a pack this build does not ship"),
		Source:  rulecontentapi.SourceVendored,
	}})
	require.NoError(t, err)

	// The startup path under test.
	opened, err := openRuleContent(ctx, logger, db)
	require.NoError(t, err)

	docs, err := opened.Corpus().Documents(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, docs)

	paths := make(map[string]struct{}, len(docs))
	for _, d := range docs {
		paths[d.Path] = struct{}{}
	}
	assert.NotContains(t, paths, "imported/stale.yml",
		"startup must install this build's pack over the stored one, or a deployment runs its first generation of rules forever")
	assert.Greater(t, len(docs), 1,
		"this build ships a corpus, so the stored pack must have been replaced by more than the one stale document")
}

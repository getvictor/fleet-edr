//go:build integration

package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/rulecontent/api"
)

// entry is the opaque payload a caller commits with its change. The bytes are the rules context's business; what matters here is
// that they arrive intact and that they arrive with the change.
func entry(payload string) api.AuditOutboxEntry {
	return api.AuditOutboxEntry{Kind: "test.audit.v1", Payload: []byte(payload)}
}

// spec:rule-content/every-authoring-change-is-attributable/the-audit-entry-commits-with-the-change
//
// TestAuditOutbox_CommitsWithTheChange is the guarantee issue #886 asks for: the audit entry and the content change are one
// transaction, so a reader can never find one without the other.
//
// The old ordering wrote the audit row after the content transaction committed and logged a failure rather than returning it,
// which left a window in which a fleet's detections had changed durably and nothing named who did it or why.
func TestAuditOutbox_CommitsWithTheChange(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)

	_, err = s.PutDocument(ctx, api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version,
		entry(`{"action":"put"}`))
	require.NoError(t, err)

	pending, err := s.PendingAuditEntries(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1, "the change committed, so its audit entry must have committed with it")
	assert.Equal(t, "test.audit.v1", pending[0].Kind)
	assert.JSONEq(t, `{"action":"put"}`, string(pending[0].Payload), "the payload is stored verbatim")
}

// spec:rule-content/every-authoring-change-is-attributable/a-refused-change-leaves-no-audit-entry
//
// TestAuditOutbox_ARefusedChangeLeavesNoEntry is the other half, and the half that makes the first one mean something: an entry
// that outlived a change which did not happen would be a trail claiming something false, which is worse than a gap.
func TestAuditOutbox_ARefusedChangeLeavesNoEntry(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)

	// A stale expected version, which is how the store refuses a change validated against a corpus that has since moved.
	_, err = s.PutDocument(ctx, api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version-1,
		entry(`{"action":"put"}`))
	require.ErrorIs(t, err, api.ErrCorpusChanged)

	pending, err := s.PendingAuditEntries(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pending, "the change was refused, so nothing may claim it happened")

	docs, err := s.Documents(ctx)
	require.NoError(t, err)
	assert.Len(t, docs, 1, "and the corpus is untouched")
}

// TestAuditOutbox_DeleteAndRollbackCommitTheirEntriesToo covers the other two mutating paths. The rollback is the one review
// objected to losing an audit row for, because it replaces every shipped rule at once.
func TestAuditOutbox_DeleteAndRollbackCommitTheirEntriesToo(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)
	version, err = s.PutDocument(ctx, api.Document{Path: "authored/mine.yml", Content: []byte("mine")}, version,
		api.AuditOutboxEntry{})
	require.NoError(t, err)

	_, err = s.DeleteDocument(ctx, "authored/mine.yml", version, entry(`{"action":"delete"}`))
	require.NoError(t, err)

	// A pack to roll back to, so the rollback has something to restore.
	_, err = s.UpgradeVendoredTo(ctx, []api.Document{shippedDoc("imported/b.yml", "b")}, stemIdentity)
	require.NoError(t, err)
	_, err = s.RollbackPack(ctx, stemIdentity, func(api.PackRollback) (api.AuditOutboxEntry, error) {
		return entry(`{"action":"rollback"}`), nil
	})
	require.NoError(t, err)

	pending, err := s.PendingAuditEntries(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2, "the delete and the rollback each committed an entry")
	// Oldest first, so the audit rows land in the order the changes did.
	assert.JSONEq(t, `{"action":"delete"}`, string(pending[0].Payload))
	assert.JSONEq(t, `{"action":"rollback"}`, string(pending[1].Payload))
}

// TestAuditOutbox_DeliveredEntriesAreRemoved pins that deleting is what marks delivery, and that it is scoped to what was
// delivered rather than clearing the table.
func TestAuditOutbox_DeliveredEntriesAreRemoved(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()

	version, err := s.Replace(ctx, []api.Document{shippedDoc("imported/a.yml", "a")})
	require.NoError(t, err)
	version, err = s.PutDocument(ctx, api.Document{Path: "authored/one.yml", Content: []byte("1")}, version, entry(`{"n":1}`))
	require.NoError(t, err)
	_, err = s.PutDocument(ctx, api.Document{Path: "authored/two.yml", Content: []byte("2")}, version, entry(`{"n":2}`))
	require.NoError(t, err)

	pending, err := s.PendingAuditEntries(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)

	require.NoError(t, s.DeleteAuditEntries(ctx, []int64{pending[0].ID}))

	left, err := s.PendingAuditEntries(ctx, 10)
	require.NoError(t, err)
	require.Len(t, left, 1, "only the delivered entry is removed")
	assert.JSONEq(t, `{"n":2}`, string(left[0].Payload), "and the undelivered one is still there to retry")
}

package ruleauthoring

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// fakePacks is a pack lifecycle whose answers the tests choose.
type fakePacks struct {
	status    rulecontentapi.PackStatus
	statusErr error
	rolled    rulecontentapi.PackRollback
	rollErr   error
	rollbacks int
}

func (f *fakePacks) Status(context.Context) (rulecontentapi.PackStatus, error) {
	return f.status, f.statusErr
}

func (f *fakePacks) Rollback(context.Context) (rulecontentapi.PackRollback, error) {
	f.rollbacks++
	return f.rolled, f.rollErr
}

func newPackService(t *testing.T, packs *fakePacks, audit *recordingAudit) *PackService {
	t.Helper()
	s, err := NewPackService(packs, audit, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return s
}

// TestNewPackService_RequiresItsCollaborators keeps a half-built service from existing. The recorder is required for the reason
// the lifecycle is: a rollback that replaced every shipped rule without leaving an audit row is the change here least acceptable
// to lose, so a deployment that wired it wrong should fail to start rather than discover it later.
func TestNewPackService_RequiresItsCollaborators(t *testing.T) {
	t.Parallel()
	_, noPacks := NewPackService(nil, &recordingAudit{}, nil)
	require.Error(t, noPacks)
	_, noAudit := NewPackService(&fakePacks{}, nil, nil)
	require.Error(t, noAudit)
	svc, ok := NewPackService(&fakePacks{}, &recordingAudit{}, nil)
	require.NoError(t, ok, "a nil logger is filled in rather than refused")
	require.NotNil(t, svc)
}

// TestPackService_StatusPassesThrough states the asymmetry deliberately: reading changes nothing, so it needs no reason and
// records nothing. A reason is required exactly where something is being changed.
func TestPackService_StatusPassesThrough(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	packs := &fakePacks{status: rulecontentapi.PackStatus{Installed: "a", Available: "b", Added: []string{"x"}}}
	svc := newPackService(t, packs, audit)

	got, err := svc.Status(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "a", got.Installed)
	assert.Equal(t, []string{"x"}, got.Added)
	assert.Empty(t, audit.events, "reading changes nothing, so it records nothing")
}

// TestPackService_StatusSurfacesAFailure keeps a broken read from looking like a current deployment, which is the answer an
// operator would act on by doing nothing.
func TestPackService_StatusSurfacesAFailure(t *testing.T) {
	t.Parallel()
	want := errors.New("corpus unreadable")
	svc := newPackService(t, &fakePacks{statusErr: want}, &recordingAudit{})

	_, err := svc.Status(t.Context())
	require.ErrorIs(t, err, want)
}

// TestPackService_RollbackRequiresAReason checks the reason BEFORE the lifecycle is touched. Checking afterwards would leave a
// rollback performed and then reported as a bad request, which is the worst of both.
func TestPackService_RollbackRequiresAReason(t *testing.T) {
	t.Parallel()
	packs := &fakePacks{}
	audit := &recordingAudit{}
	svc := newPackService(t, packs, audit)

	for _, reason := range []string{"", "   ", "\t\n"} {
		_, err := svc.Rollback(t.Context(), testActor(), reason)
		require.ErrorIs(t, err, ErrReasonRequired, "reason %q", reason)
	}
	assert.Zero(t, packs.rollbacks, "the reason is checked before anything is rolled back")
	assert.Empty(t, audit.events, "nothing happened, so nothing is recorded")
}

// TestPackService_RollbackRecordsWhoAndWhy is the claim the audit trail rests on, and it checks the payload rather than the row's
// existence: an entry saying only that a rollback happened would be the least useful of the set, given the change replaces every
// shipped detection at once.
func TestPackService_RollbackRecordsWhoAndWhy(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	packs := &fakePacks{rolled: rulecontentapi.PackRollback{
		Restored: "restored-digest", Version: 12, Withheld: []string{"imported/mine.yml"},
	}}
	svc := newPackService(t, packs, audit)

	rolled, err := svc.Rollback(t.Context(), testActor(), "rule X fires on everything")
	require.NoError(t, err)
	assert.Equal(t, "restored-digest", rolled.Restored)

	require.Len(t, audit.events, 1)
	e := audit.events[0]
	assert.Equal(t, identityapi.AuditRuleContentPackRollback, e.Action,
		"its own action, because calling this a document change would understate replacing every shipped rule")
	assert.Equal(t, "rule_content_pack", e.TargetType)
	assert.Equal(t, "restored-digest", e.TargetID)
	assert.Equal(t, "rule X fires on everything", e.Payload["reason"])
	assert.Equal(t, int64(12), e.Payload["corpus_version"])
	assert.Equal(t, []string{"imported/mine.yml"}, e.Payload["withheld"],
		"the deployment is deliberately not running a shipped rule, and a later reviewer needs that visible")
}

// TestPackService_RollbackOmitsWithheldWhenThereIsNone keeps the payload honest: an empty list would read as a decision that was
// made, when nothing was withheld at all.
func TestPackService_RollbackOmitsWithheldWhenThereIsNone(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	svc := newPackService(t, &fakePacks{rolled: rulecontentapi.PackRollback{Restored: "d", Version: 3}}, audit)

	_, err := svc.Rollback(t.Context(), testActor(), "reverting the noisy pack")
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	assert.NotContains(t, audit.events[0].Payload, "withheld")
}

// TestPackService_RefusedRollbackIsNotRecorded pins that a failure leaves no row. The corpus is exactly as it was, so an audit
// entry would describe a change that did not happen.
func TestPackService_RefusedRollbackIsNotRecorded(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	svc := newPackService(t, &fakePacks{rollErr: rulecontentapi.ErrNoPreviousPack}, audit)

	_, err := svc.Rollback(t.Context(), testActor(), "trying it")
	require.ErrorIs(t, err, rulecontentapi.ErrNoPreviousPack)
	assert.Empty(t, audit.events)
}

// TestPackService_RollbackSucceedsEvenIfItsAuditRowFails states which way this fails. The rollback is already committed by the
// time the row is written, so reporting failure would tell an operator their content is unchanged when it is not. The loss is
// logged instead.
func TestPackService_RollbackSucceedsEvenIfItsAuditRowFails(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{err: errors.New("audit store down")}
	svc := newPackService(t, &fakePacks{rolled: rulecontentapi.PackRollback{Restored: "d", Version: 4}}, audit)

	rolled, err := svc.Rollback(t.Context(), testActor(), "the pack broke detection")
	require.NoError(t, err, "the content is already rolled back, so reporting failure would misstate the outcome")
	assert.Equal(t, "d", rolled.Restored)
}

// TestPackService_RollbackWithoutAnActorStillRecords covers the shape a non-interactive caller presents. The row is worth writing
// without a principal: it still says what happened and why.
func TestPackService_RollbackWithoutAnActorStillRecords(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	svc := newPackService(t, &fakePacks{rolled: rulecontentapi.PackRollback{Restored: "d"}}, audit)

	_, err := svc.Rollback(t.Context(), nil, "automated revert")
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	assert.Equal(t, "automated revert", audit.events[0].Payload["reason"])
}

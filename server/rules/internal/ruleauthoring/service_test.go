package ruleauthoring

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulecontentapi "github.com/fleetdm/edr/server/rulecontent/api"
)

// fakeAuthor stands in for rulecontent's lifecycle, recording what it was asked to do.
type fakeAuthor struct {
	put      []rulecontentapi.Document
	deleted  []string
	warnings []rulecontentapi.ContentWarning
	outbox   *fakeOutbox
	err      error
}

// fakeOutbox is the durable half: entries land here when the change commits, and the drain takes them from here. Holding them in
// a slice rather than delivering straight through is what lets a test assert the two are separable, which is the property the
// outbox exists to give.
type fakeOutbox struct {
	entries []rulecontentapi.PendingAuditEntry
	nextID  int64
	// readErr and deleteErr drive the drain's failure paths, which decide whether an entry is retried or lost.
	readErr   error
	deleteErr error
}

func (o *fakeOutbox) add(e rulecontentapi.AuditOutboxEntry) {
	o.nextID++
	o.entries = append(o.entries, rulecontentapi.PendingAuditEntry{ID: o.nextID, Kind: e.Kind, Payload: e.Payload})
}

func (o *fakeOutbox) PendingAuditEntries(_ context.Context, limit int) ([]rulecontentapi.PendingAuditEntry, error) {
	if o.readErr != nil {
		return nil, o.readErr
	}
	if len(o.entries) > limit {
		return o.entries[:limit], nil
	}
	return o.entries, nil
}

func (o *fakeOutbox) DeleteAuditEntries(_ context.Context, ids []int64) error {
	if o.deleteErr != nil {
		return o.deleteErr
	}
	keep := o.entries[:0]
	for _, e := range o.entries {
		if !slices.Contains(ids, e.ID) {
			keep = append(keep, e)
		}
	}
	o.entries = keep
	return nil
}

// Put invokes the builder the way the real lifecycle does, with the version it is about to return and the warnings it resolved,
// and commits the entry to the outbox. Modelling that ordering is the point: the entry has to be built from facts the caller does
// not have, and written with the change rather than after it (issue #886).
func (f *fakeAuthor) Put(
	_ context.Context, doc rulecontentapi.Document, mkAudit rulecontentapi.AuditEntryFunc,
) (int64, []rulecontentapi.ContentWarning, error) {
	f.put = append(f.put, doc)
	if f.err != nil {
		return 0, f.warnings, f.err
	}
	if err := f.commit(mkAudit, 11); err != nil {
		return 0, f.warnings, err
	}
	return 11, f.warnings, nil
}

func (f *fakeAuthor) Delete(
	_ context.Context, path string, mkAudit rulecontentapi.AuditEntryFunc,
) (int64, []rulecontentapi.ContentWarning, error) {
	f.deleted = append(f.deleted, path)
	if f.err != nil {
		return 0, f.warnings, f.err
	}
	if err := f.commit(mkAudit, 12); err != nil {
		return 0, f.warnings, err
	}
	return 12, f.warnings, nil
}

// commit builds the entry and appends it to the outbox, which is what the real store does inside its transaction.
func (f *fakeAuthor) commit(mkAudit rulecontentapi.AuditEntryFunc, version int64) error {
	entry, err := rulecontentapi.BuildAuditEntry(mkAudit, version, f.warnings)
	if err != nil {
		return err
	}
	if !entry.Zero() && f.outbox != nil {
		f.outbox.add(entry)
	}
	return nil
}

// fakeValidator is only reached by Check; the author owns validation for the mutating paths.
type fakeValidator struct {
	saw      []rulecontentapi.Document
	warnings []rulecontentapi.ContentWarning
	err      error
}

func (f *fakeValidator) Validate(_ context.Context, docs []rulecontentapi.Document) ([]rulecontentapi.ContentWarning, error) {
	f.saw = docs
	return f.warnings, f.err
}

// recordingAudit captures every audit row, which is what most of these tests assert on.
type recordingAudit struct {
	events []identityapi.AuditEvent
	err    error
}

func (a *recordingAudit) Record(_ context.Context, e identityapi.AuditEvent) error {
	a.events = append(a.events, e)
	return a.err
}

func newService(t *testing.T, author *fakeAuthor, v *fakeValidator, audit *recordingAudit) *Service {
	t.Helper()
	// The author and the service share one outbox, which is what the real wiring does: rulecontent writes the entry and the
	// rules-context drain reads it back. Wiring two would make every test pass against a service that delivered nothing.
	if author.outbox == nil {
		author.outbox = &fakeOutbox{}
	}
	s, err := New(author, v, author.outbox, audit, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return s
}

func testActor() *identityapi.Actor {
	return &identityapi.Actor{Principal: identityapi.PrincipalRef{
		ID: "usr_7", Type: identityapi.PrincipalUser, Label: "operator@example.com",
	}}
}

// spec:rule-content/every-authoring-change-is-attributable/a-write-is-attributed
func TestPut_IsAttributedWithTheStatedReason(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	author := &fakeAuthor{}

	version, _, err := newService(t, author, &fakeValidator{}, audit).
		Put(t.Context(), testActor(), "tightening keychain coverage", rulecontentapi.Document{
			Path: "authored/keychain_extra.yml", Content: []byte("title: x\n"),
		})
	require.NoError(t, err)
	assert.Equal(t, int64(11), version)

	require.Len(t, audit.events, 1)
	e := audit.events[0]
	assert.Equal(t, identityapi.AuditRuleContentDocumentPut, e.Action)
	assert.Equal(t, "rule_content_document", e.TargetType)
	assert.Equal(t, "authored/keychain_extra.yml", e.TargetID, "the row must name the document")
	assert.Equal(t, "usr_7", e.Actor.ID, "and the principal who changed it")
	assert.Equal(t, "tightening keychain coverage", e.Payload["reason"], "and why, which is the only field that says so")
	// EqualValues because the payload round-trips through the outbox as JSON, which normalises numeric types (issue #886).
	assert.EqualValues(t, 11, e.Payload["corpus_version"])
}

// spec:rule-content/every-authoring-change-is-attributable/a-deletion-is-attributed
func TestDelete_IsAttributed(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}

	_, _, err := newService(t, &fakeAuthor{}, &fakeValidator{}, audit).
		Delete(t.Context(), testActor(), "rule superseded upstream", "imported/old_rule.yml")
	require.NoError(t, err)

	require.Len(t, audit.events, 1)
	assert.Equal(t, identityapi.AuditRuleContentDocumentDelete, audit.events[0].Action,
		"a deletion must be distinguishable from a write, or the trail cannot say what happened")
	assert.Equal(t, "imported/old_rule.yml", audit.events[0].TargetID)
}

// spec:rule-content/every-authoring-change-is-attributable/a-refused-submission-is-not-recorded-as-a-mutation
//
// TestPut_RefusedIsNotAudited is the assertion most likely to pass by accident, because what it checks is the ABSENCE of a row.
// It is mutation-tested for exactly that reason: a service that audited unconditionally, or one that never audited at all, would
// have to fail a different test in this file.
func TestPut_RefusedIsNotAudited(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	author := &fakeAuthor{err: rulecontentapi.ErrRefused}

	_, _, err := newService(t, author, &fakeValidator{}, audit).
		Put(t.Context(), testActor(), "attempting a change", rulecontentapi.Document{Path: "authored/bad.yml"})

	require.ErrorIs(t, err, rulecontentapi.ErrRefused)
	assert.Empty(t, audit.events, "a submission that changed nothing must not be recorded as a mutation")
}

// TestDelete_NotFoundIsNotAudited is the same property on the other mutation. A delete that removed nothing is not a change.
func TestDelete_NotFoundIsNotAudited(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	author := &fakeAuthor{err: rulecontentapi.ErrDocumentNotFound}

	_, _, err := newService(t, author, &fakeValidator{}, audit).
		Delete(t.Context(), testActor(), "removing", "authored/never.yml")

	require.ErrorIs(t, err, rulecontentapi.ErrDocumentNotFound)
	assert.Empty(t, audit.events)
}

// spec:rule-content/every-authoring-change-is-attributable/a-change-without-a-stated-reason-is-refused
//
// TestChangesRequireAReason pins that the refusal happens BEFORE the author is called, so a reasonless change cannot alter the
// corpus and then fail to be explained.
func TestChangesRequireAReason(t *testing.T) {
	t.Parallel()
	for name, reason := range map[string]string{"empty": "", "whitespace": "   \t "} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			author := &fakeAuthor{}
			audit := &recordingAudit{}
			svc := newService(t, author, &fakeValidator{}, audit)

			_, _, putErr := svc.Put(t.Context(), testActor(), reason, rulecontentapi.Document{Path: "authored/a.yml"})
			_, _, delErr := svc.Delete(t.Context(), testActor(), reason, "authored/a.yml")

			require.ErrorIs(t, putErr, ErrReasonRequired)
			require.ErrorIs(t, delErr, ErrReasonRequired)
			assert.Empty(t, author.put, "the corpus must not be touched by a change nobody explained")
			assert.Empty(t, author.deleted)
			assert.Empty(t, audit.events)
		})
	}
}

// spec:rule-content/a-change-is-told-only-about-itself/an-audit-entry-carries-only-findings-about-its-own-change
//
// TestPut_WarningsAreRecorded keeps the trail useful for the question a reviewer actually asks later. A warning is the operator
// being told their rule will not fire; someone investigating why a detection never matched wants to know that was said at the
// time rather than rediscovering it.
func TestPut_WarningsAreRecorded(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	author := &fakeAuthor{warnings: []rulecontentapi.ContentWarning{
		{Path: "authored/a.yml", Message: "authored/a.yml will not run: unsupported field"},
	}}

	_, warnings, err := newService(t, author, &fakeValidator{}, audit).
		Put(t.Context(), testActor(), "adding a rule", rulecontentapi.Document{Path: "authored/a.yml"})
	require.NoError(t, err)

	assert.Equal(t, []string{"authored/a.yml will not run: unsupported field"}, warnings)
	require.Len(t, audit.events, 1)
	// A JSON round-trip turns []string into []any, so the elements are compared rather than the slice type.
	require.Len(t, audit.events[0].Payload["warnings"], 1)
	assert.Equal(t, "authored/a.yml will not run: unsupported field",
		audit.events[0].Payload["warnings"].([]any)[0])
}

// TestPut_CommittedChangeSurvivesAnAuditFailure pins the posture on the one ordering that has no good answer. The change is
// already durable, so reporting failure to the operator would be false; the error is logged instead, which is what a reviewer
// finding a gap in the trail has to work from.
func TestPut_CommittedChangeSurvivesAnAuditFailure(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{err: errors.New("audit store down")}

	version, _, err := newService(t, &fakeAuthor{}, &fakeValidator{}, audit).
		Put(t.Context(), testActor(), "adding a rule", rulecontentapi.Document{Path: "authored/a.yml"})

	require.NoError(t, err, "the write committed, so telling the operator it failed would be false")
	assert.Equal(t, int64(11), version)
}

// spec:rule-content/operators-can-check-content-before-publishing-it/a-check-reports-refusal-without-changing-anything
func TestCheck_ChangesNothingAndAuditsNothing(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	author := &fakeAuthor{}
	v := &fakeValidator{err: errors.New("rule id \"x\" is already claimed")}

	_, err := newService(t, author, v, audit).
		Check(t.Context(), rulecontentapi.Document{Path: "authored/x.yml", Content: []byte("title: x\n")})

	require.Error(t, err, "the check reports what would happen")
	assert.Empty(t, author.put, "and touches nothing")
	assert.Empty(t, author.deleted)
	assert.Empty(t, audit.events, "nothing happened to the thing being audited")
	require.Len(t, v.saw, 1, "the validator is asked about the submitted document")
}

// spec:rule-content/operators-can-check-content-before-publishing-it/a-check-reports-warnings-for-content-that-would-be-accepted
func TestCheck_ReportsWarnings(t *testing.T) {
	t.Parallel()
	v := &fakeValidator{warnings: []rulecontentapi.ContentWarning{
		{Path: "authored/x.yml", Message: "authored/x.yml will not run: unsupported field"},
	}}

	warnings, err := newService(t, &fakeAuthor{}, v, &recordingAudit{}).
		Check(t.Context(), rulecontentapi.Document{Path: "authored/x.yml"})

	require.NoError(t, err)
	assert.Equal(t, []string{"authored/x.yml will not run: unsupported field"}, warnings)
}

// TestNew_RequiresEveryCollaborator keeps "every authoring change is attributable" enforceable by the type rather than by the
// wiring.
//
// The recorder was optional in an earlier revision, and review showed what that cost: the caller mounts these routes whenever an
// author and a corpus are present, so a recorder-less wiring is a reachable state in which every successful change to what a
// fleet detects loses its audit row. A contract a construction can silently violate is not a contract.
func TestNew_RequiresEveryCollaborator(t *testing.T) {
	t.Parallel()
	_, noAuthor := New(nil, &fakeValidator{}, &fakeOutbox{}, &recordingAudit{}, nil)
	require.Error(t, noAuthor)
	_, noValidator := New(&fakeAuthor{}, nil, &fakeOutbox{}, &recordingAudit{}, nil)
	require.Error(t, noValidator)
	_, noRecorder := New(&fakeAuthor{}, &fakeValidator{}, &fakeOutbox{}, nil, nil)
	require.Error(t, noRecorder, "a surface that cannot audit must not be constructible")
	// The outbox is required for the same reason: a change that committed its entry into nothing is a change with no trail,
	// reached by wiring rather than by failure.
	_, noOutbox := New(&fakeAuthor{}, &fakeValidator{}, nil, &recordingAudit{}, nil)
	require.Error(t, noOutbox, "a surface whose audit entries go nowhere must not be constructible")
}

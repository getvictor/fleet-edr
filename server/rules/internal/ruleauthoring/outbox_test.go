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

func newDrain(t *testing.T, outbox *fakeOutbox, audit *recordingAudit) *AuditDrain {
	t.Helper()
	d, err := NewAuditDrain(outbox, audit, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return d
}

func encoded(t *testing.T, action identityapi.AuditAction) rulecontentapi.AuditOutboxEntry {
	t.Helper()
	e, err := encodeAuditEntry(identityapi.AuditEvent{Action: action, TargetType: "rule_content_document"})
	require.NoError(t, err)
	return e
}

// TestDrain_DeliversInOrderAndClearsWhatItDelivered is the ordinary path: entries become audit rows, oldest first, and the outbox
// empties only for what landed.
func TestDrain_DeliversInOrderAndClearsWhatItDelivered(t *testing.T) {
	t.Parallel()
	outbox := &fakeOutbox{}
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentPut))
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentDelete))
	audit := &recordingAudit{}

	delivered, err := newDrain(t, outbox, audit).Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, delivered)
	require.Len(t, audit.events, 2)
	assert.Equal(t, identityapi.AuditRuleContentDocumentPut, audit.events[0].Action, "oldest first")
	assert.Equal(t, identityapi.AuditRuleContentDocumentDelete, audit.events[1].Action)
	assert.Empty(t, outbox.entries, "delivered entries are cleared")
}

// spec:rule-content/every-authoring-change-is-attributable/a-delivery-failure-delays-the-audit-row-rather-than-losing-it
//
// TestDrain_ARecorderFailureLeavesTheEntry is the property the outbox exists for: a failure to write the audit row delays it
// rather than losing it, because the entry is durable and stays until it is delivered.
func TestDrain_ARecorderFailureLeavesTheEntry(t *testing.T) {
	t.Parallel()
	outbox := &fakeOutbox{}
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentPut))
	audit := &recordingAudit{err: errors.New("audit store down")}

	delivered, err := newDrain(t, outbox, audit).Drain(context.Background())
	require.Error(t, err)
	assert.Zero(t, delivered)
	require.Len(t, outbox.entries, 1, "the entry survives so a later sweep can deliver it")

	// And when the store comes back, the same entry lands.
	audit.err = nil
	delivered, err = newDrain(t, outbox, audit).Drain(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, delivered)
	assert.Empty(t, outbox.entries, "and it is cleared only once it has actually landed")
}

// TestDrain_StopsAtTheFirstFailureRatherThanSkippingIt pins the ordering guarantee under failure. Delivering a later entry over a
// failed earlier one would produce a trail whose order disagrees with the changes it records.
func TestDrain_StopsAtTheFirstFailureRatherThanSkippingIt(t *testing.T) {
	t.Parallel()
	outbox := &fakeOutbox{}
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentPut))
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentDelete))
	audit := &recordingAudit{err: errors.New("audit store down")}

	_, err := newDrain(t, outbox, audit).Drain(context.Background())
	require.Error(t, err)
	// One ATTEMPT, not two: the recorder is asked about the first entry and the drain stops. The fake records what it was asked
	// to record whether or not it reports success, which is what makes this the assertion that shows the second was never tried.
	assert.Len(t, audit.events, 1, "the drain stops at the first failure rather than skipping past it")
	assert.Len(t, outbox.entries, 2, "and neither entry is cleared")
}

// TestDrain_LeavesAnEntryItCannotDecode covers a rolling deployment, where the replica that wrote an entry may be a version ahead
// of the one draining it. Dropping what it could not read would lose the audit row that writer was careful to make durable.
func TestDrain_LeavesAnEntryItCannotDecode(t *testing.T) {
	t.Parallel()
	outbox := &fakeOutbox{}
	outbox.add(rulecontentapi.AuditOutboxEntry{Kind: "identity.audit_event.v2", Payload: []byte(`{}`)})
	outbox.add(encoded(t, identityapi.AuditRuleContentDocumentPut))
	audit := &recordingAudit{}

	delivered, err := newDrain(t, outbox, audit).Drain(context.Background())
	require.NoError(t, err)
	assert.Zero(t, delivered, "an unknown kind stops the drain rather than being skipped")
	assert.Empty(t, audit.events)
	assert.Len(t, outbox.entries, 2, "and it is left for a replica that understands it")
}

// TestDrain_RequiresItsCollaborators: a drain missing either half silently loses every audit row, which is the failure the outbox
// exists to prevent arriving through wiring instead.
func TestDrain_RequiresItsCollaborators(t *testing.T) {
	t.Parallel()
	_, noOutbox := NewAuditDrain(nil, &recordingAudit{}, nil)
	require.Error(t, noOutbox)
	_, noAudit := NewAuditDrain(&fakeOutbox{}, nil, nil)
	require.Error(t, noAudit)
	d, ok := NewAuditDrain(&fakeOutbox{}, &recordingAudit{}, nil)
	require.NoError(t, ok, "a nil logger is filled in rather than refused")
	require.NotNil(t, d)
}

// TestAuditEntry_RoundTrips pins the persisted encoding. The entry outlives the process that wrote it and may be read by a replica
// running different code, so what survives the round trip is a format rather than an implementation detail.
func TestAuditEntry_RoundTrips(t *testing.T) {
	t.Parallel()

	original := identityapi.AuditEvent{
		Actor: identityapi.PrincipalRef{
			ID:    identityapi.UserPrincipalID(7),
			Type:  identityapi.PrincipalUser,
			Label: "operator@example.com",
		},
		Action:     identityapi.AuditRuleContentDocumentPut,
		TargetType: "rule_content_document",
		TargetID:   "authored/mine.yml",
		Payload:    map[string]any{"reason": "tuning", "corpus_version": float64(11)},
	}

	entry, err := encodeAuditEntry(original)
	require.NoError(t, err)
	require.Equal(t, AuditOutboxKind, entry.Kind)

	back, err := decodeAuditEntry(entry.Payload)
	require.NoError(t, err)
	assert.Equal(t, original, back, "every field a rule-content audit row carries survives the outbox")
}

// TestAuditEntry_KeysAreTheFormat is the other half of the previous test, and the half a round trip cannot see: a round trip
// still passes if both sides rename a key together, and the entries already on disk would then decode to nothing.
func TestAuditEntry_KeysAreTheFormat(t *testing.T) {
	t.Parallel()

	entry, err := encodeAuditEntry(identityapi.AuditEvent{
		Actor:      identityapi.PrincipalRef{ID: "usr_7", Type: identityapi.PrincipalUser, Label: "operator"},
		Action:     identityapi.AuditRuleContentPackRollback,
		TargetType: "rule_content_pack",
		TargetID:   "sha256:abc",
	})
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"actor_id": "usr_7",
		"actor_type": "user",
		"actor_label": "operator",
		"action": "rule_content.pack_rollback",
		"target_type": "rule_content_pack",
		"target_id": "sha256:abc"
	}`, string(entry.Payload), "changing a key changes the on-disk format, so it changes AuditOutboxKind too")
}

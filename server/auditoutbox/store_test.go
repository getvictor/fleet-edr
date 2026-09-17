package auditoutbox_test

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/testdb"
)

// testTable is created here rather than migrated from a context, so this package's tests describe the table shape the package
// requires of whichever context adopts it. Each context's own integration tests exercise its migrated table through the same store.
const testTable = "test_audit_outbox"

const testTableDDL = `CREATE TABLE ` + testTable + ` (
	id         BIGINT       NOT NULL AUTO_INCREMENT,
	kind       VARCHAR(64)  NOT NULL,
	payload    JSON         NOT NULL,
	created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
	held_until TIMESTAMP(6) NULL,
	PRIMARY KEY (id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci`

func openOutbox(t *testing.T) (*auditoutbox.Store, *sqlx.DB) {
	t.Helper()
	db := testdb.Open(t)
	_, err := db.ExecContext(t.Context(), testTableDDL)
	require.NoError(t, err)
	return auditoutbox.NewStore(db, testTable), db
}

func entryFor(t *testing.T, targetID string) auditoutbox.Entry {
	t.Helper()
	entry, err := auditoutbox.Encode(identityapi.AuditEvent{
		Action: identityapi.AuditDetectionConfigExclusionCreate, TargetType: "detection_exclusion", TargetID: targetID,
	})
	require.NoError(t, err)
	return entry
}

// inTx commits write's statements in one transaction, as a detection-config change does.
func inTx(t *testing.T, db *sqlx.DB, write func(tx *sqlx.Tx)) {
	t.Helper()
	tx, err := db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	write(tx)
	require.NoError(t, tx.Commit())
}

func pendingTargets(t *testing.T, s *auditoutbox.Store) []string {
	t.Helper()
	pending, err := s.PendingAuditEntries(t.Context(), auditoutbox.DrainBatch)
	require.NoError(t, err)
	targets := make([]string, 0, len(pending))
	for _, p := range pending {
		e, err := auditoutbox.Decode(p.Payload)
		require.NoError(t, err)
		targets = append(targets, e.TargetID)
	}
	return targets
}

func TestStore_AnEnqueuedEntryIsPendingOnceCommittedAndGoneOnceDeleted(t *testing.T) {
	t.Parallel()
	s, db := openOutbox(t)
	inTx(t, db, func(tx *sqlx.Tx) {
		require.NoError(t, s.Enqueue(t.Context(), tx, entryFor(t, "first")))
		require.NoError(t, s.Enqueue(t.Context(), tx, entryFor(t, "second")))
	})

	pending, err := s.PendingAuditEntries(t.Context(), 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, auditoutbox.Kind, pending[0].Kind)
	assert.Equal(t, []string{"first", "second"}, pendingTargets(t, s), "oldest first")

	require.NoError(t, s.DeleteAuditEntries(t.Context(), []int64{pending[0].ID}))
	assert.Equal(t, []string{"second"}, pendingTargets(t, s))
}

func TestStore_AnEntryInARolledBackTransactionIsNeverPending(t *testing.T) {
	t.Parallel()
	s, db := openOutbox(t)
	tx, err := db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, s.Enqueue(t.Context(), tx, entryFor(t, "rolled back")))
	require.NoError(t, tx.Rollback())

	assert.Empty(t, pendingTargets(t, s))
}

// spec:server-detection-rules-engine/detection-config-changes-commit-their-audit-entry/an-entry-whose-writer-stops-is-still-delivered
// A held entry waits for its writer to seal it, and is delivered as first written once the hold passes, so a writer that stops
// between committing the change and completing the entry delays the audit row rather than losing it.
func TestStore_AHeldEntryWaitsForItsSealOrItsHold(t *testing.T) {
	t.Parallel()
	s, db := openOutbox(t)
	var sealedID int64
	inTx(t, db, func(tx *sqlx.Tx) {
		var err error
		sealedID, err = s.EnqueueHeld(t.Context(), tx, entryFor(t, "held then sealed"), time.Hour)
		require.NoError(t, err)
		_, err = s.EnqueueHeld(t.Context(), tx, entryFor(t, "held, writer gone"), time.Hour)
		require.NoError(t, err)
		_, err = s.EnqueueHeld(t.Context(), tx, entryFor(t, "hold passed"), -time.Second)
		require.NoError(t, err)
	})

	assert.Equal(t, []string{"hold passed"}, pendingTargets(t, s), "an entry is withheld only while its hold lasts")

	sealed, err := s.Seal(t.Context(), sealedID, entryFor(t, "sealed with counts"))
	require.NoError(t, err)
	assert.True(t, sealed)
	assert.Equal(t, []string{"sealed with counts", "hold passed"}, pendingTargets(t, s),
		"sealing releases the entry with its new payload, in its original order")

	require.NoError(t, s.DeleteAuditEntries(t.Context(), []int64{sealedID}))
	sealed, err = s.Seal(t.Context(), sealedID, entryFor(t, "too late"))
	require.NoError(t, err)
	assert.False(t, sealed, "an entry already delivered cannot be sealed")
}

// A seal in flight holds its row, and a drain waits for it rather than reading the payload the seal is replacing or skipping ahead of
// it, so the entry is delivered sealed and in its place in the order.
func TestStore_ADrainWaitsForASealInFlight(t *testing.T) {
	t.Parallel()
	s, db := openOutbox(t)
	var id int64
	inTx(t, db, func(tx *sqlx.Tx) {
		var err error
		id, err = s.EnqueueHeld(t.Context(), tx, entryFor(t, "as first written"), -time.Second)
		require.NoError(t, err)
		require.NoError(t, s.Enqueue(t.Context(), tx, entryFor(t, "written after it")))
	})

	sealing, err := db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = sealing.Rollback() }()
	sealed := entryFor(t, "with counts")
	_, err = sealing.ExecContext(t.Context(), `UPDATE `+testTable+` SET payload = ?, held_until = NULL WHERE id = ?`,
		string(sealed.Payload), id)
	require.NoError(t, err)

	type result struct {
		pending []auditoutbox.Pending
		err     error
	}
	read := make(chan result, 1)
	go func() {
		pending, err := s.PendingAuditEntries(t.Context(), auditoutbox.DrainBatch)
		read <- result{pending, err}
	}()
	select {
	case r := <-read:
		t.Fatalf("the drain read %d entries past an uncommitted seal instead of waiting for it", len(r.pending))
	case <-time.After(300 * time.Millisecond):
	}
	require.NoError(t, sealing.Commit())
	r := <-read
	require.NoError(t, r.err)
	targets := make([]string, 0, len(r.pending))
	for _, p := range r.pending {
		e, err := auditoutbox.Decode(p.Payload)
		require.NoError(t, err)
		targets = append(targets, e.TargetID)
	}
	assert.Equal(t, []string{"with counts", "written after it"}, targets, "the sealed entry, first, as it was written")
}

// Once a held entry's hold has passed, a drain may already have read it as first written, so sealing it is refused and it is
// delivered unchanged: a seal cannot report counts added to a row a drain is recording without them.
func TestStore_AnEntryPastItsHoldCannotBeSealed(t *testing.T) {
	t.Parallel()
	s, db := openOutbox(t)
	var lapsedID int64
	inTx(t, db, func(tx *sqlx.Tx) {
		var err error
		lapsedID, err = s.EnqueueHeld(t.Context(), tx, entryFor(t, "as first written"), -time.Second)
		require.NoError(t, err)
	})

	sealed, err := s.Seal(t.Context(), lapsedID, entryFor(t, "with counts"))
	require.NoError(t, err)
	assert.False(t, sealed)
	assert.Equal(t, []string{"as first written"}, pendingTargets(t, s))
}

func TestNewStore_PanicsOnWiringItCannotUse(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { auditoutbox.NewStore(nil, testTable) }, "a nil database")
	db := testdb.Open(t)
	for _, table := range []string{"", "audit outbox", "outbox; DROP TABLE hosts", "Outbox", "1_outbox", "db.outbox"} {
		assert.Panics(t, func() { auditoutbox.NewStore(db, table) }, "table %q", table)
	}
	assert.NotPanics(t, func() { auditoutbox.NewStore(db, "response_audit_outbox") })
}

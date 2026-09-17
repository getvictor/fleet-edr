//go:build integration

package service_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/auditoutbox"
	identityapi "github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

func entryFor(t *testing.T, action identityapi.AuditAction) service.AuditEntryFor {
	t.Helper()
	return func(cmd service.AuditedCommand) (auditoutbox.Entry, error) {
		return auditoutbox.Encode(identityapi.AuditEvent{
			Action: action, TargetType: "host", TargetID: cmd.HostID, Payload: map[string]any{"command_id": cmd.ID},
		})
	}
}

// spec:server-admin-surface/operator-actions-commit-their-audit-entry/a-refused-action-commits-no-audit-entry
//
// The entry's own write is what fails here, through a service whose outbox names a table that does not exist, and the command is then
// asserted to have rolled back with it. That is the direction that proves the enqueue runs inside the action's transaction: an action
// that failed before reaching the enqueue would leave the outbox empty however the entry was written.
func TestInsertAudited_AFailedEntryRollsBackTheCommand(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := mysql.NewStore(db)

	svc := service.New(store, nil, nil)
	svc.SetAuditOutbox(auditoutbox.NewStore(db, "absent_audit_outbox"), nil)

	_, err := svc.InsertAudited(t.Context(), "host-a", "kill_process", []byte(`{"pid":1}`),
		entryFor(t, identityapi.AuditCommandIssue))
	require.Error(t, err, "a command whose audit entry cannot be written is refused, not queued without one")

	cmds, err := store.ListForHost(t.Context(), "host-a", "")
	require.NoError(t, err)
	assert.Empty(t, cmds, "the command rolled back with the entry")
}

// An entry builder that fails refuses the action for the same reason: the point of committing them together is that neither exists
// without the other, so a row the handler could not encode must not leave a command behind.
func TestInsertAudited_AnEntryThatCannotBeBuiltRefusesTheAction(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := mysql.NewStore(db)

	svc := service.New(store, nil, nil)
	svc.SetAuditOutbox(auditoutbox.NewStore(db, mysql.AuditOutboxTable), nil)

	boom := errors.New("cannot encode")
	_, err := svc.InsertAudited(t.Context(), "host-a", "kill_process", []byte(`{"pid":1}`),
		func(service.AuditedCommand) (auditoutbox.Entry, error) { return auditoutbox.Entry{}, boom })
	require.ErrorIs(t, err, boom)

	cmds, err := store.ListForHost(t.Context(), "host-a", "")
	require.NoError(t, err)
	assert.Empty(t, cmds)
}

// A withdrawal commits its entry the same way, and the command keeps its status when the entry cannot be written.
func TestUpdateStatusAudited_AFailedEntryLeavesTheCommandAsItWas(t *testing.T) {
	t.Parallel()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	store := mysql.NewStore(db)

	svc := service.New(store, nil, nil)
	svc.SetAuditOutbox(auditoutbox.NewStore(db, mysql.AuditOutboxTable), nil)
	id, err := svc.InsertAudited(t.Context(), "host-a", "kill_process", []byte(`{"pid":1}`),
		entryFor(t, identityapi.AuditCommandIssue))
	require.NoError(t, err)

	svc.SetAuditOutbox(auditoutbox.NewStore(db, "absent_audit_outbox"), nil)
	err = svc.UpdateStatusAudited(t.Context(), api.UpdateStatusRequest{ID: id, HostID: "host-a", Status: api.StatusCancelled},
		entryFor(t, identityapi.AuditCommandCancel))
	require.Error(t, err)

	cmd, err := store.Get(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, api.StatusPending, cmd.Status, "the withdrawal rolled back with its entry")
}

package service_test

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newSvc builds a service over an isolated test DB. External test package + testkit.ApplySchema avoids the testdb -> bootstrap ->
// service import cycle (same reason the mysql store tests live in package mysql_test).
func newSvc(t *testing.T) *service.Service {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return service.New(mysql.NewStore(db), nil, nil)
}

// TestServiceListPendingForHosts covers the control gateway's pending query through the service passthrough.
func TestServiceListPendingForHosts(t *testing.T) {
	t.Parallel()
	svc := newSvc(t)
	ctx := t.Context()

	_, err := svc.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{"n":1}`))
	require.NoError(t, err)
	_, err = svc.Insert(ctx, "host-b", "kill_process", json.RawMessage(`{"n":2}`))
	require.NoError(t, err)

	cmds, err := svc.ListPendingForHosts(ctx, []string{"host-a"})
	require.NoError(t, err)
	require.Len(t, cmds, 1)
	assert.Equal(t, "host-a", cmds[0].HostID)
	assert.Equal(t, api.StatusPending, cmds[0].Status)
}

// TestServiceFastNotify confirms the control-gateway fast-path callback fires once per queued host on both Insert and InsertBatch.
func TestServiceFastNotify(t *testing.T) {
	t.Parallel()
	svc := newSvc(t)
	ctx := t.Context()

	var mu sync.Mutex
	var notified []string
	svc.SetNotifier(func(hostID string) {
		mu.Lock()
		defer mu.Unlock()
		notified = append(notified, hostID)
	})

	_, err := svc.Insert(ctx, "host-a", "kill_process", json.RawMessage(`{}`))
	require.NoError(t, err)
	_, err = svc.InsertBatch(ctx, []string{"host-b", "host-c"}, "set_application_control",
		json.RawMessage(`{"policy_id":1,"policy_version":1,"rules":[]}`))
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"host-a", "host-b", "host-c"}, notified)
}

// TestServiceInsertValidationDoesNotNotify ensures a rejected insert does not fire the fast-path callback.
func TestServiceInsertValidationDoesNotNotify(t *testing.T) {
	t.Parallel()
	svc := newSvc(t)
	ctx := t.Context()

	notified := false
	svc.SetNotifier(func(string) { notified = true })

	_, err := svc.Insert(ctx, "", "kill_process", json.RawMessage(`{}`))
	require.ErrorIs(t, err, api.ErrInvalidInsertRequest)
	assert.False(t, notified, "a rejected insert must not notify the gateway")
}

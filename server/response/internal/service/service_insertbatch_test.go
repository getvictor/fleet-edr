package service_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/response/api"
	"github.com/fleetdm/edr/server/response/internal/mysql"
	"github.com/fleetdm/edr/server/response/internal/service"
	"github.com/fleetdm/edr/server/response/testkit"
	"github.com/fleetdm/edr/server/testdb"
)

// newBatchService wires a Service over an isolated test DB. External test package so the testdb -> bootstrap -> mysql cycle
// doesn't bite, matching the mysql store tests' posture.
func newBatchService(t *testing.T) *service.Service {
	t.Helper()
	db := testdb.Open(t)
	require.NoError(t, testkit.ApplySchema(t.Context(), db))
	return service.New(mysql.NewStore(db), nil, nil)
}

// TestInsertBatch_Validation pins the boundary guards the fan-out relies on: an empty host set, command type, or payload all wrap
// ErrInvalidInsertRequest so a caller can errors.Is + map to 400 rather than emit a malformed multi-row INSERT. The happy path
// is exercised end-to-end by the mysql store tests; here we assert the validation branches and that a valid batch lands.
func TestInsertBatch_Validation(t *testing.T) {
	t.Parallel()
	svc := newBatchService(t)
	ctx := t.Context()
	payload := json.RawMessage(`{"policy_id":1}`)

	cases := []struct {
		name        string
		hostIDs     []string
		commandType string
		payload     []byte
	}{
		{name: "empty host set", hostIDs: nil, commandType: "set_application_control", payload: payload},
		{name: "blank command type", hostIDs: []string{"host-a"}, commandType: "   ", payload: payload},
		{name: "empty payload", hostIDs: []string{"host-a"}, commandType: "set_application_control", payload: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			inserted, err := svc.InsertBatch(ctx, tc.hostIDs, tc.commandType, tc.payload)
			require.ErrorIs(t, err, api.ErrInvalidInsertRequest)
			assert.Zero(t, inserted)
		})
	}

	t.Run("valid batch lands", func(t *testing.T) {
		t.Parallel()
		inserted, err := svc.InsertBatch(ctx, []string{"host-x", "host-y"}, "set_application_control", payload)
		require.NoError(t, err)
		assert.Equal(t, 2, inserted)
	})
}

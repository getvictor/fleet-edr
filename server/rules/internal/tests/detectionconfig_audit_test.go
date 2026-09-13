//go:build integration

package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityapi "github.com/fleetdm/edr/server/identity/api"
	rulesbootstrap "github.com/fleetdm/edr/server/rules/bootstrap"
	"github.com/fleetdm/edr/server/rules/internal/auditoutbox"
)

// Detection-config changes made over the REST surface reach the audit store through the outbox the rules context wires, and leave
// the outbox empty once delivered.
func TestDetectionConfigAudit_RESTChangesAreDelivered(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"})

	created := r.do(t, http.MethodPost, "/api/v1/detection-config/exclusions",
		map[string]any{"rule_id": "suspicious_exec", "match_type": "parent_path_glob", "value": "*/ci/*", "reason": "ci runner"})
	created.Body.Close()
	require.Equal(t, http.StatusCreated, created.StatusCode)
	setting := r.do(t, http.MethodPut, "/api/v1/detection-config/rule-settings",
		map[string]any{"rule_id": "suspicious_exec", "mode": "monitor", "reason": "noisy"})
	setting.Body.Close()
	require.Equal(t, http.StatusOK, setting.StatusCode)

	events := r.audit.snapshot()
	require.Len(t, events, 2)
	assert.Equal(t, identityapi.AuditDetectionConfigExclusionCreate, events[0].Action)
	assert.Equal(t, "ci runner", events[0].Payload["reason"])
	assert.Equal(t, identityapi.AuditDetectionConfigRuleSettingUpdate, events[1].Action)
	pending, err := auditoutbox.NewStore(r.db).PendingAuditEntries(t.Context(), auditoutbox.DrainBatch)
	require.NoError(t, err)
	assert.Empty(t, pending)
}

// The rules context sweeps the detection-config outbox, so an entry a request committed but could not deliver is delivered
// without another request.
func TestDetectionConfigAudit_TheSweepDeliversWhatARequestLeftBehind(t *testing.T) {
	t.Parallel()
	r := newAppControlRig(t, []string{"host-a"}, func(d *rulesbootstrap.Deps) {
		d.AuditSweepInterval = 20 * time.Millisecond
	})
	entry, err := auditoutbox.Encode(identityapi.AuditEvent{
		Action: identityapi.AuditDetectionConfigExclusionDelete, TargetType: "detection_exclusion", TargetID: "41",
	})
	require.NoError(t, err)
	tx, err := r.db.BeginTxx(t.Context(), nil)
	require.NoError(t, err)
	require.NoError(t, auditoutbox.Enqueue(t.Context(), tx, entry))
	require.NoError(t, tx.Commit())

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.rules.Run(ctx); close(done) }()
	require.Eventually(t, func() bool {
		for _, e := range r.audit.snapshot() {
			if e.TargetID == "41" {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
	cancel()
	<-done
}

package authz_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/authz"
)

// recordingAsync is the AsyncAuditWriter test double: every Submit records the event and reports success. Tests pin the count + the
// per-event payload so the chokepoint's routing decisions are observable end-to-end.
type recordingAsync struct {
	mu     sync.Mutex
	events []api.AuditEvent
	dropAt int // when > 0, return false on Submit #dropAt to test dual-emit fallback
	calls  int
}

func (r *recordingAsync) Submit(_ context.Context, e api.AuditEvent) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.dropAt > 0 && r.calls == r.dropAt {
		return false
	}
	r.events = append(r.events, e)
	return true
}

func (r *recordingAsync) snapshot() []api.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]api.AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

func newAsyncEngine(t *testing.T, rate float64) (*authz.Engine, *recordingAudit, *recordingAsync) {
	t.Helper()
	syncRec := &recordingAudit{}
	asyncW := &recordingAsync{}
	e, err := authz.New(t.Context(), syncRec, nil, authz.Options{
		AsyncRead:        asyncW,
		ReadSamplingRate: rate,
	})
	require.NoError(t, err, "construct engine")
	return e, syncRec, asyncW
}

// rate=0.0 + read action + non-break-glass + Allow → no row anywhere. The chokepoint elides the emission entirely; sampling drops it
// before it reaches the async writer or the sync recorder.
func TestAllow_ReadAllow_RateZero_DropsEverywhere(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 0.0)
	actor := actorWithRoles(1, "default", globalBinding("auditor", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionAlertRead, api.Resource{Type: "alert"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Empty(t, syncRec.snapshot(), "rate=0.0 must NOT write to the sync recorder")
	assert.Empty(t, asyncRec.snapshot(), "rate=0.0 must NOT submit to the async writer")
}

// rate=1.0 + read action + non-break-glass + Allow → exactly one async submission, zero sync rows. Confirms the chokepoint routes to
// async (not sync) when sampling includes the event.
func TestAllow_ReadAllow_RateOne_RoutesAsync(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 1.0)
	actor := actorWithRoles(1, "default", globalBinding("auditor", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionAlertRead, api.Resource{Type: "alert"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	assert.Empty(t, syncRec.snapshot(), "rate=1.0 read-allow must NOT write sync; the async writer is the durable sink")
	require.Len(t, asyncRec.snapshot(), 1)
	assert.Equal(t, api.AuditAction("authz.alert.read"), asyncRec.snapshot()[0].Action)
}

// Break-glass actor reads at rate=0.0 still audit synchronously. The carve-out is critical: missing one break-glass action would
// defeat the surface's audit purpose.
func TestAllow_ReadAllow_BreakGlass_AlwaysSync(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 0.0)
	actor := actorWithRoles(1, "default", globalBinding("admin", "default"))
	actor.IsBreakglass = true
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostRead, api.Resource{Type: "host"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	require.Len(t, syncRec.snapshot(), 1, "break-glass reads MUST write sync")
	assert.Empty(t, asyncRec.snapshot(), "break-glass reads must NOT take the async path")
}

// audit.read at rate=0.0 always writes the audit-of-audit row. The chokepoint exempts ActionAuditRead from the sampling gate so
// auditors can always trace who read the audit log.
func TestAllow_AuditRead_AlwaysSync(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 0.0)
	actor := actorWithRoles(1, "default", globalBinding("auditor", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionAuditRead, api.Resource{Type: "audit"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	require.Len(t, syncRec.snapshot(), 1, "audit.read MUST always emit the audit-of-audit row")
	assert.Equal(t, api.AuditAction("authz.audit.read"), syncRec.snapshot()[0].Action)
	assert.Empty(t, asyncRec.snapshot(), "audit.read does not take the async path")
}

// Deny on a read action at rate=0.0 always writes sync. Denies are the security signal Phase 6's dashboard pivots on; sampling them
// would defeat the dashboard.
func TestAllow_ReadDeny_AlwaysSync(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 0.0)
	// analyst has host.read but not enrollment.read; exercise a read
	// deny against a role that is missing the specific grant.
	actor := actorWithRoles(1, "default", globalBinding("analyst", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionEnrollmentRead, api.Resource{Type: "enrollment"})
	require.NoError(t, err)
	assert.False(t, d.Allow, "missing enrollment.read grant must deny")
	require.Len(t, syncRec.snapshot(), 1, "deny MUST emit sync regardless of read sampling")
	assert.Empty(t, asyncRec.snapshot())
}

// Write actions never take the async path even at rate=1.0. Writes are infrequent and security-relevant; durability matters more than
// latency on these emissions.
func TestAllow_WriteAllow_AlwaysSync(t *testing.T) {
	e, syncRec, asyncRec := newAsyncEngine(t, 1.0)
	actor := actorWithRoles(1, "default", globalBinding("admin", "default"))
	ctx := api.WithActor(t.Context(), actor)
	d, err := e.Allow(ctx, api.ActionHostIsolate, api.Resource{Type: "host", ID: "h-1"})
	require.NoError(t, err)
	assert.True(t, d.Allow)
	require.Len(t, syncRec.snapshot(), 1, "write actions MUST write sync at every rate")
	assert.Empty(t, asyncRec.snapshot())
}

// When the async writer reports false (queue full or stopped), the chokepoint falls back to the sync path so the row still lands.
// Dual-emit guards against losing audit content on transient burst.
func TestAllow_ReadAllow_AsyncDrop_FallsBackToSync(t *testing.T) {
	syncRec := &recordingAudit{}
	asyncRec := &recordingAsync{dropAt: 1}
	e, err := authz.New(t.Context(), syncRec, nil, authz.Options{
		AsyncRead:        asyncRec,
		ReadSamplingRate: 1.0,
	})
	require.NoError(t, err)

	actor := actorWithRoles(1, "default", globalBinding("auditor", "default"))
	ctx := api.WithActor(t.Context(), actor)
	_, err = e.Allow(ctx, api.ActionAlertRead, api.Resource{Type: "alert"})
	require.NoError(t, err)

	// Async Submit returned false; the row must land in the sync
	// recorder instead.
	require.Len(t, syncRec.snapshot(), 1, "drop on full async queue must fall back to sync")
	assert.Empty(t, asyncRec.snapshot(), "no event made it past the dropping Submit")
}

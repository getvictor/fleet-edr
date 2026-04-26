package reconcile

import (
	"context"
	"encoding/json"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/agent/proctable"
)

type recorderQueue struct {
	mu     sync.Mutex
	events [][]byte
}

func (r *recorderQueue) Enqueue(_ context.Context, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.events = append(r.events, cp)
	return nil
}

func (r *recorderQueue) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.events))
	copy(out, r.events)
	return out
}

// killer plugs a deterministic alive/dead map into the reconciler.
type killer struct {
	dead map[int]bool // pid → true means kill returns ESRCH
}

func (k *killer) call(pid int, _ syscall.Signal) error {
	if k.dead[pid] {
		return syscall.ESRCH
	}
	return nil
}

func newRunner(t *testing.T, pt *proctable.Table, q *recorderQueue, k *killer, hostID string, opts Options) *Reconciler {
	t.Helper()
	if opts.Now == nil {
		// Pin "now" sufficiently far past every test PID's StartTime so the
		// MinAge guard never fires by accident.
		opts.Now = func() time.Time { return time.Unix(0, 1_000_000_000_000) }
	}
	if opts.Kill == nil {
		opts.Kill = k.call
	}
	return New(pt, q, func() string { return hostID }, opts)
}

func TestRunOnce_EmitsExitForDeadPID(t *testing.T) {
	pt := proctable.New()
	pt.Update(123, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})
	pt.Update(456, proctable.ProcessInfo{Path: "/bin/alive", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{123: true}}

	r := newRunner(t, pt, q, k, "host-A", Options{})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one synthetic exit must be emitted")

	events := q.snapshot()
	require.Len(t, events, 1)

	var env struct {
		EventID     string         `json:"event_id"`
		HostID      string         `json:"host_id"`
		TimestampNs int64          `json:"timestamp_ns"`
		EventType   string         `json:"event_type"`
		Payload     map[string]any `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(events[0], &env))
	assert.Equal(t, "exit", env.EventType)
	assert.Equal(t, "host-A", env.HostID)
	assert.NotEmpty(t, env.EventID, "event_id must be a UUID")
	assert.Len(t, env.EventID, 36)
	assert.EqualValues(t, 123, env.Payload["pid"])
	assert.EqualValues(t, -1, env.Payload["exit_code"])
	assert.Equal(t, "host_reconciled", env.Payload["exit_reason"])

	// Dead PID was pruned; live PID remains.
	_, ok := pt.Lookup(123)
	assert.False(t, ok, "dead PID must be removed from the proctable after reconcile")
	_, ok = pt.Lookup(456)
	assert.True(t, ok, "live PID must remain in the proctable")
}

func TestRunOnce_EPERMAndOtherErrorsTreatedAsAlive(t *testing.T) {
	pt := proctable.New()
	pt.Update(10, proctable.ProcessInfo{Path: "/bin/perm", StartTime: 0})
	pt.Update(11, proctable.ProcessInfo{Path: "/bin/other", StartTime: 0})

	q := &recorderQueue{}
	r := newRunner(t, pt, q, nil, "h", Options{
		Kill: func(pid int, _ syscall.Signal) error {
			if pid == 10 {
				return syscall.EPERM
			}
			return syscall.EINVAL
		},
	})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "only ESRCH must trigger a synthetic exit; EPERM/EINVAL stay live")
	assert.Empty(t, q.snapshot())
	assert.Equal(t, 2, pt.Size(), "neither PID may be pruned")
}

func TestRunOnce_RespectsMinAge(t *testing.T) {
	now := time.Unix(0, 1_000_000_000_000)
	pt := proctable.New()
	// "young" PID was first seen 5s ago; "old" PID was first seen 5min ago.
	pt.Update(7, proctable.ProcessInfo{Path: "/bin/young", StartTime: now.UnixNano() - int64(5*time.Second)})
	pt.Update(8, proctable.ProcessInfo{Path: "/bin/old", StartTime: now.UnixNano() - int64(5*time.Minute)})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{7: true, 8: true}} // both probed dead

	r := newRunner(t, pt, q, k, "h", Options{
		MinAge: 30 * time.Second,
		Now:    func() time.Time { return now },
	})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the older PID is eligible for reconciliation")

	_, ok := pt.Lookup(8)
	assert.False(t, ok, "old dead PID must be pruned")
	_, ok = pt.Lookup(7)
	assert.True(t, ok, "young dead PID must be left in place this pass")
}

func TestRunOnce_NoHostIDSkips(t *testing.T) {
	pt := proctable.New()
	pt.Update(1, proctable.ProcessInfo{Path: "/bin/x", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{1: true}}

	r := New(pt, q, func() string { return "" }, Options{Kill: k.call,
		Now: func() time.Time { return time.Unix(0, 1_000_000_000_000) }})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Empty(t, q.snapshot())
	_, ok := pt.Lookup(1)
	assert.True(t, ok, "no host_id means no events; the proctable must stay intact")
}

func TestRunOnce_CapsAtMaxPerPass(t *testing.T) {
	pt := proctable.New()
	dead := make(map[int]bool, 10)
	for i := int32(1); i <= 10; i++ {
		pt.Update(i, proctable.ProcessInfo{Path: "/bin/x", StartTime: 0})
		dead[int(i)] = true
	}

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{dead: dead}, "h", Options{MaxPerPass: 3})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, 7, pt.Size(), "only the cap is reaped per pass")
}

func TestRunOnce_SkipsPID0(t *testing.T) {
	pt := proctable.New()
	pt.Update(0, proctable.ProcessInfo{Path: "/zero", StartTime: 0})

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{dead: map[int]bool{0: true}}, "h", Options{
		Kill: func(_ int, _ syscall.Signal) error {
			t.Fatalf("kill must not be called for PID 0")
			return nil
		},
	})

	n, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, 1, pt.Size(), "PID 0 is left alone, not reaped")
}

func TestNewUUIDv4_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		u, err := newUUIDv4()
		require.NoError(t, err)
		require.Len(t, u, 36)
		assert.Equal(t, byte('-'), u[8])
		assert.Equal(t, byte('-'), u[13])
		assert.Equal(t, byte('-'), u[18])
		assert.Equal(t, byte('-'), u[23])
		assert.Equal(t, byte('4'), u[14], "version nibble must be 4")
		assert.Contains(t, "89ab", string(u[19]), "variant nibble must be 8/9/a/b")
		assert.False(t, seen[u], "uuids must be unique across calls")
		seen[u] = true
	}
}

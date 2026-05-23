package reconcile

import (
	"context"
	"encoding/json"
	"errors"
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
	// failNext, when non-nil, makes the next Enqueue call return this error instead of recording. Used to exercise the reconciler's
	// enqueue-error branch without standing up a real queue.
	failNext error
}

func (r *recorderQueue) Enqueue(_ context.Context, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.failNext; err != nil {
		r.failNext = nil
		return err
	}
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
		// Falling back to k.call is a convenience for the common case; if a test passed nil for both we'd dereference nil
		// in the runner's first pass. Fail-fast in the helper instead so the diagnostic points at the test setup, not at a
		// nil-deref panic deep inside the loop.
		if k == nil {
			t.Fatal("newRunner: either opts.Kill or k must be non-nil")
		}
		opts.Kill = k.call
	}
	return New(pt, q, func() string { return hostID }, opts)
}

// spec:agent-event-queue/synthetic-reconciliation-events-use-the-same-queue/reconciliation-exit-event-is-queued-and-uploaded
// spec:agent-process-reconciliation/periodic-kill-zero-sweep/tracked-process-has-exited-without-a-notification
// spec:agent-process-reconciliation/synthetic-exits-are-distinguishable/synthetic-exit-shape
// spec:agent-process-reconciliation/synthetic-exits-flow-through-the-standard-queue/enqueue-path-is-the-standard-queue
//
// Four scenarios share this test:
//   - agent-event-queue: synthesized exit flows through standard enqueue path with exit_reason intact.
//   - periodic-kill-zero-sweep: kernel reports "no such process" => synthetic exit + PID pruned from table.
//   - synthetic-exit-shape: event_type="exit", exit_reason="host_reconciled", fresh UUID event_id, host_id
//     populated — all four shape clauses are pinned by the env.* assertions below.
//   - enqueue-path-is-the-standard-queue: the reconciler wires its Enqueuer to the same interface the
//     production `*queue.Queue` satisfies, so durability/batching/dedup are inherited for free.
//
// One test legitimately demonstrates four distinct scenario clauses because they all collapse to the same
// observation: "a PID that the kernel says is gone produces an exit event of the documented shape via the
// standard queue interface, and the PID is removed from the tracking table."
func TestRunOnce_EmitsExitForDeadPID(t *testing.T) {
	pt := proctable.New()
	pt.Update(123, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})
	pt.Update(456, proctable.ProcessInfo{Path: "/bin/alive", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{123: true}}

	r := newRunner(t, pt, q, k, "host-A", Options{})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 1, stats.Exits, "exactly one synthetic exit must be emitted")
	assert.Equal(t, 0, stats.Heartbeats)

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

// spec:agent-process-reconciliation/periodic-kill-zero-sweep/probe-is-blocked-by-permissions
//
// Demonstrates the main clause of the scenario: when the kernel returns EPERM/EINVAL rather than ESRCH,
// the entry is treated as alive (no synthetic exit) and stays in the proctable. The AND clause about
// snapshot-originated processes receiving a heartbeat under EPERM is covered by the companion test
// TestRunOnce_EPERMOnSnapshotPIDEmitsHeartbeat below; this test exercises non-snapshot PIDs only.
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

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits, "only ESRCH must trigger a synthetic exit; EPERM/EINVAL stay live")
	assert.Equal(t, 0, stats.Heartbeats)
	assert.Empty(t, q.snapshot())
	assert.Equal(t, 2, pt.Size(), "neither PID may be pruned")
}

// spec:agent-process-reconciliation/reconciliation-respects-the-freshly-observed-window/newly-observed-process
//
// Both PIDs are probed dead. The young one (5s ago, inside the 30s MinAge window) is skipped this pass and
// stays in the proctable; the old one (5min ago) is reaped. Pins both the "skipped this pass" clause and
// the implicit "reconsidered on a future pass" — the proctable entry is preserved, so the next pass with
// the clock advanced past MinAge would reap it.
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

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 1, stats.Exits, "only the older PID is eligible for reconciliation")

	_, ok := pt.Lookup(8)
	assert.False(t, ok, "old dead PID must be pruned")
	_, ok = pt.Lookup(7)
	assert.True(t, ok, "young dead PID must be left in place this pass")
}

// spec:agent-process-reconciliation/skip-when-host-identity-is-unknown/enrollment-has-not-yet-completed
//
// hostFn returns "" (no enrollment). The pass MUST exit immediately: no probes, no enqueues, no proctable
// mutations. Pinned by the three assertions below — 0 exits, 0 heartbeats, queue empty — plus pt.Lookup(1)
// confirming the entry was not touched.
func TestRunOnce_NoHostIDSkips(t *testing.T) {
	pt := proctable.New()
	pt.Update(1, proctable.ProcessInfo{Path: "/bin/x", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{1: true}}

	r := New(pt, q, func() string { return "" }, Options{Kill: k.call,
		Now: func() time.Time { return time.Unix(0, 1_000_000_000_000) }})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits)
	assert.Equal(t, 0, stats.Heartbeats)
	assert.Empty(t, q.snapshot())
	_, ok := pt.Lookup(1)
	assert.True(t, ok, "no host_id means no events; the proctable must stay intact")
}

// spec:agent-process-reconciliation/per-pass-cap-on-synthetic-exits/many-stale-entries-at-once
//
// 10 dead PIDs, cap=3 => exactly 3 exits emitted and 7 entries left in the proctable for subsequent
// passes to reconcile. The companion scenario about heartbeats continuing past the exit cap is covered by
// TestRunOnce_ExitCapDoesNotGateHeartbeats below; this test pins the pure exit-cap clause with non-snapshot
// PIDs so the heartbeat path is out of the picture.
func TestRunOnce_CapsAtMaxPerPass(t *testing.T) {
	pt := proctable.New()
	dead := make(map[int]bool, 10)
	for i := int32(1); i <= 10; i++ {
		pt.Update(i, proctable.ProcessInfo{Path: "/bin/x", StartTime: 0})
		dead[int(i)] = true
	}

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{dead: dead}, "h", Options{MaxPerPass: 3})

	stats := r.RunOnce(context.Background())
	// Map iteration is non-deterministic in Go, so we deliberately assert only on the count of reaped PIDs and the table size — never on
	// which specific PIDs survive. Adding "PID X must be reaped" assertions here would flake.
	assert.Equal(t, 3, stats.Exits)
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

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits)
	assert.Equal(t, 1, pt.Size(), "PID 0 is left alone, not reaped")
}

// spec:agent-event-queue/synthetic-reconciliation-events-use-the-same-queue/snapshot-heartbeat-event-is-queued-and-uploaded
// spec:agent-process-reconciliation/heartbeat-emission-for-snapshot-originated-processes/live-snapshot-originated-process-emits-a-heartbeat
//
// Two scenarios share this test: the queue-side contract that snapshot_heartbeat events flow through the
// standard enqueue path, and the reconciliation-side contract that live PIDs flagged IsSnapshot=true emit
// a heartbeat (carrying the host id) while live non-snapshot PIDs do not. The companion test
// TestRunOnce_NoHeartbeatForLiveNonSnapshotPID pins the negative half on its own.
func TestRunOnce_EmitsHeartbeatForLiveSnapshotPID(t *testing.T) {
	// Issue #173: snapshot rows have no recurring kernel events. Without an agent-side liveness ping the server's 6h TTL reconciler
	// force-exits them. RunOnce emits a snapshot_heartbeat for every alive PID flagged IsSnapshot=true.
	pt := proctable.New()
	pt.Update(1, proctable.ProcessInfo{Path: "/sbin/launchd", StartTime: 0, IsSnapshot: true})
	pt.Update(99, proctable.ProcessInfo{Path: "/bin/live", StartTime: 0, IsSnapshot: false})

	q := &recorderQueue{}
	// Both PIDs alive (kill returns nil).
	r := newRunner(t, pt, q, &killer{}, "host-A", Options{})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits, "no PIDs are dead")
	assert.Equal(t, 1, stats.Heartbeats, "only the snapshot PID gets a heartbeat")

	events := q.snapshot()
	require.Len(t, events, 1)

	var env struct {
		EventID   string         `json:"event_id"`
		HostID    string         `json:"host_id"`
		EventType string         `json:"event_type"`
		Payload   map[string]any `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(events[0], &env))
	assert.Equal(t, "snapshot_heartbeat", env.EventType)
	assert.Equal(t, "host-A", env.HostID)
	assert.EqualValues(t, 1, env.Payload["pid"])
}

// spec:agent-process-reconciliation/periodic-kill-zero-sweep/tracked-process-is-still-alive
// spec:agent-process-reconciliation/heartbeat-emission-for-snapshot-originated-processes/live-non-snapshot-process-does-not-emit-a-heartbeat
//
// Two scenarios share this test, and they describe the same observation from different angles:
//   - The kill-zero-sweep scenario asserts that a live PID produces no synthetic exit and that the entry
//     is preserved. stats.Exits==0 and the queue stays empty pin both clauses; the entry preservation is
//     implicit (the reconciler removes proctable entries only when it emits an exit).
//   - The heartbeat scenario asserts the negative case: a non-snapshot live PID emits NOTHING, not even a
//     heartbeat. The Heartbeats==0 assertion plus the empty queue pin that clause.
func TestRunOnce_NoHeartbeatForLiveNonSnapshotPID(t *testing.T) {
	// Regression guard for the issue #173 implementation: only snapshot PIDs heartbeat. A regular live PID must not produce a
	// heartbeat - the fork/exec/exit stream already keeps the server's row fresh.
	pt := proctable.New()
	pt.Update(50, proctable.ProcessInfo{Path: "/bin/regular", StartTime: 0, IsSnapshot: false})

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{}, "h", Options{})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Heartbeats)
	assert.Empty(t, q.snapshot())
}

// spec:agent-process-reconciliation/heartbeat-emission-for-snapshot-originated-processes/dead-snapshot-originated-process-emits-a-synthetic-exit-not-a-heartbeat
//
// A dead snapshot PID emits a host_reconciled exit AND no heartbeat. The snapshot flag does not change
// the kill-zero-sweep verdict — kernel says gone, so the PID gets reaped and a synthetic exit fires.
func TestRunOnce_DeadSnapshotPIDEmitsExitNotHeartbeat(t *testing.T) {
	// A snapshot PID that the kernel says is gone emits a host_reconciled exit, not a
	// heartbeat. Same path as the issue #6 dead-PID flow; snapshot flag doesn't change it.
	pt := proctable.New()
	pt.Update(33, proctable.ProcessInfo{Path: "/bin/dead-snap", StartTime: 0, IsSnapshot: true})

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{dead: map[int]bool{33: true}}, "h", Options{})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 1, stats.Exits, "dead snapshot PID emits an exit")
	assert.Equal(t, 0, stats.Heartbeats, "no heartbeat for a dead PID")

	events := q.snapshot()
	require.Len(t, events, 1)
	var env struct {
		EventType string         `json:"event_type"`
		Payload   map[string]any `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(events[0], &env))
	assert.Equal(t, "exit", env.EventType)
	assert.Equal(t, "host_reconciled", env.Payload["exit_reason"])
}

func TestNew_PanicsOnNilDependencies(t *testing.T) {
	pt := proctable.New()
	q := &recorderQueue{}
	hostFn := func() string { return "h" }

	cases := []struct {
		name   string
		pt     *proctable.Table
		q      Enqueuer
		hostFn HostIDProvider
	}{
		{"nil proctable", nil, q, hostFn},
		{"nil queue", pt, nil, hostFn},
		{"nil host id provider", pt, q, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Panics(t, func() {
				_ = New(tc.pt, tc.q, tc.hostFn, Options{})
			})
		})
	}
}

func TestNew_DefaultsForZeroOptions(t *testing.T) {
	pt := proctable.New()
	q := &recorderQueue{}
	r := New(pt, q, func() string { return "h" }, Options{})
	assert.Equal(t, 60*time.Second, r.interval, "Interval defaults to 60s")
	assert.Equal(t, 30*time.Second, r.minAge, "MinAge defaults to 30s")
	assert.Equal(t, 256, r.maxPerPass, "MaxPerPass defaults to 256")
	assert.NotNil(t, r.logger, "Logger defaults to slog.Default()")
	assert.NotNil(t, r.now, "Now defaults to time.Now")
	assert.NotNil(t, r.kill, "Kill defaults to syscall.Kill")
}

func TestNew_NegativeMinAgeNormalisesToDefault(t *testing.T) {
	r := New(proctable.New(), &recorderQueue{}, func() string { return "h" }, Options{MinAge: -1 * time.Second})
	assert.Equal(t, 30*time.Second, r.minAge, "negative MinAge falls back to default")
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	pt := proctable.New()
	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{}, "h", Options{Interval: 50 * time.Millisecond})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// Let at least one tick elapse, then cancel and confirm the loop exits.
	time.Sleep(75 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s of ctx cancellation")
	}
}

func TestRun_EmitsSyntheticExitDuringLoop(t *testing.T) {
	pt := proctable.New()
	pt.Update(99, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{99: true}}
	r := newRunner(t, pt, q, k, "h", Options{Interval: 25 * time.Millisecond})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	// Wait up to a second for the loop to fire and reap PID 99.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(q.snapshot()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.NotEmpty(t, q.snapshot(), "Run must emit at least one synthetic exit before the deadline")
}

// spec:agent-process-reconciliation/per-entry-failures-do-not-stall-the-pass/enqueue-fails-for-one-entry
//
// Pins the "failed entry remains in the table to be retried on a future pass" clause: when Enqueue
// returns "queue full" for the only dead PID in the table, the PID stays in the proctable so the next
// pass can try again. The "pass continues with remaining identifiers" clause requires a multi-PID setup
// where one fails and others succeed — that is covered by the companion test
// TestRunOnce_EnqueueErrorContinuesPass below.
func TestRunOnce_EnqueueErrorIsLoggedAndPIDStays(t *testing.T) {
	pt := proctable.New()
	pt.Update(42, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})

	q := &recorderQueue{failNext: errors.New("queue full")}
	r := newRunner(t, pt, q, &killer{dead: map[int]bool{42: true}}, "h", Options{})

	// RunOnce logs the per-PID enqueue error and continues so one bad enqueue
	// doesn't stall the whole pass — there's no error return to assert on.
	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits)
	_, ok := pt.Lookup(42)
	assert.True(t, ok, "PID must stay in the proctable when its synthetic exit failed to enqueue, so the next pass retries it")
}

func TestEmitSyntheticExit_NewIDError(t *testing.T) {
	pt := proctable.New()
	pt.Update(7, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{7: true}}
	r := newRunner(t, pt, q, k, "h", Options{})
	// Inject a UUID generator that always fails. Covers the emitSyntheticExit→r.newID error branch — in production this fires only when
	// crypto/rand stops working, which is a fundamental platform failure we still want to surface rather than swallow.
	r.newID = func() (string, error) { return "", errors.New("rand unavailable") }

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits, "newID failure must propagate as a per-PID error and not enqueue an event")
	assert.Empty(t, q.snapshot(), "no event should land in the queue when ID generation fails")
	_, ok := pt.Lookup(7)
	assert.True(t, ok, "PID stays in the proctable when emit fails so the next pass can retry")
}

func TestEmitSyntheticExit_MarshalError(t *testing.T) {
	pt := proctable.New()
	pt.Update(8, proctable.ProcessInfo{Path: "/bin/dead", StartTime: 0})

	q := &recorderQueue{}
	k := &killer{dead: map[int]bool{8: true}}
	r := newRunner(t, pt, q, k, "h", Options{})
	// Inject a marshaler that always fails. In production json.Marshal over a map[string]any of int+int+string can't fail, so the test is
	// the only way to exercise the error branch — and locks in the behaviour that a marshal failure does not crash the pass.
	r.marshal = func(_ any) ([]byte, error) { return nil, errors.New("marshal broken") }

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits, "marshal failure must propagate as a per-PID error and not enqueue garbage")
	assert.Empty(t, q.snapshot())
	_, ok := pt.Lookup(8)
	assert.True(t, ok)
}

// spec:agent-process-reconciliation/periodic-kill-zero-sweep/probe-is-blocked-by-permissions
//
// Covers the AND clause of the scenario that TestRunOnce_EPERMAndOtherErrorsTreatedAsAlive doesn't reach:
// when the probe is blocked by permission denied on a snapshot-originated PID, the pass MUST still emit
// a heartbeat for it. EPERM is positive proof the process exists; treating it as "live" means the same
// snapshot-heartbeat path as a fully signallable live snapshot PID. Without this clause, snapshot PIDs
// owned by another user would silently age out of the server's freshness window.
func TestRunOnce_EPERMOnSnapshotPIDEmitsHeartbeat(t *testing.T) {
	pt := proctable.New()
	pt.Update(77, proctable.ProcessInfo{Path: "/sbin/root-owned-snap", StartTime: 0, IsSnapshot: true})

	q := &recorderQueue{}
	r := newRunner(t, pt, q, nil, "host-A", Options{
		Kill: func(_ int, _ syscall.Signal) error { return syscall.EPERM },
	})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 0, stats.Exits, "EPERM must NOT trigger a synthetic exit")
	assert.Equal(t, 1, stats.Heartbeats, "EPERM on a snapshot PID must still emit a heartbeat")

	_, ok := pt.Lookup(77)
	assert.True(t, ok, "EPERM means the PID stays in the table")

	events := q.snapshot()
	require.Len(t, events, 1)
	var env struct {
		EventType string         `json:"event_type"`
		HostID    string         `json:"host_id"`
		Payload   map[string]any `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(events[0], &env))
	assert.Equal(t, "snapshot_heartbeat", env.EventType)
	assert.Equal(t, "host-A", env.HostID)
	assert.EqualValues(t, 77, env.Payload["pid"])
}

// spec:agent-process-reconciliation/per-pass-cap-on-synthetic-exits/exit-cap-reached-while-live-snapshot-processes-remain
//
// Pins the rule that the per-pass exit cap MUST NOT gate heartbeat emission. Setup: 3 dead snapshot PIDs
// + 2 live snapshot PIDs, cap=2. Expected: 2 exits (cap enforced), 2 heartbeats (cap does not apply to
// the heartbeat path). Without this guarantee, a host with thousands of stale snapshot rows could
// starve out heartbeats for the still-alive ones and lose the freshness window.
func TestRunOnce_ExitCapDoesNotGateHeartbeats(t *testing.T) {
	pt := proctable.New()
	dead := make(map[int]bool, 3)
	for _, pid := range []int32{10, 11, 12} {
		pt.Update(pid, proctable.ProcessInfo{Path: "/dead-snap", StartTime: 0, IsSnapshot: true})
		dead[int(pid)] = true
	}
	for _, pid := range []int32{20, 21} {
		pt.Update(pid, proctable.ProcessInfo{Path: "/live-snap", StartTime: 0, IsSnapshot: true})
	}

	q := &recorderQueue{}
	r := newRunner(t, pt, q, &killer{dead: dead}, "h", Options{MaxPerPass: 2})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 2, stats.Exits, "exit cap must hold at MaxPerPass=2 even though 3 PIDs are dead")
	assert.Equal(t, 2, stats.Heartbeats, "heartbeat path is NOT gated by the exit cap; both live snapshot PIDs must heartbeat")
}

// spec:agent-process-reconciliation/per-entry-failures-do-not-stall-the-pass/enqueue-fails-for-one-entry
//
// Pins the "pass continues with the remaining identifiers" clause: when the first synthetic-exit enqueue
// fails ("queue full" via recorderQueue.failNext), the pass MUST continue and successfully enqueue the
// remaining PIDs. recorderQueue.failNext clears itself after one trip so the second PID's enqueue
// succeeds. Pinning: stats.Exits == 1 (only the successful one is counted) AND the failed PID stays in
// the proctable for retry while the successful PID is reaped.
func TestRunOnce_EnqueueErrorContinuesPass(t *testing.T) {
	pt := proctable.New()
	pt.Update(101, proctable.ProcessInfo{Path: "/bin/dead-a", StartTime: 0})
	pt.Update(102, proctable.ProcessInfo{Path: "/bin/dead-b", StartTime: 0})

	q := &recorderQueue{failNext: errors.New("queue full")}
	r := newRunner(t, pt, q, &killer{dead: map[int]bool{101: true, 102: true}}, "h", Options{})

	stats := r.RunOnce(context.Background())
	assert.Equal(t, 1, stats.Exits, "one enqueue failed; the other PID's exit succeeded")

	// Exactly one PID got reaped from the table and exactly one event landed in the queue. The order is
	// non-deterministic (proctable iteration), so we assert the count rather than which PID was first.
	survivingInPT := 0
	for _, pid := range []int32{101, 102} {
		if _, ok := pt.Lookup(pid); ok {
			survivingInPT++
		}
	}
	assert.Equal(t, 1, survivingInPT, "failed-enqueue PID must stay for retry; successful one is reaped")
	require.Len(t, q.snapshot(), 1, "only the successful enqueue lands in the queue")
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

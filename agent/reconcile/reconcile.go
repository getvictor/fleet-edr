// Package reconcile implements the agent-side half of issue #6: a periodic
// kill(pid, 0) sweep over the in-memory proctable that synthesizes a missing
// "exit" event when the kernel exit notification was lost.
//
// Why this exists: ESF is best-effort. Under kernel back-pressure, sysext
// crashes, or agent restarts, exit events go missing and the server's
// processes table accumulates rows that look "running" forever. The server
// already has a TTL reconciler (default 6h) that force-greys those rows, but
// 6h is a long time to wait on a busy host. This client-side pass closes
// rows within ~minute granularity by asking the kernel directly via
// syscall.Kill(pid, 0): if the call returns ESRCH the PID is gone, and we
// emit a synthetic exit event tagged ExitReasonHostReconciled so the UI can
// distinguish it from an observed clean exit.
package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"github.com/fleetdm/edr/agent/proctable"
)

// Enqueuer is the narrow queue-surface needed by the reconciler. The agent's
// queue.Queue satisfies it; the test suite plugs in a recorder.
type Enqueuer interface {
	Enqueue(ctx context.Context, eventJSON []byte) error
}

// HostIDProvider returns the current enrolled host_id. Returning empty is
// allowed and skips the reconciliation pass for that tick (we'd rather miss
// a sweep than emit events with a placeholder host_id).
type HostIDProvider func() string

// KillFunc is the syscall hook. Defaults to syscall.Kill(pid, 0). Tests
// inject deterministic liveness maps.
type KillFunc func(pid int, sig syscall.Signal) error

// Options configures the reconciler. Zero values fall back to defaults.
type Options struct {
	// Interval between reconciliation passes. Zero or negative values
	// fall back to the default. Default 60s. Disabling the loop entirely
	// is a wiring decision — the agent main skips constructing the
	// runner when EDR_PROCESS_RECONCILE_INTERVAL=0; the package-level
	// API always runs.
	Interval time.Duration

	// MinAge filters out PIDs first seen less than this long ago. ESF and
	// the agent's queue can have a few hundred ms of latency between the
	// real exec and the proctable Update; without this guard a kill(pid,0)
	// against a brand-new PID could race the exec and falsely report "gone"
	// before the row exists server-side. Default 30s.
	MinAge time.Duration

	// MaxPerPass caps the number of synthetic exits emitted per tick so a
	// pathological ESF gap (10k missing exits) doesn't flood the queue in
	// one shot. The remainder is picked up on subsequent ticks. Default 256.
	MaxPerPass int

	// Logger for audit lines. Nil uses slog.Default().
	Logger *slog.Logger

	// Now is the clock source for synthetic-exit timestamps. Nil uses time.Now.
	Now func() time.Time

	// Kill is the liveness probe. Nil uses syscall.Kill.
	Kill KillFunc
}

// Reconciler runs periodic liveness sweeps over the proctable.
type Reconciler struct {
	pt         *proctable.Table
	q          Enqueuer
	hostID     HostIDProvider
	interval   time.Duration
	minAge     time.Duration
	maxPerPass int
	logger     *slog.Logger
	now        func() time.Time
	kill       KillFunc
	// newID and marshal are seams for tests so the rare error paths in
	// emitSyntheticExit are reachable. Default to crypto/rand-backed
	// newUUIDv4 and stdlib json.Marshal — both effectively never fail in
	// production on a healthy host. Tests inject failing versions to lock
	// in our error-handling shape (issue: synthetic exits must surface
	// queue-affecting failures rather than silently skip a PID).
	newID   func() (string, error)
	marshal func(any) ([]byte, error)
}

// New constructs a Reconciler. Panics on nil pt, q, or hostID.
func New(pt *proctable.Table, q Enqueuer, hostID HostIDProvider, opts Options) *Reconciler {
	if pt == nil {
		panic("reconcile.New: proctable must not be nil")
	}
	if q == nil {
		panic("reconcile.New: queue must not be nil")
	}
	if hostID == nil {
		panic("reconcile.New: hostID provider must not be nil")
	}
	if opts.Interval <= 0 {
		opts.Interval = 60 * time.Second
	}
	if opts.MinAge < 0 {
		opts.MinAge = 0
	}
	if opts.MinAge == 0 {
		opts.MinAge = 30 * time.Second
	}
	if opts.MaxPerPass <= 0 {
		opts.MaxPerPass = 256
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Kill == nil {
		opts.Kill = syscall.Kill
	}
	return &Reconciler{
		pt:         pt,
		q:          q,
		hostID:     hostID,
		interval:   opts.Interval,
		minAge:     opts.MinAge,
		maxPerPass: opts.MaxPerPass,
		logger:     opts.Logger,
		now:        opts.Now,
		kill:       opts.Kill,
		newID:      newUUIDv4,
		marshal:    json.Marshal,
	}
}

// Run loops until ctx is cancelled, emitting one log line per non-zero pass.
// Blocks; intended for a dedicated goroutine. Per-PID failures inside RunOnce
// are logged inline and never propagate up — one bad enqueue must not stall
// the whole pass — so RunOnce returns just the count and Run has nothing to
// branch on but `n > 0`.
func (r *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.logger.InfoContext(ctx, "process reconciliation started",
		"edr.reconcile.interval", r.interval,
		"edr.reconcile.min_age", r.minAge,
		"edr.reconcile.max_per_pass", r.maxPerPass,
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := r.RunOnce(ctx); n > 0 {
				r.logger.InfoContext(ctx, "process reconciliation pass",
					"edr.reconcile.synthetic_exits", n,
				)
			}
		}
	}
}

// RunOnce performs a single reconciliation pass and returns the count of
// synthetic exit events enqueued. Exposed for tests and one-shot usage.
// Per-PID failures (enqueue errors, marshal errors, UUID errors) are logged
// inline so one bad PID can't stall the whole pass — there's nothing the
// caller can do that the inline log path hasn't already done.
func (r *Reconciler) RunOnce(ctx context.Context) int {
	hostID := r.hostID()
	if hostID == "" {
		// No host_id yet — the enroll flow hasn't completed. Skip the pass
		// rather than emit events with an empty host_id (the server's ingest
		// handler would reject the whole batch on the first one).
		return 0
	}

	now := r.now()
	cutoff := now.Add(-r.minAge).UnixNano()
	emitted := 0

	for pid, info := range r.pt.Snapshot() {
		if pid <= 0 {
			// Skip PID 0 / negative — kill(0, 0) signals all processes in the
			// caller's process group, kill(-1, 0) signals every process the
			// caller may signal. Neither is what we want.
			continue
		}
		if info.StartTime > cutoff {
			continue
		}
		// kill(pid, 0) is the standard liveness probe. Three outcomes:
		//   nil   — pid exists and we may signal it; treat as alive.
		//   ESRCH — "no such process"; the missed-exit signal we react to.
		//   EPERM — pid exists but we lack permission; treat as alive. The
		//           agent runs as root in production so this is rare, but the
		//           conservative read keeps non-root dev runs from reaping
		//           entries they can't probe authoritatively.
		// Anything else (very rare; bad fd, weird kernel state) we skip too.
		if err := r.kill(int(pid), 0); !errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err := r.emitSyntheticExit(ctx, hostID, pid, now); err != nil {
			r.logger.WarnContext(ctx, "enqueue synthetic exit failed",
				"pid", pid, "err", err)
			continue
		}
		// Drop the entry from the proctable so subsequent passes skip it
		// and so network-event enrichment doesn't continue attributing to a
		// dead PID.
		r.pt.Remove(pid)
		emitted++
		if emitted >= r.maxPerPass {
			break
		}
	}
	return emitted
}

// eventEnvelope is the on-the-wire shape the ingest handler expects. We
// duplicate it locally rather than import server/store types because the
// agent must not depend on server packages.
type eventEnvelope struct {
	EventID     string         `json:"event_id"`
	HostID      string         `json:"host_id"`
	TimestampNs int64          `json:"timestamp_ns"`
	EventType   string         `json:"event_type"`
	Payload     map[string]any `json:"payload"`
}

func (r *Reconciler) emitSyntheticExit(ctx context.Context, hostID string, pid int32, now time.Time) error {
	id, err := r.newID()
	if err != nil {
		return fmt.Errorf("generate event id: %w", err)
	}
	env := eventEnvelope{
		EventID:     id,
		HostID:      hostID,
		TimestampNs: now.UnixNano(),
		EventType:   "exit",
		Payload: map[string]any{
			"pid":         int(pid),
			"exit_code":   -1,
			"exit_reason": "host_reconciled",
		},
	}
	body, err := r.marshal(env)
	if err != nil {
		return fmt.Errorf("marshal exit envelope: %w", err)
	}
	return r.q.Enqueue(ctx, body)
}

// newUUIDv4 returns an RFC-4122 v4 UUID without taking on a non-stdlib
// dependency. The agent already imports crypto/rand for elsewhere; this is
// a 12-line copy of what google/uuid.NewRandom does, scoped to one call site.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	out := make([]byte, 36)
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out), nil
}

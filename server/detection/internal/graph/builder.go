package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// pendingExitTTL caps how long an exit event hangs in the pending-exit buffer waiting for its companion snapshot exec (issue #176).
// 30s comfortably absorbs the worst observed post-restart agent reconnect + snapshot-batch upload window (~1-3s in dev QA), with a
// 10x safety margin. Beyond 30s we'd risk binding a stale exit to a freshly-recycled PID.
const pendingExitTTL = 30 * time.Second

// pendingExitKey identifies the (host, pid) tuple a buffered exit waits for. Snapshot exec ingest joins on this key.
type pendingExitKey struct {
	hostID string
	pid    int
}

// pendingExit captures everything needed to mark a snapshot row exited at insert time. Issue #176: when a NOTIFY_EXIT for a PID
// lands at the server before the snapshot exec for the same PID (small race after extension restart), the exit's UPDATE is a no-op
// (no row yet). We buffer the exit here for pendingExitTTL; the snapshot exec consumes it on arrival so we don't end up with a
// phantom alive row.
type pendingExit struct {
	exitTimeNs       int64
	exitIngestedAtNs int64
	exitCode         int
	exitReason       string
	expiresAt        time.Time
}

// Builder incrementally materializes fork/exec/exit events into the
// processes table.
type Builder struct {
	store  *mysql.Store
	logger *slog.Logger
	now    func() time.Time

	pendingExitsMu sync.Mutex
	pendingExits   map[pendingExitKey]pendingExit
}

// NewBuilder creates a graph builder backed by the given store.
func NewBuilder(s *mysql.Store, logger *slog.Logger) *Builder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Builder{
		store:        s,
		logger:       logger,
		now:          time.Now,
		pendingExits: make(map[pendingExitKey]pendingExit),
	}
}

// bufferPendingExit records an exit event whose UPDATE found no row, so a later snapshot exec for the same PID can carry the exit
// through to the synthesised row (issue #176). Overwrites any prior pending exit for the same (host, pid): the newest exit signal
// is authoritative since the previous one didn't bind either.
func (b *Builder) bufferPendingExit(hostID string, pid int, pe pendingExit) {
	pe.expiresAt = b.now().Add(pendingExitTTL)
	b.pendingExitsMu.Lock()
	b.pendingExits[pendingExitKey{hostID: hostID, pid: pid}] = pe
	b.pendingExitsMu.Unlock()
}

// consumePendingExit looks up a buffered exit for (hostID, pid). Returns the exit and removes it from the buffer when found and not
// expired. Returns ok=false when missing or expired. Expired entries are purged lazily here AND by sweepPendingExits at batch
// boundaries; both paths matter because not every snapshot exec arrives with the same lifecycle.
func (b *Builder) consumePendingExit(hostID string, pid int) (pendingExit, bool) {
	key := pendingExitKey{hostID: hostID, pid: pid}
	b.pendingExitsMu.Lock()
	defer b.pendingExitsMu.Unlock()
	pe, ok := b.pendingExits[key]
	if !ok {
		return pendingExit{}, false
	}
	delete(b.pendingExits, key)
	if pe.expiresAt.Before(b.now()) {
		return pendingExit{}, false
	}
	return pe, true
}

// sweepPendingExits drops expired entries. Called once per ProcessBatch to keep the map size bounded in steady state -
// pendingExitTTL is short and the map rarely has more than a handful of entries on a healthy host.
func (b *Builder) sweepPendingExits() {
	now := b.now()
	b.pendingExitsMu.Lock()
	defer b.pendingExitsMu.Unlock()
	for k, pe := range b.pendingExits {
		if pe.expiresAt.Before(now) {
			delete(b.pendingExits, k)
		}
	}
}

// ProcessBatch processes a batch of events, updating the processes table for fork, exec, and exit events. Other event types are
// ignored.
func (b *Builder) ProcessBatch(ctx context.Context, events []api.Event) error {
	// Sort by timestamp so fork always precedes exec/exit for the same PID.
	sorted := make([]api.Event, len(events))
	copy(sorted, events)
	slices.SortStableFunc(sorted, func(a, be api.Event) int {
		if a.TimestampNs < be.TimestampNs {
			return -1
		}
		if a.TimestampNs > be.TimestampNs {
			return 1
		}
		return 0
	})

	// Sweep expired pending exits once per batch (issue #176 buffer hygiene). Bounded-size
	// map, called per batch is plenty.
	b.sweepPendingExits()

	var failCount int
	for _, evt := range sorted {
		var err error
		switch evt.EventType {
		case "fork":
			err = b.handleFork(ctx, evt)
		case "exec":
			err = b.handleExec(ctx, evt)
		case "exit":
			err = b.handleExit(ctx, evt)
		case "snapshot_heartbeat":
			err = b.handleSnapshotHeartbeat(ctx, evt)
		}
		if err != nil {
			failCount++
			b.logger.WarnContext(ctx, "event processing failed", "event_id", evt.EventID, "type", evt.EventType, "err", err)
		}
	}
	if failCount > 0 {
		return fmt.Errorf("graph: %d event(s) failed to process", failCount)
	}
	return nil
}

type snapshotHeartbeatPayload struct {
	PID int `json:"pid"`
}

// handleSnapshotHeartbeat bumps last_seen_ns on the snapshot row for the heartbeat PID so the TTL reconciler's
// COALESCE(last_seen_ns, fork_time_ns) predicate sees a fresh timestamp and exempts the row from the issue #6 force-exit. No-ops
// for non-snapshot rows and for snapshot rows that have already exited; the store's WHERE clause guards both. Issue #173.
func (b *Builder) handleSnapshotHeartbeat(ctx context.Context, evt api.Event) error {
	var p snapshotHeartbeatPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}
	return b.store.UpdateLastSeenForSnapshot(ctx, evt.HostID, p.PID, evt.TimestampNs)
}

type forkPayload struct {
	ChildPID  int `json:"child_pid"`
	ParentPID int `json:"parent_pid"`
}

func (b *Builder) handleFork(ctx context.Context, evt api.Event) error {
	var p forkPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Handle PID reuse: close any existing non-exited record for this PID.
	if err := b.store.CloseStaleProcess(ctx, evt.HostID, p.ChildPID, evt.TimestampNs); err != nil {
		return err
	}

	// Inherit parent's path for the new process (fork-without-exec case).
	parentPath, err := b.store.GetParentPath(ctx, evt.HostID, p.ParentPID)
	if err != nil {
		b.logger.WarnContext(ctx, "failed to get parent path", "host_id", evt.HostID, "parent_pid", p.ParentPID, "err", err)
	}

	forkIngested := evt.IngestedAtNs
	_, err = b.store.InsertProcess(ctx, api.Process{
		HostID:           evt.HostID,
		PID:              p.ChildPID,
		PPID:             p.ParentPID,
		Path:             parentPath,
		ForkTimeNs:       evt.TimestampNs,
		ForkIngestedAtNs: &forkIngested,
	})
	return err
}

type execPayload struct {
	PID         int             `json:"pid"`
	PPID        int             `json:"ppid"`
	Path        string          `json:"path"`
	Args        api.NullRawJSON `json:"args"`
	UID         *int            `json:"uid"`
	GID         *int            `json:"gid"`
	CodeSigning api.NullRawJSON `json:"code_signing"`
	SHA256      *string         `json:"sha256"`
	// CDHash is the 40-hex code-directory hash; agent emits it only for Hardened-Runtime binaries (issue #68 / PR #185). Decoder
	// tolerates absence: non-HR rows + pre-cdhash agents simply leave the field nil and the persisted column stays NULL.
	CDHash *string `json:"cdhash"`
	// Snapshot is true for synthetic exec events emitted by the ESF startup baseline pass (issue #11). The graph builder uses this
	// to avoid clobbering a richer live-event row with a sparse synthetic one when the snapshot pass and an early-startup live exec
	// both arrive for the same PID.
	Snapshot bool `json:"snapshot"`
}

func (b *Builder) handleExec(ctx context.Context, evt api.Event) error {
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Resolve the running-at-this-moment row for the PID. Three shapes drive different recovery paths:
	//   (a) no row: exec-without-fork (synthesize a root row).
	//   (b) row, exec_time_ns NULL: first exec after fork; UPDATE in place.
	//   (c) row, exec_time_ns set: same-PID re-exec (issue #10). Close the prior generation and INSERT a new linked row.
	//       Without this branch, shell exec-optimization chains (python -> sh -> bash -> /tmp/payload) get collapsed
	//       into the final exec only.
	current, err := b.store.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return err
	}

	// Snapshot dedup: a snapshot exec for a PID that already has a fully-materialised live row would otherwise hit the re-exec branch
	// below and replace the live row (real args, code_signing, sha256) with a sparse snapshot row. The race window is small but real.
	// See issue #11 review: extension's snapshot pass fires ~ms after es_subscribe, and any process the live stream observed in
	// that window is in `processes` before the snapshot batch ingests. Drop the snapshot exec; the live data is the authoritative one.
	if p.Snapshot && current != nil && current.ExecTimeNs != nil {
		return nil
	}

	if current == nil {
		return b.insertExecWithoutFork(ctx, evt, p)
	}
	if current.ExecTimeNs == nil {
		return b.store.UpdateProcessExec(ctx, mysql.ProcessExecUpdate{
			HostID: evt.HostID, PID: p.PID, ExecTimeNs: evt.TimestampNs,
			Path: p.Path, Args: p.Args,
			UID: p.UID, GID: p.GID,
			CodeSigning: p.CodeSigning, SHA256: p.SHA256, CDHash: p.CDHash,
		})
	}
	return b.insertReExec(ctx, evt, p, current)
}

// insertExecWithoutFork synthesizes a root process row when an exec event arrives for a PID we've never seen fork for. fork_time_ns is
// set to the exec time as a best effort.
func (b *Builder) insertExecWithoutFork(ctx context.Context, evt api.Event, p execPayload) error {
	ppid := 0
	if p.PPID != 0 {
		ppid = p.PPID
	}
	forkIngested := evt.IngestedAtNs
	row := api.Process{
		HostID:           evt.HostID,
		PID:              p.PID,
		PPID:             ppid,
		Path:             p.Path,
		Args:             p.Args,
		UID:              p.UID,
		GID:              p.GID,
		CodeSigning:      p.CodeSigning,
		SHA256:           p.SHA256,
		CDHash:           p.CDHash,
		ForkTimeNs:       evt.TimestampNs,
		ForkIngestedAtNs: &forkIngested,
		ExecTimeNs:       &evt.TimestampNs,
		IsSnapshot:       p.Snapshot,
	}
	// Issue #173: snapshot rows seed last_seen_ns at insert time so the TTL reconciler's COALESCE(last_seen_ns, fork_time_ns)
	// predicate gives them a fresh baseline. Without this, the very first reconciliation pass after a snapshot insert would see
	// last_seen_ns=NULL -> fall back to fork_time_ns -> indistinguishable from a stale row.
	if p.Snapshot {
		seen := evt.TimestampNs
		row.LastSeenNs = &seen
	}
	// Issue #176: if a NOTIFY_EXIT for this PID arrived ahead of the snapshot exec, the
	// graph builder buffered it in pendingExits. Consume the buffer now so the synthesised
	// row is born exited rather than a phantom alive row that survives until TTL.
	//
	// Lifetime quirk: the buffered exit's timestamp is necessarily BEFORE the snapshot
	// exec event timestamp (the kernel observed the exit first; the snapshot enumeration
	// just happened to emit later). Inserting fork_time_ns = exec_time, exit_time_ns =
	// buffered exit_time would produce a row with fork > exit, which GetProcessByPID's
	// "alive at atTimeNs" predicate rejects entirely. Pull fork_time_ns back to the exit
	// time so the row is born already-exited with a zero-length lifetime: best we can
	// do given the snapshot exec carries no real fork time. last_seen_ns mirrors the same
	// timestamp so the row doesn't look "fresh" to the TTL reconciler.
	if p.Snapshot {
		if pe, ok := b.consumePendingExit(evt.HostID, p.PID); ok {
			row.ForkTimeNs = pe.exitTimeNs
			row.ExecTimeNs = &pe.exitTimeNs
			row.LastSeenNs = &pe.exitTimeNs
			row.ExitTimeNs = &pe.exitTimeNs
			row.ExitIngestedAtNs = &pe.exitIngestedAtNs
			reason := pe.exitReason
			row.ExitReason = &reason
			row.ExitCode = &pe.exitCode
		}
	}
	_, err := b.store.InsertProcess(ctx, row)
	return err
}

// insertReExec handles the issue #10 branch: a process called execve() again on the same PID without forking in between. The store's
// ReExec helper wraps the close + insert in a single transaction so we can never leave the PID appearing exited with no current
// generation (partial failure).
func (b *Builder) insertReExec(ctx context.Context, evt api.Event, p execPayload, prior *api.Process) error {
	_, reLinked, err := b.store.ReExec(ctx, prior.ID, evt.TimestampNs, evt.IngestedAtNs, api.Process{
		HostID: evt.HostID,
		PID:    p.PID,
		// Preserve the parent linkage from the original fork: a re-exec doesn't change PPID on macOS. Falls back to whatever
		// the exec event carries if the prior row somehow has ppid=0.
		PPID:             pickPPID(prior.PPID, p.PPID),
		Path:             p.Path,
		Args:             p.Args,
		UID:              p.UID,
		GID:              p.GID,
		CodeSigning:      p.CodeSigning,
		SHA256:           p.SHA256,
		CDHash:           p.CDHash,
		ForkTimeNs:       prior.ForkTimeNs, // chain preserves the original fork time
		ForkIngestedAtNs: prior.ForkIngestedAtNs,
		ExecTimeNs:       &evt.TimestampNs,
	})
	if err != nil {
		return fmt.Errorf("re-exec prior id=%d: %w", prior.ID, err)
	}
	if !reLinked {
		// Prior row was terminally closed (observed exit or pid reuse):
		// we anchored a fresh chain instead of chaining through.
		b.logger.WarnContext(ctx, "re-exec arrived after prior generation was terminally closed",
			"host_id", evt.HostID, "pid", p.PID, "prior_row_id", prior.ID)
	}
	return nil
}

// pickPPID prefers a non-zero prior PPID. macOS ES reports PPID on every NOTIFY_EXEC and it should be identical for re-execs on the
// same pid, but staying defensive: if prior has it and the event doesn't, use prior.
func pickPPID(prior, fromEvent int) int {
	if prior != 0 {
		return prior
	}
	return fromEvent
}

type exitPayload struct {
	PID        int    `json:"pid"`
	ExitCode   int    `json:"exit_code"`
	ExitReason string `json:"exit_reason,omitempty"`
}

func (b *Builder) handleExit(ctx context.Context, evt api.Event) error {
	var p exitPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Whitelist: only the agent-emitted reconciled reason is honoured on the wire. Anything else (server-only synthetic reasons: reexec,
	// pid_reuse, ttl_reconciliation) collapses to ExitReasonEvent so a compromised agent can't mark normal exits with a misleading reason.
	reason := api.ExitReasonEvent
	if p.ExitReason == api.ExitReasonHostReconciled {
		reason = api.ExitReasonHostReconciled
	}

	affected, err := b.store.UpdateProcessExit(ctx, evt.HostID, p.PID, evt.TimestampNs, evt.IngestedAtNs, p.ExitCode, reason)
	if err != nil {
		return err
	}
	if affected == 0 {
		// Issue #176: no row to update. This is the post-restart race window where the extension's snapshot enumerator saw the PID
		// but emitted its synthetic exec AFTER the live NOTIFY_EXIT for the same PID landed at the server. Buffer the exit so the
		// inbound snapshot exec can consume it and synthesise an already-exited row, rather than insert a phantom alive row that
		// survives until 6h TTL reconciliation. Reason is preserved so the synthesised row's exit_reason reflects host_reconciled
		// vs event correctly.
		b.bufferPendingExit(evt.HostID, p.PID, pendingExit{
			exitTimeNs:       evt.TimestampNs,
			exitIngestedAtNs: evt.IngestedAtNs,
			exitCode:         p.ExitCode,
			exitReason:       reason,
		})
	}
	return nil
}

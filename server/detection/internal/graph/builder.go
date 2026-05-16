package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/mysql"
)

// Builder incrementally materializes fork/exec/exit events into the
// processes table.
type Builder struct {
	store  *mysql.Store
	logger *slog.Logger
}

// NewBuilder creates a graph builder backed by the given store.
func NewBuilder(s *mysql.Store, logger *slog.Logger) *Builder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Builder{store: s, logger: logger}
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
	// Snapshot is true for synthetic exec events emitted by the ESF
	// startup baseline pass (issue #11). The graph builder uses this to
	// avoid clobbering a richer live-event row with a sparse synthetic
	// one when the snapshot pass and an early-startup live exec both
	// arrive for the same PID.
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

	// Snapshot dedup: a snapshot exec for a PID that already has a fully-materialised
	// live row would otherwise hit the re-exec branch below and replace the live
	// row (real args, code_signing, sha256) with a sparse snapshot row. The race
	// window is small but real — see issue #11 review: extension's snapshot pass
	// fires ~ms after es_subscribe, and any process the live stream observed in
	// that window is in `processes` before the snapshot batch ingests. Drop the
	// snapshot exec; the live data is the authoritative one.
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
			CodeSigning: p.CodeSigning, SHA256: p.SHA256,
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
	_, err := b.store.InsertProcess(ctx, api.Process{
		HostID:           evt.HostID,
		PID:              p.PID,
		PPID:             ppid,
		Path:             p.Path,
		Args:             p.Args,
		UID:              p.UID,
		GID:              p.GID,
		CodeSigning:      p.CodeSigning,
		SHA256:           p.SHA256,
		ForkTimeNs:       evt.TimestampNs,
		ForkIngestedAtNs: &forkIngested,
		ExecTimeNs:       &evt.TimestampNs,
	})
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

	return b.store.UpdateProcessExit(ctx, evt.HostID, p.PID, evt.TimestampNs, evt.IngestedAtNs, p.ExitCode, reason)
}

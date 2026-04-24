// Package graph builds and queries process trees from ingested EDR events.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/fleetdm/edr/server/store"
)

// Builder incrementally materializes fork/exec/exit events into the processes table.
type Builder struct {
	store  *store.Store
	logger *slog.Logger
}

// NewBuilder creates a graph builder backed by the given store.
func NewBuilder(s *store.Store, logger *slog.Logger) *Builder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Builder{store: s, logger: logger}
}

// ProcessBatch processes a batch of events, updating the processes table for
// fork, exec, and exit events. Other event types are ignored.
func (b *Builder) ProcessBatch(ctx context.Context, events []store.Event) error {
	// Sort by timestamp so fork always precedes exec/exit for the same PID.
	sorted := make([]store.Event, len(events))
	copy(sorted, events)
	slices.SortStableFunc(sorted, func(a, be store.Event) int {
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

func (b *Builder) handleFork(ctx context.Context, evt store.Event) error {
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
	_, err = b.store.InsertProcess(ctx, store.Process{
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
	PID         int               `json:"pid"`
	PPID        int               `json:"ppid"`
	Path        string            `json:"path"`
	Args        store.NullRawJSON `json:"args"`
	UID         *int              `json:"uid"`
	GID         *int              `json:"gid"`
	CodeSigning store.NullRawJSON `json:"code_signing"`
	SHA256      *string           `json:"sha256"`
}

func (b *Builder) handleExec(ctx context.Context, evt store.Event) error {
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Resolve the running-at-this-moment row for the PID. Three shapes:
	//   (a) no row            — exec-without-fork (synthesize a root row).
	//   (b) row, exec_time_ns NULL  — first exec after fork; UPDATE in place.
	//   (c) row, exec_time_ns set   — same-PID re-exec (issue #10): close the
	//       prior generation and INSERT a new linked row. Without this branch,
	//       shell exec-optimization chains (python→sh→bash→/tmp/payload) get
	//       collapsed into the final exec only.
	current, err := b.store.GetProcessByPID(ctx, evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return err
	}

	if current == nil {
		return b.insertExecWithoutFork(ctx, evt, p)
	}
	if current.ExecTimeNs == nil {
		return b.store.UpdateProcessExec(ctx, store.ProcessExecUpdate{
			HostID: evt.HostID, PID: p.PID, ExecTimeNs: evt.TimestampNs,
			Path: p.Path, Args: p.Args,
			UID: p.UID, GID: p.GID,
			CodeSigning: p.CodeSigning, SHA256: p.SHA256,
		})
	}
	return b.insertReExec(ctx, evt, p, current)
}

// insertExecWithoutFork synthesizes a root process row when an exec event
// arrives for a PID we've never seen fork for. fork_time_ns is set to the
// exec time as a best effort; downstream queries treat it as the earliest
// moment this process could have been alive.
func (b *Builder) insertExecWithoutFork(ctx context.Context, evt store.Event, p execPayload) error {
	ppid := 0
	if p.PPID != 0 {
		ppid = p.PPID
	}
	forkIngested := evt.IngestedAtNs
	_, err := b.store.InsertProcess(ctx, store.Process{
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

// insertReExec handles the issue #10 branch: a process called execve() again
// on the same PID without forking in between. Close the prior generation
// (marked exit_reason=reexec) and insert the new generation linked back via
// previous_exec_id.
func (b *Builder) insertReExec(ctx context.Context, evt store.Event, p execPayload, prior *store.Process) error {
	if err := b.store.CloseReExecGeneration(ctx, prior.ID, evt.TimestampNs, evt.IngestedAtNs); err != nil {
		return fmt.Errorf("close prior re-exec generation id=%d: %w", prior.ID, err)
	}
	priorID := prior.ID
	_, err := b.store.InsertProcess(ctx, store.Process{
		HostID: evt.HostID,
		PID:    p.PID,
		// Preserve the parent linkage from the original fork — a re-exec
		// doesn't change PPID on macOS. Falls back to whatever the exec
		// event carries if the prior row somehow has ppid=0.
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
		PreviousExecID:   &priorID,
	})
	return err
}

// pickPPID prefers a non-zero prior PPID. macOS ES reports PPID on every
// NOTIFY_EXEC and it should be identical for re-execs on the same pid, but
// staying defensive: if prior has it and the event doesn't, use prior.
func pickPPID(prior, fromEvent int) int {
	if prior != 0 {
		return prior
	}
	return fromEvent
}

type exitPayload struct {
	PID      int `json:"pid"`
	ExitCode int `json:"exit_code"`
}

func (b *Builder) handleExit(ctx context.Context, evt store.Event) error {
	var p exitPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	return b.store.UpdateProcessExit(ctx, evt.HostID, p.PID, evt.TimestampNs, evt.IngestedAtNs, p.ExitCode)
}

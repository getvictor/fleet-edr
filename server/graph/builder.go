// Package graph builds and queries process trees from ingested EDR events.
package graph

import (
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
	return &Builder{store: s, logger: logger}
}

// ProcessBatch processes a batch of events, updating the processes table for
// fork, exec, and exit events. Other event types are ignored.
func (b *Builder) ProcessBatch(events []store.Event) error {
	// Sort by timestamp so fork always precedes exec/exit for the same PID.
	sorted := make([]store.Event, len(events))
	copy(sorted, events)
	slices.SortStableFunc(sorted, func(a, b store.Event) int {
		if a.TimestampNs < b.TimestampNs {
			return -1
		}
		if a.TimestampNs > b.TimestampNs {
			return 1
		}
		return 0
	})

	var failCount int
	for _, evt := range sorted {
		var err error
		switch evt.EventType {
		case "fork":
			err = b.handleFork(evt)
		case "exec":
			err = b.handleExec(evt)
		case "exit":
			err = b.handleExit(evt)
		}
		if err != nil {
			failCount++
			b.logger.Warn("event processing failed", "event_id", evt.EventID, "type", evt.EventType, "err", err)
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

func (b *Builder) handleFork(evt store.Event) error {
	var p forkPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Handle PID reuse: close any existing non-exited record for this PID.
	if err := b.store.CloseStaleProcess(evt.HostID, p.ChildPID, evt.TimestampNs); err != nil {
		return err
	}

	// Inherit parent's path for the new process (fork-without-exec case).
	parentPath, _ := b.store.GetParentPath(evt.HostID, p.ParentPID)

	_, err := b.store.InsertProcess(store.Process{
		HostID:     evt.HostID,
		PID:        p.ChildPID,
		PPID:       p.ParentPID,
		Path:       parentPath,
		ForkTimeNs: evt.TimestampNs,
	})
	return err
}

type execPayload struct {
	PID         int             `json:"pid"`
	PPID        int             `json:"ppid"`
	Path        string          `json:"path"`
	Args        json.RawMessage `json:"args"`
	UID         *int            `json:"uid"`
	GID         *int            `json:"gid"`
	CodeSigning json.RawMessage `json:"code_signing"`
	SHA256      *string         `json:"sha256"`
}

func (b *Builder) handleExec(evt store.Event) error {
	var p execPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	// Try to update an existing process record (from a prior fork).
	err := b.store.UpdateProcessExec(evt.HostID, p.PID, evt.TimestampNs,
		p.Path, p.Args, p.UID, p.GID, p.CodeSigning, p.SHA256)
	if err != nil {
		return err
	}

	// Exec-without-fork: if no matching fork record exists, create a partial process record.
	// We detect this by checking if any row was updated. Since MySQL doesn't easily return
	// rows affected for "matched but unchanged" vs "no match", we do a lookup.
	proc, err := b.store.GetProcessByPID(evt.HostID, p.PID, evt.TimestampNs)
	if err != nil {
		return err
	}
	if proc == nil {
		ppid := 0
		if p.PPID != 0 {
			ppid = p.PPID
		}
		_, err = b.store.InsertProcess(store.Process{
			HostID:      evt.HostID,
			PID:         p.PID,
			PPID:        ppid,
			Path:        p.Path,
			Args:        p.Args,
			UID:         p.UID,
			GID:         p.GID,
			CodeSigning: p.CodeSigning,
			SHA256:      p.SHA256,
			ForkTimeNs:  evt.TimestampNs,
			ExecTimeNs:  &evt.TimestampNs,
		})
		return err
	}
	return nil
}

type exitPayload struct {
	PID      int `json:"pid"`
	ExitCode int `json:"exit_code"`
}

func (b *Builder) handleExit(evt store.Event) error {
	var p exitPayload
	if err := json.Unmarshal(evt.Payload, &p); err != nil {
		return err
	}

	return b.store.UpdateProcessExit(evt.HostID, p.PID, evt.TimestampNs, p.ExitCode)
}

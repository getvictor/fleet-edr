// Package rules contains concrete detection rule implementations.
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fleetdm/edr/server/detection"
	"github.com/fleetdm/edr/server/store"
)

// Known shell paths.
var shellPaths = map[string]bool{
	"/bin/sh":       true,
	"/bin/bash":     true,
	"/bin/zsh":      true,
	"/bin/dash":     true,
	"/usr/bin/sh":   true,
	"/usr/bin/bash": true,
	"/usr/bin/zsh":  true,
	"/usr/bin/dash": true,
}

// Suspicious path prefixes where legitimate binaries should not execute from.
var suspiciousPrefixes = []string{
	"/tmp/",
	"/var/tmp/",
	"/private/tmp/",
	"/dev/shm/",
}

// SuspiciousExec detects when a non-shell process spawns a shell and a direct
// child of the shell executes a binary from a suspicious location within 30 seconds.
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1204 (User Execution)
type SuspiciousExec struct{}

func (r *SuspiciousExec) ID() string {
	return "suspicious_exec"
}

// execPayload is the subset of exec event payload fields needed for detection.
type execPayload struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Path string `json:"path"`
}

func (r *SuspiciousExec) Evaluate(ctx context.Context, events []store.Event, s *store.Store) ([]detection.Finding, error) {
	// Collect exec events from the batch.
	var shellExecs []shellExecInfo
	for _, evt := range events {
		if evt.EventType != "exec" {
			continue
		}

		var p execPayload
		if err := json.Unmarshal(evt.Payload, &p); err != nil {
			continue
		}

		if !shellPaths[p.Path] {
			continue
		}

		shellExecs = append(shellExecs, shellExecInfo{
			event:   evt,
			payload: p,
		})
	}

	var findings []detection.Finding
	for _, shell := range shellExecs {
		finding, err := r.evaluateShellExec(ctx, shell, s)
		if err != nil {
			return nil, fmt.Errorf("evaluate shell exec pid %d: %w", shell.payload.PID, err)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

type shellExecInfo struct {
	event   store.Event
	payload execPayload
}

func (r *SuspiciousExec) evaluateShellExec(ctx context.Context, shell shellExecInfo, s *store.Store) (*detection.Finding, error) {
	// Look up the parent process to check if it's also a shell (shell → shell is normal).
	parent, err := s.GetProcessByPID(ctx, shell.event.HostID, shell.payload.PPID, shell.event.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get parent: %w", err)
	}
	if parent == nil {
		return nil, nil // parent not yet materialized — skip to avoid false positives
	}
	if shellPaths[parent.Path] {
		return nil, nil // shell → shell is normal
	}

	// Look up the shell process itself in the processes table.
	shellProc, err := s.GetProcessByPID(ctx, shell.event.HostID, shell.payload.PID, shell.event.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get shell process: %w", err)
	}
	if shellProc == nil {
		return nil, nil // process not yet materialized
	}

	// Query child processes of the shell within a 30-second window.
	windowNs := int64(30_000_000_000) // 30 seconds in nanoseconds
	tr := store.TimeRange{
		FromNs: shell.event.TimestampNs,
		ToNs:   shell.event.TimestampNs + windowNs,
	}

	children, err := s.GetChildProcesses(ctx, shell.event.HostID, shell.payload.PID, tr)
	if err != nil {
		return nil, fmt.Errorf("get children: %w", err)
	}

	// Check if any child was forked from a suspicious path.
	// We use fork_time_ns as the time window boundary since exec_time_ns may not be set yet.
	for _, child := range children {
		if !isSuspiciousPath(child.Path) {
			continue
		}

		return &detection.Finding{
			HostID:      shell.event.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "Suspicious exec from temp path",
			Description: fmt.Sprintf("%s → %s → %s", parent.Path, shell.payload.Path, child.Path),
			ProcessID:   child.ID,
			EventIDs:    []string{shell.event.EventID},
		}, nil
	}

	return nil, nil
}

func isSuspiciousPath(path string) bool {
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Path traversal.
	if strings.Contains(path, "..") {
		return true
	}
	return false
}

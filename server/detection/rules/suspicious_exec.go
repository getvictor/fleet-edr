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

// Techniques: T1059 (Command and Scripting Interpreter), T1105 (Ingress
// Tool Transfer). The rule fires on "shell with outbound network" plus
// "shell spawns binary in /tmp" — both high-confidence dropper shapes.
func (r *SuspiciousExec) Techniques() []string {
	return []string{"T1059", "T1105"}
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

	// Shell-exec-optimization case: sh -c "<single command>" often re-execs directly
	// into the target binary without forking. The pid survives, but GetProcessByPID
	// returns the *latest* exec for that pid, which is no longer /bin/sh. If the
	// pid's current path is a suspicious location, the shell was used as a launcher
	// for a temp-path binary and we fire here.
	if shellProc.Path != shell.payload.Path && isSuspiciousPath(shellProc.Path) {
		return &detection.Finding{
			HostID:      shell.event.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "Suspicious exec from temp path",
			Description: fmt.Sprintf("%s → %s → %s", parent.Path, shell.payload.Path, shellProc.Path),
			ProcessID:   shellProc.ID,
			EventIDs:    []string{shell.event.EventID},
		}, nil
	}

	// Parent/child causality is an on-host property, so the child lookup runs
	// on kernel time. Network events are cross-source (ES + NE) and so run on
	// server-stamped ingest time (issue #7). We build two windows of the same
	// 30-second width but anchored to different clocks.
	const windowNs = int64(30_000_000_000)
	kernelTR := store.TimeRange{
		FromNs: shell.event.TimestampNs,
		ToNs:   shell.event.TimestampNs + windowNs,
	}
	ingestTR := store.TimeRange{
		FromNs: shell.event.IngestedAtNs,
		ToNs:   shell.event.IngestedAtNs + windowNs,
	}

	children, err := s.GetChildProcesses(ctx, shell.event.HostID, shell.payload.PID, kernelTR)
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

	// Check for outbound network connections from the shell or its children.
	// This catches reverse shells, download-and-execute chains, and curl|sh patterns.
	finding, err := r.checkNetworkActivity(ctx, shell, parent, shellProc, children, ingestTR, s)
	if err != nil {
		return nil, fmt.Errorf("check network activity: %w", err)
	}
	return finding, nil
}

// networkConnectPayload is the subset of network_connect event fields needed for detection.
type networkConnectPayload struct {
	Direction     string `json:"direction"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
}

// checkNetworkActivity looks for outbound network connections from the shell or its children
// within the detection time window. Returns a finding if outbound activity is found.
func (r *SuspiciousExec) checkNetworkActivity(
	ctx context.Context,
	shell shellExecInfo,
	parent *store.Process,
	shellProc *store.Process,
	children []store.Process,
	tr store.TimeRange,
	s *store.Store,
) (*detection.Finding, error) {
	// Collect PIDs to check: the shell itself plus all children. Map each PID to its
	// process row ID so the finding can link to the actual network-originating process.
	pidsToCheck := []int{shell.payload.PID}
	pidToProcessID := map[int]int64{shell.payload.PID: shellProc.ID}
	for _, child := range children {
		pidsToCheck = append(pidsToCheck, child.PID)
		pidToProcessID[child.PID] = child.ID
	}

	for _, pid := range pidsToCheck {
		f, err := r.findOutboundForPID(ctx, s, shell, parent, pidToProcessID[pid], pid, tr)
		if err != nil {
			return nil, err
		}
		if f != nil {
			return f, nil
		}
	}
	return nil, nil
}

// findOutboundForPID scans a single PID's network events for the first outbound
// connection and returns a finding when found. Factored out of checkNetworkActivity to
// flatten the nested for/for/continue structure.
func (r *SuspiciousExec) findOutboundForPID(
	ctx context.Context, s *store.Store,
	shell shellExecInfo, parent *store.Process,
	processID int64, pid int, tr store.TimeRange,
) (*detection.Finding, error) {
	netEvents, err := s.GetNetworkEventsForProcess(ctx, shell.event.HostID, pid, tr)
	if err != nil {
		return nil, fmt.Errorf("get network events for pid %d: %w", pid, err)
	}
	for _, evt := range netEvents {
		if evt.EventType != "network_connect" {
			continue
		}
		var conn networkConnectPayload
		if err := json.Unmarshal(evt.Payload, &conn); err != nil {
			continue
		}
		if conn.Direction != "outbound" {
			continue
		}
		parentPath := "(unknown)"
		if parent != nil {
			parentPath = parent.Path
		}
		return &detection.Finding{
			HostID:      shell.event.HostID,
			RuleID:      r.ID(),
			Severity:    detection.SeverityHigh,
			Title:       "Shell spawn with outbound network connection",
			Description: fmt.Sprintf("%s → %s → outbound %s:%d", parentPath, shell.payload.Path, conn.RemoteAddress, conn.RemotePort),
			ProcessID:   processID,
			EventIDs:    []string{shell.event.EventID, evt.EventID},
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

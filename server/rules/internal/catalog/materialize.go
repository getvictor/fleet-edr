package catalog

import (
	"context"
	"fmt"
	"time"

	"github.com/fleetdm/edr/server/rules/api"
)

// processMaterializationGrace bounds how long an event may keep failing evaluation while waiting for its subject process row to be
// written by the graph builder. Within the grace window a missing row is treated as an ordering race between concurrently processed
// claim batches (issue #535 intra-replica workers, ADR-0011 cross-replica claimers): the rule raises
// api.ErrProcessNotYetMaterialized so the processor nacks and re-evaluates the batch once the concurrent flush commits, which in
// practice is the very next poll tick. Past the window the row is assumed to never arrive (a pre-capture pid, or an agent that never
// sent the fork/exec) and evaluation degrades to the historical silent skip, so a permanently orphaned event cannot retry forever.
// 30s is orders of magnitude above a batch flush (milliseconds) while still small enough that a backlogged processor (events older
// than the grace at first evaluation) simply keeps the pre-#535 behaviour rather than amplifying the backlog with retries.
const processMaterializationGrace = 30 * time.Second

// resolveSubjectProcess looks up the process an event is ABOUT (the pid carried in the event's own payload, whose fork/exec is
// ordered before it in the same host stream) and distinguishes "not yet materialized" from "never will be". A found row and a store
// error pass through unchanged. A miss returns api.ErrProcessNotYetMaterialized while the event is inside the materialization grace
// window, and (nil, nil) once it is past it.
//
// This is deliberately NOT used for ancestor or parent-chain lookups (shell_from_office's Office parent, suspicious_exec's and
// osascript_network_exec's chain walks): a parent can legitimately predate the capture and never materialize, so retrying those
// would stall batches for the full grace window with no alert at the end of it. It is also NOT used for dns_c2_beacon's flow
// resolution: that rule must resolve the process BEFORE its suspicion gate (the gate reads proc.Path), so a retryable miss there
// would fire for every outbound connect whose exec the agent dropped (event channel full), turning sustained load into batch-retry
// storms. Every caller here resolves only after a payload-level pre-filter (a sudoers write, a security-binary exec, a temp-path
// exec, ...), so the sentinel can only be raised by events that are already rare.
func resolveSubjectProcess(ctx context.Context, s api.GraphReader, evt api.Event, pid int) (*api.Process, error) {
	proc, err := s.GetProcessByPID(ctx, evt.HostID, pid, evt.TimestampNs)
	if err != nil {
		return nil, fmt.Errorf("get process pid %d: %w", pid, err)
	}
	if proc == nil && withinMaterializationGrace(evt.IngestedAtNs, time.Now().UnixNano()) {
		return nil, fmt.Errorf("event %s (type %s) references pid %d: %w", evt.EventID, evt.EventType, pid, api.ErrProcessNotYetMaterialized)
	}
	return proc, nil
}

// withinMaterializationGrace reports whether an event ingested at ingestedAtNs is still young enough (relative to nowNs) for a
// missing subject process to be treated as retryable. A zero ingest stamp (fixture replay, unit tests, or a path that never stamped
// it) is never in grace, preserving the historical skip semantics for those inputs.
func withinMaterializationGrace(ingestedAtNs, nowNs int64) bool {
	return ingestedAtNs > 0 && nowNs-ingestedAtNs < int64(processMaterializationGrace)
}

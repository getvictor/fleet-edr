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

// flowProcessMaterializationGrace is the tighter retry bound dns_c2_beacon uses for its flow-to-process resolution. That lookup runs
// BEFORE the rule's suspicion gate (the gate reads proc.Path), so unlike the subject-process callers it can be reached by ANY young
// outbound connect, not just a rare pre-filtered event. A tight window still covers the cross-batch / cross-replica materialization
// race (the process row commits within a batch flush, so a real race clears on the very next tick) while capping how long a genuinely
// orphaned connect (its exec dropped by a full agent channel) can hold its batch in the nack/re-claim loop before evaluation degrades
// to the historical silent skip. See resolveFlowProcess in dns_c2_beacon.go.
const flowProcessMaterializationGrace = 5 * time.Second

// resolveSubjectProcess looks up the process an event is ABOUT (the pid carried in the event's own payload, whose fork/exec is
// ordered before it in the same host stream) and distinguishes "not yet materialized" from "never will be". A found row and a store
// error pass through unchanged. A miss returns api.ErrProcessNotYetMaterialized while the event is inside the materialization grace
// window, and (nil, nil) once it is past it.
//
// This is deliberately NOT used for ancestor or parent-chain lookups (shell_from_office's Office parent, suspicious_exec's and
// osascript_network_exec's chain walks): a parent can legitimately predate the capture and never materialize, so retrying those
// would stall batches for the full grace window with no alert at the end of it. Every caller here resolves only after a payload-level
// pre-filter (a sudoers write, a security-binary exec, a temp-path exec, ...), so the sentinel can only be raised by events that are
// already rare. dns_c2_beacon's flow-to-process resolution runs BEFORE its suspicion gate and so is NOT pre-filtered; it opts into the
// same retryable-miss contract but under the tighter flowProcessMaterializationGrace (see resolveFlowProcess in dns_c2_beacon.go),
// precisely to bound the batch-retry cost the unfiltered position would otherwise create under sustained load.
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
// missing subject process to be treated as retryable, using the subject-process grace.
func withinMaterializationGrace(ingestedAtNs, nowNs int64) bool {
	return withinGrace(ingestedAtNs, nowNs, processMaterializationGrace)
}

// withinGrace is the shared age-window check for a retryable materialization miss: an event with a positive ingest stamp whose age
// (nowNs minus ingestedAtNs) falls strictly inside the grace bound in either direction is retryable. A zero (or negative) ingest
// stamp (fixture replay, unit tests, or a path that never stamped it) is never in grace, preserving the historical silent-skip
// semantics for those inputs.
//
// The window is symmetric: a NEGATIVE age (the ingest stamp is ahead of this replica's clock) is in grace only up to the same bound.
// Small negative ages are legitimate and must stay in grace: the ingest stamp comes from whichever replica accepted the event, and
// cross-replica skew of milliseconds-to-seconds lands exactly in the window where the race retry matters. But an unbounded negative
// branch would let a badly future-dated stamp (a replica with a broken clock) keep the batch retrying until the local clock catches
// up, so the cap bounds the worst case at roughly twice the grace instead of indefinitely.
func withinGrace(ingestedAtNs, nowNs int64, grace time.Duration) bool {
	if ingestedAtNs <= 0 {
		return false
	}
	age := nowNs - ingestedAtNs
	return age > -int64(grace) && age < int64(grace)
}

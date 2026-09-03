package engine

import (
	"context"
	"fmt"

	"github.com/fleetdm/edr/server/detection/api"
	rulesapi "github.com/fleetdm/edr/server/rules/api"
)

// retryableGraphReader is the GraphReader the engine hands to rules. It forwards every read and marks any FAILURE retryable, so a
// read that could not be answered fails the batch instead of being isolated like a broken rule (issue #798).
//
// The classification lives here rather than in the rules because a contract that depends on each rule remembering to mark its own
// read failures is one that the next rule added silently breaks, and the loss is invisible: the engine swallows a non-retryable
// rule error, the processor acks, and those events are never evaluated again. Wrapping once at the boundary means there is nothing
// to remember. A rule that wraps the error with its own fmt.Errorf still matches errors.Is, so the sentinel survives the rules'
// existing error handling untouched.
//
// It is NOT wrapped inside the store: the same store serves the process-graph builder and the process-detail reads, and neither
// should inherit a rules-context retry sentinel from a read they perform for their own reasons.
//
// Only errors are wrapped. A read that legitimately matches no row returns a nil row and a nil error, which is an ANSWER the rules
// already handle, and that path is untouched here.
type retryableGraphReader struct {
	// A named field rather than an embedded interface, deliberately, and the opposite of the right choice for a test fake.
	// Embedding would make this type keep compiling when GraphReader grows a method, and pass that method through UNWRAPPED, which
	// is precisely the silent drift this change exists to remove. Held explicitly, with the assertion below, a new method fails the
	// build until it is handled here.
	inner api.GraphReader
}

// Fails the build if GraphReader grows a method this decorator does not wrap. That is the point of the named field above.
var _ api.GraphReader = (*retryableGraphReader)(nil)

// retryable marks a read failure as one the batch should be retried for. Returns nil unchanged so callers can wrap unconditionally.
//
// ErrGraphUnavailable rather than the bare ErrRetryBatch, and the distinction is not cosmetic: the generic sentinel is ABSORBED by
// the per-event rule loops so the batch continues, which is right for an event that cannot be decided yet and wrong for a failed
// read, where every remaining read will fail identically. It is also logged at DEBUG, which is right for a rule that deliberately
// waits and wrong for a dependency outage. See the sentinel's own comment for all three divergences.
//
// The retry is not bounded here and does not need to be: a read that fails permanently rather than transiently is caught by the
// work queue's own bound, which sets the batch aside once it has exceeded both an attempt count and a duration (issue #836). That
// bound is what makes this classification safe, since without it a permanently failing read would hold its host's queue forever.
func retryable(err error, read string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("graph read %s: %w: %w", read, err, rulesapi.ErrGraphUnavailable)
}

func (r *retryableGraphReader) GetProcessByPID(ctx context.Context, hostID string, pid int, atTimeNs int64) (*api.Process, error) {
	proc, err := r.inner.GetProcessByPID(ctx, hostID, pid, atTimeNs)
	return proc, retryable(err, "GetProcessByPID")
}

func (r *retryableGraphReader) GetProcessByPIDVersion(
	ctx context.Context, hostID string, pid int, pidversion uint32, atNs int64,
) (*api.Process, error) {
	proc, err := r.inner.GetProcessByPIDVersion(ctx, hostID, pid, pidversion, atNs)
	return proc, retryable(err, "GetProcessByPIDVersion")
}

func (r *retryableGraphReader) GetChildProcesses(
	ctx context.Context, hostID string, ppid int, tr api.TimeRange,
) ([]api.Process, error) {
	procs, err := r.inner.GetChildProcesses(ctx, hostID, ppid, tr)
	return procs, retryable(err, "GetChildProcesses")
}

func (r *retryableGraphReader) GetExecChain(ctx context.Context, current api.Process) ([]api.Process, error) {
	chain, err := r.inner.GetExecChain(ctx, current)
	return chain, retryable(err, "GetExecChain")
}

func (r *retryableGraphReader) GetNetworkEventsForProcess(
	ctx context.Context, hostID string, pid int, tr api.TimeRange,
) ([]api.Event, error) {
	events, err := r.inner.GetNetworkEventsForProcess(ctx, hostID, pid, tr)
	return events, retryable(err, "GetNetworkEventsForProcess")
}

func (r *retryableGraphReader) GetHostEventsByType(
	ctx context.Context, hostID, eventType string, tr api.TimeRange,
) ([]api.Event, error) {
	events, err := r.inner.GetHostEventsByType(ctx, hostID, eventType, tr)
	return events, retryable(err, "GetHostEventsByType")
}

package api

import "context"

// EventLog is the durable work queue that decouples ingestion from detection processing. Ingestion appends every accepted event;
// the detection pipeline claims batches, processes them, and acknowledges them. It is the seam that lets ingestion and processing
// scale and fail independently (ADR-0015), while preserving the multi-replica claim semantics of ADR-0011.
//
// Invariants every implementation MUST uphold:
//   - At-least-once: an appended event is delivered to a claimer at least once; a crash between a claim and Ack re-delivers on a later
//     claim. Consumers are therefore idempotent.
//   - Idempotent append: appending an event whose EventID was already appended is a no-op, so an agent retry never double-enqueues.
//   - Per-host causal order: a claim returns ONE host's events ordered by timestamp, so a host's events process in causal order.
//   - Lock-free fan-out: concurrent claimers on separate replicas receive disjoint batches without coordinating.
//
// The queue scopes every claim to a single host (issue #717). It does NOT make a host exclusive to one claimer: two claimers asking
// for the same host still receive disjoint batches, which is enough for the at-least-once contract but NOT enough for a consumer whose
// state machine needs a host's events in causal order. The graph builder is such a consumer, so the detection processor serializes
// itself per host with an advisory lock before claiming. Scoping the claim is what makes that serialization possible: a claim that
// spanned hosts would put one lock's worth of work under several hosts' locks.
//
// The v0.4.0 implementation is an ephemeral MySQL queue; a later swap to a streaming log (Redpanda) changes no caller.
type EventLog interface {
	// Append enqueues events as not-yet-processed. Idempotent by EventID.
	Append(ctx context.Context, events []Event) error

	// PendingHosts returns up to limit host ids that currently have at least one claimable event (never claimed, or claimed by a
	// worker whose claim has since expired), ordered by each host's oldest claimable event so the longest-waiting host comes first.
	// It is a read: it claims nothing and takes no locks, so two callers can see the same host. Callers use it to pick which host to
	// serialize on, and MUST treat the result as a hint that may be stale by the time they act on it.
	PendingHosts(ctx context.Context, limit int) ([]string, error)

	// ClaimForHost atomically claims up to limit claimable events for hostID, ordered by timestamp, without blocking concurrent
	// claimers. The claimed events are hidden from other claimers until Ack or Nack. Returns an empty slice when that host has
	// nothing claimable, which is normal: PendingHosts is a hint and another claimer may have taken the host's backlog first.
	//
	// A claim SHALL NOT reach past an event that is still in flight: if another claimer holds an unexpired claim on one of this
	// host's events, only events strictly older than the oldest such event are offered, and an empty slice is returned when none
	// are. Without that bound an in-flight event is a hole in the stream rather than a stop sign, because in-flight events do not
	// match the claimable predicate: a claimer that died between claiming a fork and flushing it would let the next claimer take
	// the following exec and fold it as an exec with no fork. Callers therefore get at-most-one-gap-free prefix per host and may
	// see nothing for a host until an abandoned claim's lease expires, which is bounded and preferable to out-of-order folding.
	// Returns the claim's stamp alongside the events, which Ack requires to prove it still holds the claim (issue #817). The
	// stamp is meaningless when no events were claimed.
	ClaimForHost(ctx context.Context, hostID string, limit int) ([]Event, int64, error)

	// Ack marks the claimed events (identified by EventID) fully processed: they are excluded from future claims but stay in the queue
	// until PruneProcessed removes them, so Ack is a cheap index update off the delete path. Acknowledgment needs only identity, so it
	// takes IDs rather than whole events: the caller need not retain the (potentially large) payloads until ack.
	//
	// Takes the stamp ClaimForHost returned and reports whether this claim still held the rows (issue #817). A claim expires and is
	// re-offered, so an evaluation that outlives its lease runs alongside its own reclaimer; an unconditional ack let both attempts
	// succeed and neither learn it had lost, so anything additive done after acknowledging counted the batch twice. A caller told
	// held=false MUST skip whatever it does after the ack, because the attempt that owns the rows now will do it.
	//
	// The caller MUST serialize this against that host's claimers, and this interface does not do it (issue #863). The statement
	// takes row locks as it scans, so an earlier event of a batch can be locked while a later one is not; a claim arriving in that
	// window skips the locked row through FOR UPDATE SKIP LOCKED and takes the later one, which is then folded without its
	// predecessor. The in-flight bound does not cover it, because it counts only claims that are still live and the window is
	// reached precisely when the claim has outlived its lease. Nack carries the same requirement, for the same reason.
	Ack(ctx context.Context, eventIDs []string, claimStampNs int64) (held bool, err error)

	// Nack returns the claimed events (identified by EventID) to the not-yet-processed state for a later ClaimForHost, counting the
	// attempt, and reports how many it SET ASIDE instead of returning.
	//
	// claimStampNs is the stamp ClaimForHost issued, and an implementation SHALL act only on events this claim still holds, as Ack
	// does. Identifying a claim by an event's STATE instead lets a caller whose processing outran its lease reset and count an
	// attempt against a claim a replacement now owns, which pushes that batch toward its retry bounds on failures it did not have,
	// and leaves the replacement's own acknowledgement to be refused so its work is redone (issue #840).
	//
	// A caller SHALL be told whether it still held the claim, as Ack tells it. Without that, "withdrew nothing" is the same
	// answer for a superseded attempt and for a held batch that simply had no event reach its bounds, so an attempt whose
	// processing outran its lease would leave no trace: the ack path reports that at WARN and is the only signal anyone gets
	// that leases are being exceeded, and this path would have been the one way to lose a claim silently.
	//
	// The count is the point of the return value. A batch that fails the same way every time is otherwise retried forever, and
	// because the claim takes a host's oldest work first, nothing newer for that host is ever claimed: the host stops
	// contributing to the process graph and raising detections at all (issue #836). An implementation SHALL bound the retries and
	// withdraw the events once that bound is passed, and the caller reports the count so a stalled host is visible.
	//
	// The count SHALL be exact rather than merely non-zero. A caller decides whether a WHOLE batch was withdrawn by comparing it
	// against the events it handed over, so an under-count reads as a partial withdrawal.
	//
	// Serialized against that host's claimers by the caller, exactly as Ack is and for the same reason: this statement takes row
	// locks the same way, so an unserialized requeue opens the same window (issue #863).
	//
	// tally is opaque to this interface: a caller that has resolved something about the batch worth surviving its own failure
	// hands the bytes over, and an implementation SHALL keep them with the returned events and give them back to whoever WITHDRAWS
	// the batch (NackResult.CarriedTally). That is the only way the value can survive, because the attempt that resolved it is by
	// definition the one that failed, and the attempt that withdraws the batch may be a later one that never got far enough to
	// resolve anything (issue #893). An implementation SHALL NOT let a nack with no tally discard one an earlier attempt supplied,
	// for exactly that reason. Nothing here interprets the bytes; see MonitorTally in the rules API for what the detection
	// pipeline puts in them.
	//
	// A caller MUST keep the tally within MaxNackTallyBytes, and MUST hand over none rather than an oversized one. Returning the
	// batch is the important half of this call and the tally is the incidental half, so a value too large to store has to cost the
	// value rather than the nack.
	Nack(ctx context.Context, eventIDs []string, claimStampNs int64, tally []byte) (result NackResult, err error)

	// CountPending counts events that have not been fully processed. Backs the processor-backlog gauge.
	CountPending(ctx context.Context) (int64, error)

	// PruneProcessed removes fully-processed (acked) events from the queue in batches of at most batchSize (a non-positive batchSize
	// uses the implementation's default), returning the total removed. The count is meaningful even when err != nil: a sweep that fails
	// mid-run still removed the returned rows. It is the sweep that keeps the queue to its in-flight working set (the archive holds the
	// durable history); a high-volume deployment runs it on a cadence off the hot path rather than deleting on each Ack. Removing only
	// acked events never affects a not-yet-processed or in-flight claim.
	PruneProcessed(ctx context.Context, batchSize int) (int64, error)

	// PruneSetAside removes set-aside events older than retentionDays, in batches of at most batchSize. A non-positive
	// retentionDays prunes nothing, which keeps them indefinitely and matches what a disabled retention window means elsewhere.
	//
	// Set-aside rows are the only record of which events a host stopped processing, so they are retained for the deployment's
	// window rather than deleted when they are created; that window doubles as the time an operator has to look at them
	// (issue #836).
	PruneSetAside(ctx context.Context, retentionDays, batchSize int) (int64, error)
}

// MaxNackTallyBytes bounds what Nack will carry for a batch.
//
// The storage this rides in is finite, and a write that exceeds it is REFUSED rather than truncated, which would fail the nack and
// leave the batch in flight until its claim lease expired. That is a real input rather than a hypothetical one: a tally carries an
// entry per matching rule, and an imported rule pack is operator-sized and defaults to monitor mode.
//
// 32KiB against a 64KiB column, so a caller that respects the bound cannot reach the ceiling by a margin it has to compute
// exactly. On the pipeline's own encoding this is several hundred rules' worth for one host.
const MaxNackTallyBytes = 32 * 1024

// NackResult is what Nack reports back about the events it returned.
type NackResult struct {
	// SetAside counts the events Nack WITHDREW rather than returning to the queue, because they passed their retry bounds. It is
	// exact rather than merely non-zero: a caller decides whether a WHOLE batch was withdrawn by comparing it against the events
	// it handed over, so an under-count reads as a partial withdrawal.
	SetAside int64

	// Held reports whether this attempt still owned the claim. Without it, "withdrew nothing" is the same answer for a superseded
	// attempt and for a held batch that simply had no event reach its bounds.
	Held bool

	// CarriedTally is the tally an earlier attempt on these same events supplied, returned to whoever withdraws them and empty
	// otherwise. A batch that is coming back will be processed again and resolve its own, so handing this out before the batch's
	// last word would count it twice.
	CarriedTally []byte
}

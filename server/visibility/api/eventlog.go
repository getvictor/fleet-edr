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
	ClaimForHost(ctx context.Context, hostID string, limit int) ([]Event, error)

	// Ack marks the claimed events (identified by EventID) fully processed: they are excluded from future claims but stay in the queue
	// until PruneProcessed removes them, so Ack is a cheap index update off the delete path. Acknowledgment needs only identity, so it
	// takes IDs rather than whole events: the caller need not retain the (potentially large) payloads until ack.
	Ack(ctx context.Context, eventIDs []string) error

	// Nack returns the claimed events (identified by EventID) to the not-yet-processed state for a later ClaimForHost (retry after a
	// processing failure).
	Nack(ctx context.Context, eventIDs []string) error

	// CountPending counts events that have not been fully processed. Backs the processor-backlog gauge.
	CountPending(ctx context.Context) (int64, error)

	// PruneProcessed removes fully-processed (acked) events from the queue in batches of at most batchSize (a non-positive batchSize
	// uses the implementation's default), returning the total removed. The count is meaningful even when err != nil: a sweep that fails
	// mid-run still removed the returned rows. It is the sweep that keeps the queue to its in-flight working set (the archive holds the
	// durable history); a high-volume deployment runs it on a cadence off the hot path rather than deleting on each Ack. Removing only
	// acked events never affects a not-yet-processed or in-flight claim.
	PruneProcessed(ctx context.Context, batchSize int) (int64, error)
}

package api

import "context"

// EventLog is the durable work queue that decouples ingestion from detection processing. Ingestion appends every accepted event;
// the detection pipeline claims batches, processes them, and acknowledges them. It is the seam that lets ingestion and processing
// scale and fail independently (ADR-0015), while preserving the multi-replica claim semantics of ADR-0011.
//
// Invariants every implementation MUST uphold:
//   - At-least-once: an appended event is delivered to a claimer at least once; a crash between Claim and Ack re-delivers on a later
//     Claim. Consumers are therefore idempotent.
//   - Idempotent append: appending an event whose EventID was already appended is a no-op, so an agent retry never double-enqueues.
//   - Per-host causal order: a single Claim returns events ordered by (host, timestamp) so a host's events process in causal order.
//   - Lock-free fan-out: concurrent claimers on separate replicas receive disjoint batches without coordinating.
//
// The v0.4.0 implementation is an ephemeral MySQL queue; a later swap to a streaming log (Redpanda) changes no caller.
type EventLog interface {
	// Append enqueues events as not-yet-processed. Idempotent by EventID.
	Append(ctx context.Context, events []Event) error

	// Claim atomically claims up to limit not-yet-processed events for this worker, ordered per host by timestamp, without blocking
	// concurrent claimers. The claimed events are hidden from other claimers until Ack or Nack.
	Claim(ctx context.Context, limit int) ([]Event, error)

	// Ack marks the claimed events (identified by EventID) fully processed; they leave the queue. Acknowledgment needs only identity,
	// so it takes IDs rather than whole events: the caller need not retain the (potentially large) payloads until ack.
	Ack(ctx context.Context, eventIDs []string) error

	// Nack returns the claimed events (identified by EventID) to the not-yet-processed state for a later Claim (retry after a
	// processing failure).
	Nack(ctx context.Context, eventIDs []string) error

	// CountPending counts events that have not been fully processed. Backs the processor-backlog gauge.
	CountPending(ctx context.Context) (int64, error)
}

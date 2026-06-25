// Package api is the published surface of the visibility bounded context (ADR-0015, amending ADR-0004).
//
// Visibility owns endpoint event ingestion and the event store: the "what happened on the endpoint" data plane, distinct from
// detection (rules -> alerts) and from observability (the server's own OTel runtime-control surface). It is the seventh bounded
// context; the v0.5.0 hunting/investigation surface will read from it.
//
// The context is being extracted in stages. This package establishes its published language first: the canonical Event envelope and
// the two seams every other context consumes:
//
//   - EventLog: the durable, multi-replica work queue that decouples ingestion from detection processing. Detection's pipeline claims
//     from it; it preserves per-host causal ordering, at-least-once delivery, and idempotency by event_id (ADR-0011's claim).
//   - EventArchive: the durable, append-mostly event lake. Ingestion writes to it; correlation and (in v0.5.0) hunting read from it.
//
// The interfaces are store-neutral on purpose. The v0.4.0 implementation backs EventLog with an ephemeral MySQL queue and EventArchive
// with ClickHouse; a later swap to a streaming log (Redpanda) is additive and changes no caller.
//
// Event is defined here because the envelope is visibility's to own; detection/api keeps the name as a type alias so existing callers
// stay byte-identical while the dependency points the right way (detection -> visibility).
package api

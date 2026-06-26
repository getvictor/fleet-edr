// Package bootstrap wires the visibility bounded context (ADR-0015): endpoint event ingestion and the event store.
//
// It applies the context's schema and constructs its stores, handing cmd/main a handle with accessors for the published seams. Today
// it owns the EventLog (the MySQL `event_queue` work queue that decouples ingestion from detection processing); the EventArchive
// (the ClickHouse event lake) and the live ingest/processor wiring land in subsequent increments.
//
// Production wiring (cmd/main) calls New + ApplySchema; tests reach for visibility/testkit instead. arch-go pins that split.
package bootstrap

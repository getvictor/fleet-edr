// Package wire holds the Go-side decoder bindings for
// schema/events.json. The agent posts bytes that DecodeBatch
// unmarshals straight into []api.Event; the helper exists so a
// future protobuf cutover only swaps this package rather than
// churning every caller.
//
// Phase 5 ships JSON-only; protobuf is a future swap (out of scope
// per phase5.md).
package wire

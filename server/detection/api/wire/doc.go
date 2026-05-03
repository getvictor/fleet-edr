// Package wire holds the Go-side decoder bindings for
// schema/events.json. The agent posts bytes that DecodeBatch
// unmarshals straight into []api.Event; the helper exists so a
// future protobuf cutover only swaps this package rather than
// churning every caller.
//
// JSON-only today; protobuf would be a future swap.
package wire

package gateway

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc/stats"
)

// The control connection's span is coloured by what gRPC reports when the RPC ends, and for a long-lived stream that is usually not
// what the server concluded (issue #1124).
//
// A client that goes away takes the transport with it, and gRPC ends the RPC with the transport's own error, `transport is closing`.
// That happens whatever the handler returns, so the handler alone cannot make an ordinary disconnect a successful span: measured on
// edr-dev, and reproduced by the bufconn-free test in disconnect_test.go, which serves the gateway exactly as production does (over
// net/http's HTTP/2 server) and then kills the client's socket.
//
// So the gateway states its own verdict and the span reports that. Nothing here inspects the transport's error or its wording, which
// is grpc-go's to change; the one input is whether this server considers the connection to have failed.
//
// It fails safe. A verdict is only ever recorded as SUCCESS, and only by a handler that ran to completion, so an RPC that never
// reached the handler (rejected by the auth interceptor, for instance) keeps whatever gRPC reported for it.

// spanVerdict is one RPC's verdict, reachable from the stats handler because it rides the context gRPC threads from TagRPC through
// to the End event.
type spanVerdict struct{ succeeded atomic.Bool }

type spanVerdictKey struct{}

// recordSpanVerdict states how the handler finished, for the span. A nil error is the handler saying this connection did not fail,
// whatever the transport made of its ending.
func recordSpanVerdict(ctx context.Context, err error) {
	verdict, ok := ctx.Value(spanVerdictKey{}).(*spanVerdict)
	if !ok {
		return
	}
	verdict.succeeded.Store(err == nil)
}

// handlerVerdictStats wraps the OTel stats handler so a connection the gateway considers successful is recorded as successful.
type handlerVerdictStats struct{ stats.Handler }

// TagRPC attaches this RPC's verdict before the wrapped handler tags it, so the value is on the context the End event carries.
func (h handlerVerdictStats) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return h.Handler.TagRPC(context.WithValue(ctx, spanVerdictKey{}, &spanVerdict{}), info)
}

// HandleRPC passes every event through untouched, except the end of an RPC whose handler reported success: there the transport's
// error is dropped, so the span records the OK the handler concluded rather than the disconnect that ended the stream.
func (h handlerVerdictStats) HandleRPC(ctx context.Context, rpcStats stats.RPCStats) {
	end, isEnd := rpcStats.(*stats.End)
	if !isEnd || end.Error == nil {
		h.Handler.HandleRPC(ctx, rpcStats)
		return
	}
	verdict, ok := ctx.Value(spanVerdictKey{}).(*spanVerdict)
	if !ok || !verdict.succeeded.Load() {
		h.Handler.HandleRPC(ctx, rpcStats)
		return
	}
	// Copied rather than mutated: the event belongs to gRPC, and other handlers may still read it.
	cleared := *end
	cleared.Error = nil
	h.Handler.HandleRPC(ctx, &cleared)
}

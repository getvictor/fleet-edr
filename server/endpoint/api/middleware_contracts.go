package api

import "context"

// ctxKey is unexported so callers must go through the With* / *FromContext helpers below. The actual middleware in
// server/endpoint/internal/ middleware uses these helpers too -- production code path and test path both write through the same
// setter.
type ctxKey int

const ctxKeyHostID ctxKey = iota + 1

// HostIDFromContext returns the host_id pinned by the HostToken middleware. The second return is false when the context was not
// wrapped (caller bypassed middleware -- a programming error in production; tests should use WithHostIDForTest).
func HostIDFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(ctxKeyHostID)
	s, ok := v.(string)
	return s, ok && s != ""
}

// WithHostID returns a context with host_id pinned. Called by the
// HostToken middleware on every authed agent request.
func WithHostID(ctx context.Context, hostID string) context.Context {
	return context.WithValue(ctx, ctxKeyHostID, hostID)
}

// WithHostIDForTest is a backward-compat alias for WithHostID. Existing tests across the codebase use the ForTest naming; keep it
// working without forcing a rename in the same PR. New tests should prefer WithHostID.
func WithHostIDForTest(ctx context.Context, hostID string) context.Context {
	return WithHostID(ctx, hostID)
}

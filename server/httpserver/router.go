package httpserver

import (
	"net/http"
	"slices"
)

// Router is the subset of *http.ServeMux that route registration uses (Handle + HandleFunc). *http.ServeMux satisfies it, so a context's
// RegisterAuthedRoutes can accept a Router without any call site change. Accepting the interface lets the outer router record every
// pattern a context registers, so the session-protected allowlist is derived from what handlers actually register rather than
// hand-maintained in a parallel slice (issue #463: a route registered on the API mux but missing from the slice fell through to the SPA
// catch-all and 302'd, which the UI then parsed as JSON).
type Router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// RecordingRouter wraps a Router, forwarding every registration to the inner Router while recording the registered patterns in order.
// It is used at composition time: register every context's authed routes through one RecordingRouter, then mount exactly Patterns() on
// the session-protected boundary. A route can no longer be registered without being mounted, so the drift that caused #463 is
// structurally impossible rather than guarded after the fact.
type RecordingRouter struct {
	inner    Router
	patterns []string
}

// NewRecordingRouter returns a RecordingRouter forwarding to inner.
func NewRecordingRouter(inner Router) *RecordingRouter {
	return &RecordingRouter{inner: inner}
}

// Handle records the pattern and forwards to the inner Router.
func (r *RecordingRouter) Handle(pattern string, handler http.Handler) {
	r.patterns = append(r.patterns, pattern)
	r.inner.Handle(pattern, handler)
}

// HandleFunc records the pattern and forwards to the inner Router.
func (r *RecordingRouter) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	r.patterns = append(r.patterns, pattern)
	r.inner.HandleFunc(pattern, handler)
}

// Patterns returns a copy of every pattern registered through this RecordingRouter, in registration order. Patterns are unique by
// construction: the inner *http.ServeMux panics on a duplicate registration, so a duplicate would fail at composition time, not here.
func (r *RecordingRouter) Patterns() []string {
	return slices.Clone(r.patterns)
}

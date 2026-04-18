package api

import (
	"net/http"
)

// testAPIToken is the bearer token used by the auto-auth test wrapper below.
const testAPIToken = "test-api-token"

// autoAuth is a test-only middleware that stamps the standard test bearer on every request that
// does not already carry an Authorization header. It lets us reuse most existing tests unchanged
// now that the production API rejects unauthenticated requests outright.
//
// Tests that exercise the auth layer (missing header, wrong prefix) should bypass this wrapper
// by constructing a bare mux directly.
type autoAuth struct{ next http.Handler }

func (a *autoAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		r.Header.Set("Authorization", "Bearer "+testAPIToken)
	}
	a.next.ServeHTTP(w, r)
}

// testMux builds a mux with the provided handler's routes and wraps it with autoAuth.
func testMux(h *Handler) http.Handler {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return &autoAuth{next: mux}
}

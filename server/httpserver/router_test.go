package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordingRouter_recordsAndForwards(t *testing.T) {
	t.Parallel()
	inner := http.NewServeMux()
	rec := NewRecordingRouter(inner)

	rec.HandleFunc("GET /api/a", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	rec.Handle("POST /api/b", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))

	// Patterns are recorded in registration order.
	assert.Equal(t, []string{"GET /api/a", "POST /api/b"}, rec.Patterns())

	// Registrations were forwarded to the inner mux: it actually serves them.
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/a", http.StatusTeapot},
		{http.MethodPost, "/api/b", http.StatusAccepted},
	} {
		r := httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		inner.ServeHTTP(w, r)
		assert.Equal(t, tc.want, w.Code, "%s %s", tc.method, tc.path)
	}
}

func TestRecordingRouter_patternsIsACopy(t *testing.T) {
	t.Parallel()
	rec := NewRecordingRouter(http.NewServeMux())
	rec.HandleFunc("GET /api/x", func(http.ResponseWriter, *http.Request) {})
	got := rec.Patterns()
	got[0] = "mutated"
	// Mutating the returned slice must not affect the recorder's internal state.
	require.Equal(t, []string{"GET /api/x"}, rec.Patterns())
}

// *http.ServeMux must satisfy Router so call sites that pass a concrete mux keep compiling.
var _ Router = (*http.ServeMux)(nil)

package intake

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleReadyz_Draining pins that once the drain gate reports draining, /readyz returns 503 with status "draining" so a load
// balancer removes this replica from rotation. The store is nil here, which would otherwise make readyz report "degraded": the
// assertion on status="draining" proves the drain check takes precedence over the DB check (the contract the LB depends on).
func TestHandleReadyz_Draining(t *testing.T) {
	t.Run("spec:server-availability/sigterm-produces-a-load-balancer-drainable-graceful-shutdown/readiness-reports-not-ready-once-draining-begins", func(t *testing.T) {
		h := New(nil, nil, BuildInfo{})
		h.SetReadinessGate(func() bool { return true })

		mux := http.NewServeMux()
		h.RegisterHealthRoutes(mux)

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))

		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		var body struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "draining", body.Status, "drain must take precedence over the DB check")
	})
}

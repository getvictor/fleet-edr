package tracingpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/internal/observability/tracing"
)

func TestRegister_classifiesRoutesByTier(t *testing.T) {
	t.Parallel()
	reg := tracing.NewRegistry()
	Register(reg)

	cases := []struct {
		span string
		want tracing.Tier
	}{
		{"POST /api/events", tracing.TierHighVolume},
		{"GET /api/commands", tracing.TierHighVolume},
		{"POST /api/token/refresh", tracing.TierHighVolume},
		// Enrollment is rare + load-bearing, so it is intentionally NOT high-volume; it falls to Full (100%).
		{"POST /api/enroll", tracing.TierFull},
		{"GET /api/hosts", tracing.TierStandard},
		{"GET /api/alerts", tracing.TierStandard},
		{"GET /api/settings/tracing", tracing.TierStandard},
		{"GET /livez", tracing.TierDrop},
		{"GET /readyz", tracing.TierDrop},
		{"GET /health", tracing.TierDrop},
		// A parameter-bearing operator detail read is not classified (otelhttp emits the raw path), so it falls to full fidelity.
		{"GET /api/alerts/42", tracing.TierFull},
		{"GET /api/commands/abc-123", tracing.TierFull},
		// An unknown route falls to full fidelity.
		{"POST /api/brand-new", tracing.TierFull},
	}
	for _, tc := range cases {
		t.Run(tc.span, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, reg.Lookup(tc.span))
		})
	}
}

package tracing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistry_LookupHitsAndMissDefaultsToFull(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register("POST", "/api/events", TierHighVolume)
	reg.Register("GET", "/api/hosts", TierStandard)
	reg.Register("GET", "/livez", TierDrop)

	cases := []struct {
		name     string
		spanName string
		want     Tier
	}{
		{"high-volume hit", "POST /api/events", TierHighVolume},
		{"standard hit", "GET /api/hosts", TierStandard},
		{"drop hit", "GET /livez", TierDrop},
		{"unregistered path falls to full", "GET /api/hosts/abc-123/tree", TierFull},
		{"unregistered method falls to full", "DELETE /api/events", TierFull},
		{"non-http span name falls to full", "db.query", TierFull},
		{"empty span name falls to full", "", TierFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, reg.Lookup(tc.spanName))
		})
	}
}

func TestRegistry_ReRegisterOverwrites(t *testing.T) {
	t.Parallel()
	reg := NewRegistry()
	reg.Register("GET", "/api/commands", TierStandard)
	reg.Register("GET", "/api/commands", TierHighVolume)
	assert.Equal(t, TierHighVolume, reg.Lookup("GET /api/commands"))
}

func TestTierFullIsZeroValue(t *testing.T) {
	t.Parallel()
	// The Lookup-miss contract depends on TierFull being the zero value.
	var z Tier
	assert.Equal(t, TierFull, z)
}

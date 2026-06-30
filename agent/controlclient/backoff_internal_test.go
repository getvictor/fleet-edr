package controlclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/internal/control"
)

// stubChannelClient is the minimal control.ControlChannelClient needed to construct a Client without a real connection. New only
// records it; these tests never call Connect.
type stubChannelClient struct{ control.ControlChannelClient }

// TestNewBackoffBounds pins how New resolves the InitialBackoff / MaxBackoff config into the effective bounds, including the
// misordered-config clamp that previously fell back to the 30s default instead of clamping up to InitialBackoff.
func TestNewBackoffBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		initial     time.Duration
		maxBackoff  time.Duration
		wantInitial time.Duration
		wantMax     time.Duration
	}{
		{"both unset take defaults", 0, 0, defaultInitialBackoff, defaultMaxBackoff},
		{"max unset takes default cap", 2 * time.Second, 0, 2 * time.Second, defaultMaxBackoff},
		{"misordered max clamps up to initial", 10 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second},
		{"normal bounds preserved", 1 * time.Second, 20 * time.Second, 1 * time.Second, 20 * time.Second},
		{"negative initial takes default", -1, 20 * time.Second, defaultInitialBackoff, 20 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := New(Config{Client: stubChannelClient{}, InitialBackoff: tc.initial, MaxBackoff: tc.maxBackoff})
			assert.Equal(t, tc.wantInitial, c.initialBackoff)
			assert.Equal(t, tc.wantMax, c.maxBackoff)
		})
	}
}

func TestNewPanicsWithoutClient(t *testing.T) {
	t.Parallel()
	require.PanicsWithValue(t, "controlclient.New: Client must not be nil", func() { New(Config{}) })
}

// TestJitter guards the reconnect jitter against rand.Int64N(0), which panics: any duration whose half rounds to zero must yield no
// jitter rather than crashing the control-client goroutine.
func TestJitter(t *testing.T) {
	t.Parallel()
	assert.Zero(t, jitter(0))
	assert.Zero(t, jitter(1), "1ns/2 rounds to 0; must not call rand.Int64N(0)")
	assert.Zero(t, jitter(-5), "negative duration yields no jitter")
	for range 50 {
		j := jitter(10 * time.Second)
		assert.GreaterOrEqual(t, j, time.Duration(0))
		assert.Less(t, j, 5*time.Second, "jitter is bounded by half the duration")
	}
}

func TestMinDuration(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 1*time.Second, minDuration(1*time.Second, 2*time.Second))
	assert.Equal(t, 1*time.Second, minDuration(2*time.Second, 1*time.Second))
}

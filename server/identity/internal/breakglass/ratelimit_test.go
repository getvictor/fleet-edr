package breakglass_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/identity/internal/breakglass"
)

// AllowIP refuses to bucket an empty IP — a regression that bucketed "" would let an attacker who somehow got past the upstream IP
// resolver consume the same single bucket as everyone else.
func TestRateLimits_EmptyIPRejected(t *testing.T) {
	t.Parallel()
	r := breakglass.NewRateLimits(0, 0, 0)
	assert.False(t, r.AllowIP(""))
}

// Each bucket exhausts independently. Within the configured budget each is allowed; one over and it rejects. Pinned because the spec
// calls for independently-exhaustable buckets.
func TestRateLimits_IndependentlyExhausted(t *testing.T) {
	t.Parallel()
	r := breakglass.NewRateLimits(2, 2, 2) // 2/min each; burst=2

	// Per-IP: 2 then reject.
	assert.True(t, r.AllowIP("203.0.113.5"))
	assert.True(t, r.AllowIP("203.0.113.5"))
	assert.False(t, r.AllowIP("203.0.113.5"), "third call exceeds 2/min budget")

	// A different IP has its own bucket.
	assert.True(t, r.AllowIP("203.0.113.6"))

	// Per-email failed budget is independent of per-IP.
	assert.True(t, r.AllowEmailFail("admin@example.com"))
	assert.True(t, r.AllowEmailFail("admin@example.com"))
	assert.False(t, r.AllowEmailFail("admin@example.com"))

	// Setup bucket: shared global budget.
	assert.True(t, r.AllowSetup())
	assert.True(t, r.AllowSetup())
	assert.False(t, r.AllowSetup())
}

// Email is normalised lowercase + trimmed. Pinned because a regression that bucketed "Admin@x" and "admin@x" separately would double
// the brute-force budget by case-folding.
func TestRateLimits_EmailNormalised(t *testing.T) {
	t.Parallel()
	r := breakglass.NewRateLimits(99, 1, 99) // burst=1 forces same bucket
	assert.True(t, r.AllowEmailFail(" admin@example.com "))
	assert.False(t, r.AllowEmailFail("ADMIN@EXAMPLE.COM"),
		"case + whitespace must collide on the same bucket")
}

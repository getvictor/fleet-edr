package audit_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/identity/api"
	"github.com/fleetdm/edr/server/identity/internal/audit"
)

// rate=0.0 drops every non-carve-out read; carve-outs (break-glass +
// audit.read) still emit. This is the wave-1 default's behavior.
func TestShouldSampleRead_RateZero(t *testing.T) {
	for range 100 {
		assert.False(t, audit.ShouldSampleRead(api.ActionHostRead, false, 0.0))
		assert.False(t, audit.ShouldSampleRead(api.ActionAlertRead, false, 0.0))
	}
	// Break-glass overrides rate=0.0.
	assert.True(t, audit.ShouldSampleRead(api.ActionHostRead, true, 0.0))
	// audit.read overrides rate=0.0 — auditors must see who read audit.
	assert.True(t, audit.ShouldSampleRead(api.ActionAuditRead, false, 0.0))
}

// rate=1.0 includes every read action. This matches the wave-1
// historical behavior (audit-everything) for operators who set the
// env var explicitly.
func TestShouldSampleRead_RateOne(t *testing.T) {
	for _, a := range []api.Action{
		api.ActionHostRead,
		api.ActionProcessRead,
		api.ActionAlertRead,
		api.ActionPolicyRead,
		api.ActionEnrollmentRead,
		api.ActionUserRead,
	} {
		assert.True(t, audit.ShouldSampleRead(a, false, 1.0), "action %s at rate=1.0", a)
	}
}

// rate=0.5 over a large sample lands within ±5% of the expected
// inclusion fraction. The exact test bound is generous (rand.Float64
// is not a security RNG and we don't seed it deterministically) but
// tight enough to catch a regression that flipped the comparison
// direction.
func TestShouldSampleRead_RateHalf_Distribution(t *testing.T) {
	const iters = 10_000
	included := 0
	for range iters {
		if audit.ShouldSampleRead(api.ActionHostRead, false, 0.5) {
			included++
		}
	}
	// Wide bounds: ±5% of expected 5000.
	assert.InDelta(t, 5000, included, 500, "rate=0.5 inclusion fraction outside expected band")
}

// Out-of-range rates clamp rather than panic or misbehave. Negative
// rates round to "audit nothing" (other than carve-outs); rates above
// 1.0 round to "audit everything." Defensive: a misconfigured
// EDR_AUDIT_READ_SAMPLING shouldn't tip the chokepoint into UB.
func TestShouldSampleRead_RateOutOfRange(t *testing.T) {
	for range 100 {
		assert.False(t, audit.ShouldSampleRead(api.ActionHostRead, false, -0.5))
		assert.True(t, audit.ShouldSampleRead(api.ActionHostRead, false, 1.5))
	}
	// Carve-outs still apply for negative rates.
	assert.True(t, audit.ShouldSampleRead(api.ActionHostRead, true, -0.5))
	assert.True(t, audit.ShouldSampleRead(api.ActionAuditRead, false, -0.5))
}

// Non-read actions are not in the sample-and-async path; the
// chokepoint never asks ShouldSampleRead about them. But if it ever
// did, the function returns false at any rate < 1.0 because the
// action isn't a read action — we don't want a write action to slip
// through "this is a read" because of a future enum addition mistake.
//
// Today the function doesn't gate on IsReadAction explicitly (the
// chokepoint does that before calling), so this test pins the
// implementation contract: ShouldSampleRead is an inclusion gate, not
// a read-action classifier. Callers must combine it with
// api.IsReadAction. The chokepoint test in
// engine_test.go's TestAllow_*_AsyncSampling locks the combined
// behavior end-to-end.
func TestShouldSampleRead_NonReadActionPassthrough(t *testing.T) {
	// rate=0.0 drops everything but the carve-outs, regardless of
	// whether the action is a "read" or not.
	assert.False(t, audit.ShouldSampleRead(api.ActionHostIsolate, false, 0.0))
	assert.True(t, audit.ShouldSampleRead(api.ActionHostIsolate, true, 0.0))
	// rate=1.0 audits everything regardless of action — chokepoint
	// is responsible for not asking about writes.
	assert.True(t, audit.ShouldSampleRead(api.ActionHostIsolate, false, 1.0))
}

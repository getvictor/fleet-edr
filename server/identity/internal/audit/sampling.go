// Read-action audit sampling. The chokepoint emits one audit row per
// privileged decision; for high-volume read endpoints (host.read,
// alert.read, …) that volume can swamp the audit table without
// adding security signal. ShouldSampleRead is the gate the chokepoint
// consults before submitting a read-allow event to the async writer.
//
// Default rate is 0.0 (audit zero non-breakglass read-allow events);
// operators set EDR_AUDIT_READ_SAMPLING=1.0 to keep the wave-1
// audit-everything behavior.
//
// Carve-outs preserved regardless of rate:
//   - Break-glass actor: every action is audited at the chokepoint
//     because the break-glass surface is a high-stakes reviewer
//     concern; missing one action there would defeat the surface's
//     audit purpose.
//   - api.ActionAuditRead: every list of audit history is itself
//     audited (the audit-of-audit row) so reviewers can see who
//     accessed the audit log even when read_sampling=0.0.

package audit

import (
	"math/rand/v2"

	"github.com/fleetdm/edr/server/identity/api"
)

// ShouldSampleRead reports whether a read-action chokepoint emission
// should be recorded under the configured inclusion rate.
//
// The rate is interpreted as an inclusion probability: rate=0.0 → 0%
// of non-carve-out events are audited; rate=1.0 → 100%. Out-of-range
// rates are clamped (negative → 0.0, > 1.0 → 1.0) so a misconfigured
// env var still produces defined behavior.
//
// Caller is the chokepoint; this function is package-level (not a
// method on AsyncWriter) because the gate runs BEFORE Submit, on the
// hot path, and the writer doesn't need to exist for the gate's
// answer to be correct.
func ShouldSampleRead(action api.Action, breakGlass bool, rate float64) bool {
	if breakGlass {
		return true
	}
	if action == api.ActionAuditRead {
		return true
	}
	if rate <= 0.0 {
		return false
	}
	if rate >= 1.0 {
		return true
	}
	// math/rand/v2 is fine here - sampling decisions are not security-sensitive (an attacker who can predict the gate's outcome learns
	// whether the chokepoint logged a row, which is public information once the audit table is read by an authed user). crypto/rand would
	// be ~100x slower for no security gain.
	return rand.Float64() < rate //nolint:gosec
}

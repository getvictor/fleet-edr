package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsReadAction_AdminSurfaceReadsAreDeliberatelyExcluded pins a decision that was previously only an absence.
//
// Membership in the read set makes an event eligible for SAMPLING, and sampling means dropped. The set is therefore the
// high-volume operator reads, where a complete trail is not worth an insert per request. The admin-surface reads are excluded on
// purpose: they are page loads on a governed settings screen, a handful per session rather than per host or per alert, so the
// record of who looked at what the deployment detects is worth more than sampling saves.
//
// Without this test the exclusions read as an oversight, which is exactly how review read them, and "add it to the switch" is the
// plausible-looking change that would quietly make governance reads droppable.
func TestIsReadAction_AdminSurfaceReadsAreDeliberatelyExcluded(t *testing.T) {
	t.Parallel()

	for _, a := range []Action{ActionRuleContentRead, ActionDetectionConfigRead, ActionAppControlRead} {
		assert.False(t, IsReadAction(a),
			"%s is an admin-surface read: it must audit synchronously and always, not be eligible for sampling", a)
	}

	for _, a := range []Action{ActionHostRead, ActionProcessRead, ActionAlertRead, ActionEnrollmentRead, ActionUserRead} {
		assert.True(t, IsReadAction(a), "%s is a high-volume operator read and belongs in the sampled set", a)
	}

	// A write is never a read, whatever surface it belongs to.
	for _, a := range []Action{ActionRuleContentWrite, ActionDetectionConfigWrite} {
		assert.False(t, IsReadAction(a), "%s is a write", a)
	}
}

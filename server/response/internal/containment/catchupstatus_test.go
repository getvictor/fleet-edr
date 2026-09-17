//go:build integration

package containment

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/catchup"
	"github.com/fleetdm/edr/server/response/api"
)

// Every status a command can hold has to map onto one the shared decision knows, because the decision leaves a status it does not
// recognize alone. A status that fell through would therefore stop the catch-up resending to that host, silently and for as long as
// the command stayed in it. This is the test that turns a rename on either side into a failure.
func TestCatchupStatus_MapsEveryStatusACommandCanHold(t *testing.T) {
	t.Parallel()
	known := map[catchup.Status]bool{
		catchup.StatusPending: true, catchup.StatusAcked: true, catchup.StatusCompleted: true,
		catchup.StatusFailed: true, catchup.StatusExpired: true, catchup.StatusCancelled: true,
	}
	// Every value api.Status takes. A new one added without a case here fails this test rather than the fleet's catch-up.
	all := []api.Status{
		api.StatusPending, api.StatusAcked, api.StatusCompleted, api.StatusFailed, api.StatusExpired, api.StatusCancelled,
	}
	for _, s := range all {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			assert.True(t, known[catchupStatus(s)], "api.Status %q maps to %q, which the shared decision does not know", s,
				catchupStatus(s))
		})
	}
	assert.Empty(t, catchupStatus("quarantined"), "a status this version does not know maps to nothing, and is left alone")
}

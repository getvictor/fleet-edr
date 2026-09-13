package bootstrap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/coordination/leader"
)

// nopCoordinator is a non-nil coordinator whose methods are never called: reservedLeaderConns only asks whether one is wired.
type nopCoordinator struct{ leader.Coordinator }

// TestReservedLeaderConns_CountsRetentionWhenEitherWindowIsOn pins the reservation to what the retention runner actually does. Its Loop
// keeps running, and so keeps its leader lock and a pooled connection, while EITHER window is nonzero (issue #995). Keying the count on the
// process window alone under-reserved that connection for an operator who holds process records for a forensic hold while alerts keep
// expiring, and the processor then sized its workers against a connection that never came back (issue #722).
func TestReservedLeaderConns_CountsRetentionWhenEitherWindowIsOn(t *testing.T) {
	t.Parallel()
	// Process TTL is on in every case, so each count is queue-prune + process TTL (2) plus one if retention holds its lock.
	cases := []struct {
		name               string
		retentionDays      int
		alertRetentionDays int
		want               int
	}{
		{name: "both windows on", retentionDays: 30, alertRetentionDays: 180, want: 3},
		{name: "only the process window on", retentionDays: 30, want: 3},
		{name: "only the alert window on", alertRetentionDays: 180, want: 3},
		{name: "both windows off", want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := Deps{
				Coordinator:        nopCoordinator{},
				StaleProcessTTL:    time.Hour,
				RetentionDays:      tc.retentionDays,
				AlertRetentionDays: tc.alertRetentionDays,
			}
			assert.Equal(t, tc.want, reservedLeaderConns(deps))
		})
	}
}

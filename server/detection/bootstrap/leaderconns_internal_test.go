package bootstrap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/fleetdm/edr/server/coordination/leader"
)

// nopCoordinator is a non-nil coordinator whose methods are never called: reservedLeaderConns only asks whether one is wired.
type nopCoordinator struct{ leader.Coordinator }

// TestReservedLeaderConns_CountsRetentionWhenAnyWindowIsOn pins the reservation to what the retention runner actually does. Its Loop keeps
// running, and so keeps its leader lock and a pooled connection, while ANY of its windows is nonzero (issues #995 and #994). Keying the
// count on the process window alone under-reserved that connection for an operator who holds process records for a forensic hold while
// alerts or monitor records keep expiring, and the processor then sized its workers against a connection that never came back (#722).
func TestReservedLeaderConns_CountsRetentionWhenAnyWindowIsOn(t *testing.T) {
	t.Parallel()
	// Process TTL is on in every case, so each count is queue-prune + process TTL (2) plus one if retention holds its lock.
	cases := []struct {
		name        string
		processDays int
		alertDays   int
		monitorDays int
		want        int
	}{
		{name: "every window on", processDays: 30, alertDays: 180, monitorDays: 7, want: 3},
		{name: "only the process window on", processDays: 30, want: 3},
		{name: "only the alert window on", alertDays: 180, want: 3},
		{name: "only the monitor-record window on", monitorDays: 7, want: 3},
		{name: "every window off", want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := Deps{
				Coordinator:                nopCoordinator{},
				StaleProcessTTL:            time.Hour,
				RetentionDays:              tc.processDays,
				AlertRetentionDays:         tc.alertDays,
				MonitorRecordRetentionDays: tc.monitorDays,
			}
			assert.Equal(t, tc.want, reservedLeaderConns(deps))
		})
	}
}

package telemetryhealth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fleetdm/edr/server/detection/api"
	"github.com/fleetdm/edr/server/detection/internal/telemetryhealth"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// wedged is the activity shape of the incident this package exists for: process telemetry flowing, both flow streams silent in the
// recent window, and both known to have produced inside the reference window.
func wedged() visibilityapi.TelemetryActivity {
	return visibilityapi.TelemetryActivity{
		ProcessInWindow:    1204,
		ConnectInWindow:    0,
		DNSInWindow:        0,
		ConnectInReference: 91_037,
		DNSInReference:     82_382,
	}
}

// The non-accusation cases are the ones that decide whether this signal is usable at all: a check that cries wolf on idle laptops
// gets muted, and a muted check detects nothing.
//
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/an-idle-host-is-not-accused
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/a-provider-that-never-produced-is-not-accused
// spec:server-host-status/the-server-derives-health-conditions-its-endpoints-cannot-report/a-host-already-reporting-a-fault-gains-no-second-condition
func TestDerive(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		status   string
		activity visibilityapi.TelemetryActivity
		want     []string // derived component types, in order
	}{
		{
			name:     "both providers silent while processes run",
			status:   string(endpointapi.HealthHealthy),
			activity: wedged(),
			want:     []string{"content_filter_delivery", "dns_proxy_delivery"},
		},
		{
			name:   "only DNS silent, connections still flowing",
			status: string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{
				ProcessInWindow: 500, ConnectInWindow: 771, DNSInWindow: 0,
				ConnectInReference: 5000, DNSInReference: 900,
			},
			want: []string{"dns_proxy_delivery"},
		},
		{
			name:   "only connections silent, DNS still flowing",
			status: string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{
				ProcessInWindow: 500, ConnectInWindow: 0, DNSInWindow: 123,
				ConnectInReference: 5000, DNSInReference: 900,
			},
			want: []string{"content_filter_delivery"},
		},
		{
			name:   "everything flowing",
			status: string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{
				ProcessInWindow: 500, ConnectInWindow: 771, DNSInWindow: 123,
				ConnectInReference: 5000, DNSInReference: 900,
			},
			want: nil,
		},
		{
			// The false-positive case that matters most (issue #677 QA step 1): a host doing nothing produces no flows, and that
			// is not a fault. Reference counts are deliberately non-zero here, so ONLY the process gate can be rejecting it.
			name:   "idle host with no process activity is not accused",
			status: string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{
				ProcessInWindow: 0, ConnectInWindow: 0, DNSInWindow: 0,
				ConnectInReference: 5000, DNSInReference: 900,
			},
			want: nil,
		},
		{
			// An offline host sends nothing at all, so it reaches here as pure zeroes. Issue #677 QA step 4: it must not be
			// reported under this condition, since host-offline reporting already covers it.
			name:     "offline host with no activity at all is not accused",
			status:   string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{},
			want:     nil,
		},
		{
			// The DNS proxy is opt-in and a deliberately disabled provider is reported by ABSENCE, so nothing in the health
			// snapshot distinguishes it from a wedge. The reference window is what does.
			name:   "provider that never produced is not accused",
			status: string(endpointapi.HealthHealthy),
			activity: visibilityapi.TelemetryActivity{
				ProcessInWindow: 500, ConnectInWindow: 771, DNSInWindow: 0,
				ConnectInReference: 5000, DNSInReference: 0,
			},
			want: nil,
		},
		{
			name:     "unhealthy host is left alone, the endpoint already reported a fault",
			status:   string(endpointapi.HealthUnhealthy),
			activity: wedged(),
			want:     nil,
		},
		{
			name:     "degraded host is left alone",
			status:   string(endpointapi.HealthDegraded),
			activity: wedged(),
			want:     nil,
		},
		{
			name:     "host that never checked in has made no claim to contradict",
			status:   string(endpointapi.HealthUnknown),
			activity: wedged(),
			want:     nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := telemetryhealth.Derive(tc.status, tc.activity)
			var types []string
			for _, c := range got {
				types = append(types, c.Type)
			}
			assert.Equal(t, tc.want, types)
		})
	}
}

// TestDerive_ConditionShape pins what an operator actually reads, since a finding nobody can act on is not worth raising.
func TestDerive_ConditionShape(t *testing.T) {
	t.Parallel()
	got := telemetryhealth.Derive(string(endpointapi.HealthHealthy), wedged())
	require.Len(t, got, 2)

	dns := got[1]
	assert.Equal(t, "dns_proxy_delivery", dns.Type)
	assert.Equal(t, string(endpointapi.HealthDegraded), dns.Status,
		"degraded, not unhealthy: this is inferred from absence, not observed by the endpoint")
	assert.Equal(t, telemetryhealth.ReasonNoFlowTelemetry, dns.Reason)
	assert.Contains(t, dns.Message, "dns_query", "the message must name the stream that went silent")
	assert.Contains(t, dns.Message, "dns_proxy", "the message must name the provider to remediate")
	assert.Contains(t, dns.Message, "1204", "the message must carry the evidence the host was not merely idle")
	assert.Contains(t, dns.Message, "2h", "the window is stated in the message so an operator knows what 'no events' covers")
	assert.NotContains(t, dns.Message, "2h0m0s", "Go's duration spelling reads as machine output mid-sentence")
	assert.Zero(t, dns.LastTransitionNs,
		"a window count cannot recover the instant the stream fell silent, and a stamped 'now' would date a days-old fault to page load")
}

func TestRollup(t *testing.T) {
	t.Parallel()
	degraded := []api.DerivedComponent{{Type: "dns_proxy_delivery", Status: string(endpointapi.HealthDegraded)}}
	cases := []struct {
		name     string
		reported string
		derived  []api.DerivedComponent
		want     string
	}{
		{
			name:     "nothing derived leaves the reported rollup exactly as it was",
			reported: string(endpointapi.HealthHealthy),
			derived:  nil,
			want:     string(endpointapi.HealthHealthy),
		},
		{
			name:     "a derived condition degrades a healthy host",
			reported: string(endpointapi.HealthHealthy),
			derived:  degraded,
			want:     string(endpointapi.HealthDegraded),
		},
		{
			// Unreachable through Derive (it gates on healthy) but pinned anyway: the fold must never DOWNGRADE a worse reported
			// state, or a derived condition would mask a fault the endpoint observed directly.
			name:     "a derived condition never downgrades a worse reported state",
			reported: string(endpointapi.HealthUnhealthy),
			derived:  degraded,
			want:     string(endpointapi.HealthUnhealthy),
		},
		{
			name:     "a derived condition beats an unknown rollup",
			reported: string(endpointapi.HealthUnknown),
			derived:  degraded,
			want:     string(endpointapi.HealthDegraded),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, telemetryhealth.Rollup(tc.reported, tc.derived))
		})
	}
}

// TestWindows pins the nesting the archive read depends on. A SilentFromNs outside the reference range would make the inner counts
// meaningless (they are computed from rows the outer range already excluded), and the bug would show up as a signal that never fires
// rather than as an error.
func TestWindows(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 19, 11, 20, 0, 0, time.UTC)
	w := telemetryhealth.Windows(now)

	assert.Equal(t, now.UnixNano(), w.Reference.ToNs, "the read must not look past now, or a future-stamped event masks a real fault")
	assert.Equal(t, now.Add(-telemetryhealth.ReferenceWindow).UnixNano(), w.Reference.FromNs)
	assert.Equal(t, now.Add(-telemetryhealth.SilenceWindow).UnixNano(), w.SilentFromNs)

	assert.Greater(t, w.SilentFromNs, w.Reference.FromNs, "the silence window must sit strictly inside the reference window")
	assert.Less(t, w.SilentFromNs, w.Reference.ToNs)
}

// TestWindowsAreMeasured guards the two constants against a well-meaning edit.
//
// They are not preferences. Over 30 days of the dogfood host's archive, benign flow silence never exceeded 30 minutes while the real
// wedge ran for days, and the reference window has to comfortably exceed the longest wedge on record (44 hours) or the signal
// switches itself off partway through the fault it is reporting. An edit that violates either bound is a behaviour change that needs
// its own measurement, not a constant tweak.
func TestWindowsAreMeasured(t *testing.T) {
	t.Parallel()
	assert.Greater(t, telemetryhealth.SilenceWindow, 30*time.Minute,
		"the silence window must exceed the longest benign silence observed (30 minutes) or healthy hosts will be accused")
	assert.Greater(t, telemetryhealth.ReferenceWindow, 48*time.Hour,
		"the reference window must outlast the longest wedge on record (44 hours) or the signal clears itself mid-fault")
	assert.Less(t, telemetryhealth.SilenceWindow, telemetryhealth.ReferenceWindow)
}

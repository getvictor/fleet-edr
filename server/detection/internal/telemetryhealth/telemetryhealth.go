// Package telemetryhealth derives per-host health that the endpoint cannot report about itself.
//
// # The failure it exists for
//
// A macOS network-extension provider can start, report itself running, and then stop delivering events, with nothing inside the
// endpoint able to tell that state from an idle machine (issue #677). Three separate causes present with this identical signature: a
// System Settings disable/re-enable that relaunches the extension process with no provider sessions, a wedged DNS proxy session that
// keeps claiming state Running while the extension logs nothing at all, and a bare binary swap during a redeploy. In every one the
// agent's own health is the signal that lies, so a check that consults it alone cannot see any of them.
//
// What the server has, and the endpoint does not, is the other side of the contradiction: whether the events actually arrived. So the
// claim made here needs two independent sources to disagree. The agent asserts its components are healthy; the archive says a stream
// that this host does use produced nothing recently while process telemetry kept flowing. Neither half is evidence alone.
//
// # Why the thresholds are what they are
//
// Measured, not chosen. Over 30 days of one dogfood host's archive (~15M events, the host from #677), bucketed at 10 minutes:
//
//   - The wedge is one continuous run from 2026-07-17 15:00 to 07-19 11:20. 227 of those buckets carried process activity with zero
//     flow events, 37.8 hours' worth, spread across 44.3 hours of wall clock (the gaps are the machine asleep, producing nothing at
//     all). On 07-18 alone: 134,132 process events, 0 network_connect, 0 dns_query.
//   - Every other silence run in the month is 30 minutes or shorter. DNS silence with connections still flowing: 21 runs, longest
//     30 minutes. Connection silence: 6 runs, all 10 minutes.
//
// So benign silence tops out at 30 minutes and the real fault ran for days: a 75x separation with nothing in between. SilenceWindow
// sits at 2 hours, 4x above the worst benign run observed and still catching a wedge inside the first 5% of its life.
//
// Two candidate designs died on that data and are worth not re-deriving. A per-host flow-to-exec ratio baseline (the issue's own
// suggestion) buys nothing a plain "any process activity" gate does not already give, and costs stored history. And widening the
// window does NOT trade false positives for detection latency here the way it usually would: the benign and faulty populations are
// disjoint, so 2 hours and 12 hours have the same false-positive count, which is zero.
package telemetryhealth

import (
	"fmt"
	"strings"
	"time"

	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// SilenceWindow is how long a stream must produce nothing before that silence is called a fault. See the package comment for the
// measurement behind the value.
const SilenceWindow = 2 * time.Hour

// ReferenceWindow is how far back the check looks to establish that a host uses a stream at all.
//
// It is the guard against accusing a host whose provider is legitimately off, which is not a hypothetical: the DNS proxy is opt-in,
// and the extension reports a deliberately disabled provider by OMITTING it rather than marking it stopped, so nothing in the health
// snapshot distinguishes "the operator turned this off" from "this wedged". A host configured with no network extension at all has
// the same shape. Requiring the stream to have produced something recently answers both without needing the endpoint's cooperation.
//
// Its cost is a ceiling on how long a wedge stays reported: a fault lasting longer than this empties the reference window too, and
// the host stops being flagged. 7 days against the 44-hour incident on record is a 4x margin. Removing the ceiling entirely needs the
// agent to publish its per-provider liveness map to the server, which is tracked separately.
const ReferenceWindow = 7 * 24 * time.Hour

// Windows builds the archive read's bounds from the current time, so the two windows are derived in exactly one place and a caller
// cannot pair a silence window with a reference window that does not contain it.
//
// The upper bound is now rather than open-ended: an event stamped in the future (a host with a skewed clock) would otherwise land
// inside the silence window and mask a real fault by making a silent stream look active.
func Windows(now time.Time) visibilityapi.TelemetryActivityWindows {
	return visibilityapi.TelemetryActivityWindows{
		Reference: httpserver.TimeRange{
			FromNs: now.Add(-ReferenceWindow).UnixNano(),
			ToNs:   now.UnixNano(),
		},
		SilentFromNs: now.Add(-SilenceWindow).UnixNano(),
	}
}

// derivedComponent describes one stream whose silence is worth reporting, and how to name it to an operator.
type derivedComponent struct {
	// componentType is the wire `type` of the derived condition. The "_delivery" suffix is deliberate: it keeps these distinct from
	// the provider-named components the agent may itself report later, so the two can coexist without one silently shadowing the
	// other, and it says what is actually being asserted (events are not being delivered) rather than restating the provider name.
	componentType string
	// provider is the network-extension provider an operator has to act on, named because remediation is per provider.
	provider string
	// stream is the event type whose absence is the evidence.
	stream string
	// inWindow and inReference select this stream's counts out of an activity record.
	inWindow    func(visibilityapi.TelemetryActivity) int64
	inReference func(visibilityapi.TelemetryActivity) int64
}

// derivedComponents is the fixed set of stream contradictions checked, one per network-extension provider.
//
// Both are checked independently even though the incident on record took both down at once (they are two sessions of a single
// extension process, so that cause cannot hit one alone). Independence costs nothing and covers the causes that can: a DNS proxy
// session wedging while the content filter keeps delivering is exactly the shape #677 was first reported as.
var derivedComponents = []derivedComponent{
	{
		componentType: "content_filter_delivery",
		provider:      "content_filter",
		stream:        "network_connect",
		inWindow:      func(a visibilityapi.TelemetryActivity) int64 { return a.ConnectInWindow },
		inReference:   func(a visibilityapi.TelemetryActivity) int64 { return a.ConnectInReference },
	},
	{
		componentType: "dns_proxy_delivery",
		provider:      "dns_proxy",
		stream:        "dns_query",
		inWindow:      func(a visibilityapi.TelemetryActivity) int64 { return a.DNSInWindow },
		inReference:   func(a visibilityapi.TelemetryActivity) int64 { return a.DNSInReference },
	},
}

// ReasonNoFlowTelemetry is the machine reason on every derived condition: the host's reported health claims its components are fine,
// but a flow stream it does use has delivered nothing while process telemetry continued.
const ReasonNoFlowTelemetry = "no_flow_telemetry"

// Derive returns the server-derived health conditions for one host, given the health rollup the agent reported and the host's
// telemetry activity. It returns nil when there is nothing to say, which is the overwhelmingly common case.
//
// reportedStatus gates the whole check, and gating on the ROLLUP rather than on the network-extension component specifically is not a
// shortcut. The rollup is a worst-of, so healthy means every reported component is healthy: it is exactly the positive claim being
// contradicted, and it needs no parsing of a components blob that the server otherwise passes through untouched. Any other value
// means the endpoint is already reporting a problem, and adding a second condition on top would be noise on a host whose operator can
// already see something is wrong.
//
// The activity argument is the host's own record from the archive. A host absent from the archive's result has no activity to reason
// about; callers pass the zero value, which fails the process-activity gate and yields nothing.
func Derive(reportedStatus string, activity visibilityapi.TelemetryActivity) []endpointapi.ComponentHealth {
	if endpointapi.HealthStatus(reportedStatus) != endpointapi.HealthHealthy {
		return nil
	}
	// No process activity means the host is idle, asleep, offline, or unknown. Silence proves nothing there, and this is the gate
	// that keeps the ordinary case (a laptop that is simply not being used) from ever producing a finding.
	if activity.ProcessInWindow == 0 {
		return nil
	}
	var out []endpointapi.ComponentHealth
	for _, dc := range derivedComponents {
		if dc.inWindow(activity) > 0 {
			continue // the stream is delivering
		}
		if dc.inReference(activity) == 0 {
			continue // this host does not use this stream; its silence is not evidence of anything
		}
		out = append(out, endpointapi.ComponentHealth{
			Type:    dc.componentType,
			Status:  endpointapi.HealthDegraded,
			Reason:  ReasonNoFlowTelemetry,
			Message: message(dc, activity.ProcessInWindow),
		})
	}
	return out
}

// message states the contradiction in the terms an operator has to act on: which provider, what stopped, and the evidence that the
// host was not merely idle.
//
// Degraded rather than unhealthy: the server is inferring from absence, and absence has one honest alternative reading (the host's
// clock, an ingest backlog). Unhealthy is reserved for the endpoint reporting a fault it observed directly.
//
// LastTransitionNs is deliberately left zero. Every other component carries an agent-observed instant at which it entered its current
// state, and this condition has no such instant to offer: the archive can say the stream is empty now, but the moment it fell silent
// is not something a count over a window recovers. Filling it with the query time would render "since 0m ago" on a fault that may be
// two days old, which is worse than rendering nothing.
func message(dc derivedComponent, processEvents int64) string {
	return fmt.Sprintf("reports healthy, but no %s events reached the server in the last %s while %d process events did; "+
		"%s may be running without capturing", dc.stream, humanDuration(SilenceWindow), processEvents, dc.provider)
}

// humanDuration renders a whole-unit duration the way an operator writes one. Go's own formatting spells two hours "2h0m0s", which
// reads as machine output in the middle of a sentence a human is meant to act on.
func humanDuration(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "0m")
}

// Rollup folds derived conditions into a host's reported rollup, returning the status an operator should actually see.
//
// Derived conditions only ever exist when the reported rollup was healthy (Derive gates on it), so this is in practice "healthy
// becomes degraded when something was derived". It is written as a general worst-of anyway, over the same precedence the endpoint
// context defines, so that adding a derived condition of another severity later cannot silently produce a rollup that disagrees with
// the conditions beneath it.
func Rollup(reportedStatus string, derived []endpointapi.ComponentHealth) string {
	if len(derived) == 0 {
		return reportedStatus
	}
	worst := endpointapi.HealthStatus(reportedStatus)
	for _, c := range derived {
		if severity(c.Status) > severity(worst) {
			worst = c.Status
		}
	}
	return string(worst)
}

// severity orders health states for the worst-of fold: unhealthy beats degraded beats healthy, and unknown sits at the bottom so a
// host with no snapshot is never promoted above a real reported state.
func severity(s endpointapi.HealthStatus) int {
	switch s {
	case endpointapi.HealthUnhealthy:
		return 3
	case endpointapi.HealthDegraded:
		return 2
	case endpointapi.HealthHealthy:
		return 1
	case endpointapi.HealthUnknown:
		return 0
	default:
		return 0
	}
}

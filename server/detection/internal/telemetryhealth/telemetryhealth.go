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
// claim made here needs two independent sources to disagree. The agent asserts that a specific provider is capturing; the archive says
// that provider's stream produced nothing recently while process telemetry kept flowing. Neither half is evidence alone.
//
// # The residual risk of trusting a claim
//
// Gating on the endpoint's own claim means a host that claims nothing cannot be accused, where inferring use from history
// would still have reported it. That is bounded by the reporting rules on the other side rather than by anything here: an
// agent observing no running provider reports the owning extension as UNHEALTHY (issue #649), so an honest agent cannot
// present a healthy extension with no provider claims, and that state is already visible as the extension's own condition.
// What remains is an agent too old to report per provider, which loses this detection until upgraded, and a falsified
// snapshot, which no gate chosen here would survive: an endpoint able to suppress its own claims can equally fabricate the
// telemetry this check reads against them.
//
// The agent's half is a per-provider claim (issue #702). An earlier version of this could not read one, because the agent collapsed its
// provider map into a single component before posting, and had to infer "this host uses this stream" from the stream's own history
// instead. That proxy was inaccurate in two ways that are now simply gone: a provider disabled inside the history window kept being
// reported until its events aged out, and a fault outlasting the window stopped being reported at all. Reading the claim removes the
// window, the history, and both errors.
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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fleetdm/edr/server/detection/api"
	endpointapi "github.com/fleetdm/edr/server/endpoint/api"
	"github.com/fleetdm/edr/server/httpserver"
	visibilityapi "github.com/fleetdm/edr/server/visibility/api"
)

// SilenceWindow is how long a stream must produce nothing before that silence is called a fault. See the package comment for the
// measurement behind the value.
const SilenceWindow = 2 * time.Hour

// Window builds the archive read's bounds from the current time.
//
// The upper bound is now rather than open-ended: an event stamped in the future (a host with a skewed clock) would otherwise land
// inside the window and mask a real fault by making a silent stream look active.
func Window(now time.Time) httpserver.TimeRange {
	return httpserver.TimeRange{FromNs: now.Add(-SilenceWindow).UnixNano(), ToNs: now.UnixNano()}
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
	// inWindow selects this stream's count out of an activity record.
	inWindow func(visibilityapi.TelemetryActivity) int64
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
	},
	{
		componentType: "dns_proxy_delivery",
		provider:      "dns_proxy",
		stream:        "dns_query",
		inWindow:      func(a visibilityapi.TelemetryActivity) int64 { return a.DNSInWindow },
	},
}

// ReasonNoFlowTelemetry is the machine reason on every derived condition: the host's reported health claims its components are fine,
// but a flow stream it does use has delivered nothing while process telemetry continued.
const ReasonNoFlowTelemetry = "no_flow_telemetry"

// Claims is what a host asserted about its own capture providers, read from the components it posted (issue #702).
//
// Only providers claiming to be CAPTURING are kept. Every other case is silence rather than a claim, and silence is not
// something this package can contradict:
//
//   - a provider the operator disabled is omitted by the agent entirely, which is exactly how a supported opt-out is meant to
//     read;
//   - a provider the endpoint already reports as stopped needs no second opinion, and adding one would be noise on a host whose
//     operator can already see the fault;
//   - a provider reporting a state the agent did not recognise has asserted nothing either way.
type Claims struct {
	capturing map[string]struct{}
}

// ParseClaims reads a host's posted components into the set of providers claiming to capture. A payload that does not decode
// yields no claims, so an unreadable snapshot produces no findings rather than a guess.
func ParseClaims(components []byte) Claims {
	c := Claims{capturing: map[string]struct{}{}}
	if len(components) == 0 {
		return c
	}
	var reported []endpointapi.ComponentHealth
	if err := json.Unmarshal(components, &reported); err != nil {
		return c
	}
	for _, comp := range reported {
		if comp.Status == endpointapi.HealthHealthy && isProvider(comp.Type) {
			c.capturing[comp.Type] = struct{}{}
		}
	}
	return c
}

// Any reports whether the host claims ANY provider is capturing, so a caller can skip the telemetry read entirely for a host
// that cannot produce a finding whatever the telemetry says. On the fleet-wide list that is most of the work for hosts that
// are offline, unenrolled, or already reporting a fault.
func (c Claims) Any() bool { return len(c.capturing) > 0 }

// claims reports whether one provider asserted it is capturing.
func (c Claims) claims(provider string) bool {
	_, ok := c.capturing[provider]
	return ok
}

// isProvider reports whether a component type names one of the capture providers this rule reasons about. It exists so an
// unrelated component that happens to be healthy (the extensions themselves, anything added later) cannot be mistaken for a
// provider claim.
func isProvider(componentType string) bool {
	for _, dc := range derivedComponents {
		if dc.provider == componentType {
			return true
		}
	}
	return false
}

// Derive returns the server-derived health conditions for one host, given what the host claimed about its providers and what its
// telemetry actually did. It returns nil when there is nothing to say, which is the overwhelmingly common case.
//
// The gate is now the provider's OWN claim rather than the host's overall rollup. That is what removes the history this check used
// to need: "does this host use this stream" is answered by the endpoint stating it, not inferred from whether the stream produced
// anything lately. It is also more precise in both directions. A host whose security extension is unhealthy for unrelated reasons no
// longer suppresses a genuine content-filter wedge, and a provider the endpoint already reports as stopped no longer collects a
// second, redundant condition.
//
// The activity argument is the host's own record from the archive. A host absent from the archive's result has no activity to reason
// about; callers pass the zero value, which fails the process-activity gate and yields nothing.
func Derive(claims Claims, activity visibilityapi.TelemetryActivity) []api.DerivedComponent {
	// No process activity means the host is idle, asleep, offline, or unknown. Silence proves nothing there, and this is the gate
	// that keeps the ordinary case (a laptop that is simply not being used) from ever producing a finding.
	if activity.ProcessInWindow == 0 {
		return nil
	}
	var out []api.DerivedComponent
	for _, dc := range derivedComponents {
		if !claims.claims(dc.provider) {
			continue // nothing was asserted about this provider, so there is nothing to contradict
		}
		if dc.inWindow(activity) > 0 {
			continue // the stream is delivering
		}
		out = append(out, api.DerivedComponent{
			Type: dc.componentType,
			// The endpoint context owns the health vocabulary, so the value is taken from its constant even though the field
			// is a plain string here: one spelling, defined once, however many contexts render it.
			Status:  string(endpointapi.HealthDegraded),
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
func Rollup(reportedStatus string, derived []api.DerivedComponent) string {
	if len(derived) == 0 {
		return reportedStatus
	}
	worst := endpointapi.HealthStatus(reportedStatus)
	for _, c := range derived {
		if status := endpointapi.HealthStatus(c.Status); severity(status) > severity(worst) {
			worst = status
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
